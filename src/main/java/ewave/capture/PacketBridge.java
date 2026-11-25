package ewave.capture;

import ewave.core.AdaptiveScanner;
import ewave.decoder.Dot11Frame;
import ewave.decoder.Dot11FrameDecoder;
import ewave.model.PacketEvent;
import ewave.model.EwaveEvent;
import ewave.passive.DeviceProfiler;
import ewave.passive.MyNetworkProfile;
import ewave.passive.MyNetworkStore;
import ewave.passive.PassiveWifiSession;
import ewave.passive.WifiInventory;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Binary 802.11 radiotap capture and PCAP replay coordinator with channel hopping,
 * Sniper tracking, passive analysis session state, and physical-radio Lab Ops coordination.
 */
public final class PacketBridge implements AutoCloseable {
    private static final System.Logger LOG = System.getLogger(PacketBridge.class.getName());
    public static final int DEFAULT_TICK_MS = 20;
    private final int tickMs;
    private final long tickNanos;
    private static final Pattern OUI = Pattern.compile(
            "^\\s*([0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}|[0-9a-f]{6})"
                    + "\\s+(?:\\((?:hex|base 16)\\)\\s+)?(.+?)\\s*$", Pattern.CASE_INSENSITIVE);

    /** Default cap for the WebSocket/UI event queue; oldest events are evicted if unconsumed. */
    public static final int EVENT_QUEUE_CAPACITY = 1024;
    private static final int MAX_CAPTURE_ERROR = 256;
    private final int eventCapacity;
    private final AtomicLong droppedEvents = new AtomicLong();
    private final BlockingQueue<EwaveEvent> eventQueue;
    private final Map<String, String> vendors;
    private final ProcessStarter processStarter;
    private final Function<String, RadioStatus.Settings> radioSettings;
    private final Function<String, String> wiphyResolver;
    private final Function<String, Optional<List<RadioStatus.Channel>>> radioChannels;
    private final DeviceProfiler profiler;
    private volatile int channel;
    // Guarded by this, including every session's counters and pending packets.
    private volatile Session session;
    private long tick;
    private long probeCount;
    private long reportFrames;
    private long reportInventory;
    private long reportTopology;
    private long reportProbes;
    private long reportSettings;
    private String captureMode = "idle";
    private long captureStartedAt;
    private String captureInterface;
    private List<RadioStatus.Channel> captureChannels = RadioStatus.FALLBACK_CHANNELS;
    private Integer fixedFrequencyMhz;
    private boolean captureStoppedWhilePaused;
    private boolean capturePausedForOps;
    private String captureError;
    private final Map<String, String> activeOpsLeases = new HashMap<>();
    private volatile PassiveWifiSession passiveWifi;
    private PassiveApWatch apWatch;
    private SniperController sniper = new SniperController();
    private CaptureHealth health;
    private Replay replay;
    private final MyNetworkStore myNetwork = new MyNetworkStore();

    public PacketBridge() {
        this(DEFAULT_TICK_MS);
    }

    public PacketBridge(int tickMs) {
        this(tickMs, new DeviceProfiler());
    }

    public PacketBridge(DeviceProfiler profiler) {
        this(DEFAULT_TICK_MS, profiler);
    }

    public PacketBridge(int tickMs, DeviceProfiler profiler) {
        this(ProcessBuilder::start, loadBundledVendors(), profiler, tickMs, EVENT_QUEUE_CAPACITY,
                EVENT_QUEUE_CAPACITY, RadioStatus::read, RadioStatus::readWiphy, RadioStatus::readChannels);
    }

    @FunctionalInterface
    interface ProcessStarter {
        Process start(ProcessBuilder builder) throws IOException;
    }

    // Process seam keeps tests independent of capture privileges and hardware.
    PacketBridge(ProcessStarter processStarter, Map<String, String> vendors) {
        this(processStarter, vendors, new DeviceProfiler());
    }

    PacketBridge(ProcessStarter processStarter, Map<String, String> vendors, DeviceProfiler profiler) {
        this(processStarter, vendors, profiler, DEFAULT_TICK_MS);
    }

    PacketBridge(ProcessStarter processStarter, Map<String, String> vendors, DeviceProfiler profiler, int tickMs) {
        this(processStarter, vendors, profiler, tickMs, EVENT_QUEUE_CAPACITY);
    }

    PacketBridge(ProcessStarter processStarter, Map<String, String> vendors, DeviceProfiler profiler, int tickMs,
                 int eventCapacity) {
        this(processStarter, vendors, profiler, tickMs, eventCapacity, eventCapacity);
    }

    PacketBridge(ProcessStarter processStarter, Map<String, String> vendors, DeviceProfiler profiler, int tickMs,
                 int ignoredPacketCapacity, int eventCapacity) {
        this(processStarter, vendors, profiler, tickMs, ignoredPacketCapacity, eventCapacity, iface -> null, iface -> iface);
    }

    PacketBridge(ProcessStarter processStarter, Map<String, String> vendors, DeviceProfiler profiler, int tickMs,
                 int ignoredPacketCapacity, int eventCapacity,
                 Function<String, RadioStatus.Settings> radioSettings,
                 Function<String, String> wiphyResolver) {
        this(processStarter, vendors, profiler, tickMs, ignoredPacketCapacity, eventCapacity, radioSettings,
                wiphyResolver, iface -> Optional.empty());
    }

    PacketBridge(ProcessStarter processStarter, Map<String, String> vendors, DeviceProfiler profiler, int tickMs,
                 int ignoredPacketCapacity, int eventCapacity, Function<String, RadioStatus.Settings> radioSettings,
                 Function<String, String> wiphyResolver,
                 Function<String, Optional<List<RadioStatus.Channel>>> radioChannels) {
        this.radioSettings = radioSettings;
        this.wiphyResolver = Objects.requireNonNull(wiphyResolver);
        this.radioChannels = Objects.requireNonNull(radioChannels);
        if (tickMs < 10 || tickMs > 2000) throw new IllegalArgumentException("--tick-ms must be 10..2000");
        if (eventCapacity < 1) throw new IllegalArgumentException("eventCapacity must be positive");
        this.tickMs = tickMs;
        tickNanos = TimeUnit.MILLISECONDS.toNanos(tickMs);
        this.eventCapacity = eventCapacity;
        this.eventQueue = new ArrayBlockingQueue<>(eventCapacity);
        this.processStarter = Objects.requireNonNull(processStarter);
        this.vendors = Map.copyOf(vendors);
        this.profiler = Objects.requireNonNull(profiler);
    }

    public int getTickMs() { return tickMs; }

    public DeviceProfiler getProfiler() { return profiler; }

    /** Binary capture on an operator-prepared radiotap monitor interface. */
    public synchronized void startPassive(String iface) throws IOException {
        startPassive(iface, false);
    }

    public synchronized void startPassive(String iface, boolean collectLabTargets) throws IOException {
        startPassive(iface, collectLabTargets, null);
    }

    /** Runs the monitor decoder and optionally schedules the same radio from its frame observations. */
    public synchronized void startPassive(String iface, boolean collectLabTargets, AdaptiveScanner scanner) throws IOException {
        if (scanner != null && scanner.config().bands() < 13) {
            throw new IllegalArgumentException("Channels 1..13 require at least 13 scanner bands");
        }
        startCapture(iface, scanner, scanner == null ? "watch" : "scan", collectLabTargets, true, null);
    }

    /** Reads an existing PCAP in order, as fast as the decoder can process it. */
    public synchronized void startReplay(Path file) throws IOException {
        startReplay(file, Objects.toString(file.getFileName(), ""), null);
    }

    public synchronized Map<String, Object> startReplay(Path file, String name, UUID recordingId) throws IOException {
        if (isRunning()) throw new IllegalStateException("Capture is already running");
        if (!activeOpsLeases.isEmpty()) throw new IllegalStateException("Stop active Lab Ops before starting replay");
        if (!Files.isRegularFile(file)) throw new IOException("Replay requires a regular PCAP file");
        captureStoppedWhilePaused = false;
        fixedFrequencyMhz = null;
        var started = new Replay(name, recordingId);
        var reports = PassiveWifiSession.forReplay(profiler, myNetwork.get(), started::now);
        started.input = Files.newInputStream(file);
        sniper = new SniperController(reports::addressId);
        profiler.clear();
        replay = started;
        health = started.health;
        passiveWifi = reports;
        captureMode = "replay";
        captureStartedAt = System.currentTimeMillis();
        captureInterface = null;
        channel = 0;
        captureError = null;
        probeCount = 0;
        try {
            Thread.ofPlatform().daemon().name("ewave-pcap-replay").start(() -> readReplay(started, reports));
        } catch (RuntimeException | Error failure) {
            started.state = "FAILED";
            closeStream(started.input);
            throw failure;
        }
        return getCaptureStatus();
    }

    public synchronized void setFixedFrequencyMhz(Integer frequencyMhz) {
        if (frequencyMhz != null && (frequencyMhz < 2300 || frequencyMhz > 7125)) {
            throw new IllegalArgumentException("Frequency must be in 2300..7125 MHz");
        }
        this.fixedFrequencyMhz = frequencyMhz;
        channel = legacyChannel(frequencyMhz == null ? 0 : frequencyMhz);
    }

    /** Serialized runtime capture start/switch preserving live same-interface observations. */
    public synchronized Map<String, Object> configureRuntimeCapture(String mode, String iface, Integer frequencyMhz,
                                                                    Path replayFile, int bands,
                                                                    boolean collectLabTargets) throws IOException {
        return configureRuntimeCapture(mode, iface, frequencyMhz, replayFile, bands, collectLabTargets, false);
    }

    public synchronized Map<String, Object> configureRuntimeCapture(String mode, String iface, Integer frequencyMhz,
                                                                    Path replayFile, int bands,
                                                                    boolean collectLabTargets, boolean requireIdle)
            throws IOException {
        if (requireIdle && isRunning()) throw new IllegalStateException("Stop the current capture first");
        if (!activeOpsLeases.isEmpty()) {
            throw new IllegalStateException("Stop active Lab Ops before changing capture mode");
        }
        if (mode == null) throw new IllegalArgumentException("mode is required (watch, scan, or replay)");
        switch (mode) {
            case "replay" -> {
                if (replayFile == null || !Files.isRegularFile(replayFile) || !Files.isReadable(replayFile)) {
                    throw new IllegalArgumentException("Replay requires a readable PCAP file");
                }
                stop();
                startReplay(replayFile);
            }
            case "watch", "scan" -> {
                if (iface == null || iface.isBlank() || iface.startsWith("-")) {
                    throw new IllegalArgumentException("A valid Wi-Fi interface is required");
                }
                if (bands < 13) throw new IllegalArgumentException("Channels 1..13 require at least 13 scanner bands");
                if ("watch".equals(mode) && frequencyMhz != null && (frequencyMhz < 2300 || frequencyMhz > 7125)) {
                    throw new IllegalArgumentException("Frequency must be in 2300..7125 MHz");
                }
                if ("scan".equals(mode) && frequencyMhz != null) {
                    throw new IllegalArgumentException("Fixed frequency cannot be combined with adaptive scan mode");
                }
                boolean preserveSession = passiveWifi != null && !passiveWifi.isReplaySession()
                        && Objects.equals(captureInterface, iface) && replay == null;
                AdaptiveScanner scanner = "scan".equals(mode)
                        ? new AdaptiveScanner(scannerConfig(bands),
                                Math.max(60, Math.ceilDiv(6000, tickMs)))
                        : null;
                if (session != null || (replay != null && replay.running())) {
                    stopCaptureOnly(!preserveSession);
                }
                if ("watch".equals(mode) && frequencyMhz != null) {
                    tuneInterfaceNow(iface, frequencyMhz);
                    setFixedFrequencyMhz(frequencyMhz);
                } else if ("scan".equals(mode)) {
                    fixedFrequencyMhz = null;
                }
                startCapture(iface, scanner, mode, collectLabTargets, !preserveSession, frequencyMhz);
            }
            default -> throw new IllegalArgumentException("Unsupported capture mode: " + mode);
        }
        return getCaptureStatus();
    }

    private AdaptiveScanner.Config scannerConfig(int bands) {
        var base = AdaptiveScanner.Config.defaults(bands, 2048, 42L);
        // Keep the existing 20-second fitting horizon when the sampling cadence changes.
        return new AdaptiveScanner.Config(base.bands(), base.capacity(), base.refitInterval(), base.minHits(),
                base.smoothing(), base.priorStrength(), Math.max(base.maxPeriod(), Math.ceilDiv(20_000, tickMs)),
                base.pd(), base.pfa(), base.surveyWeight(), base.surveyDuty(), base.optimism(), base.seed());
    }

    /** Stops live capture or replay while keeping collected observations available for inspection. */
    public synchronized Map<String, Object> stopRuntimeCapture() {
        // Stopping passive observation must also cancel any deferred resume held by an Ops lease.
        stopCaptureOnly(true);
        return getCaptureStatus();
    }

    /** Tunes the active monitor interface during fixed-channel watch mode. */
    public synchronized Map<String, Object> tuneChannel(int frequencyMhz) throws IOException {
        if (frequencyMhz < 2300 || frequencyMhz > 7125) {
            throw new IllegalArgumentException("Frequency must be in 2300..7125 MHz");
        }
        if (!activeOpsLeases.isEmpty()) {
            throw new IllegalStateException("Stop active Lab Ops before tuning the channel");
        }
        Session current = session;
        if (current == null || current.health == null || captureInterface == null) {
            throw new IllegalStateException("Start live Wi-Fi capture before tuning a channel");
        }
        if (current.scanner != null || sniper.needsSweep() || sniper.desiredFrequencyMhz() != null) {
            throw new IllegalStateException("Switch to fixed watch and cancel Sniper before manually tuning");
        }
        tuneInterfaceNow(captureInterface, frequencyMhz);
        setFixedFrequencyMhz(frequencyMhz);
        current.confirmTune(frequencyMhz, System.nanoTime(), System.currentTimeMillis());
        return getCaptureStatus();
    }

    private void tuneInterfaceNow(String iface, int frequencyMhz) throws IOException {
        var builder = new ProcessBuilder("sudo", "iw", "dev", iface, "set", "freq", Integer.toString(frequencyMhz))
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(ProcessBuilder.Redirect.DISCARD);
        Process tuning = processStarter.start(builder);
        try {
            if (!tuning.waitFor(2, TimeUnit.SECONDS) || tuning.exitValue() != 0) {
                throw new IOException("Could not tune " + iface + " to " + frequencyMhz + " MHz");
            }
        } catch (InterruptedException stopped) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while tuning " + iface, stopped);
        } finally {
            if (tuning.isAlive()) {
                destroyDescendants(tuning, true);
                tuning.destroyForcibly();
            }
        }
    }

    private void stopCaptureOnly(boolean cancelSniper) {
        Session stopped;
        InputStream replayInput = null;
        synchronized (this) {
            captureStoppedWhilePaused = true;
            stopped = session;
            if (cancelSniper) sniper.cancel();
            if (stopped != null) {
                session = null;
                if (apWatch != null) apWatch.stop(System.currentTimeMillis());
            }
            if (replay != null && replay.running()) {
                replay.state = "STOPPED";
                replayInput = replay.input;
            }
            notifyAll();
        }
        if (stopped != null) terminate(stopped);
        if (replayInput != null) closeStream(replayInput);
    }

    public synchronized CaptureHealth.Report getCaptureHealth() {
        if (health == null) return null;
        Long reference = replay == null || replay.timestamp < 0 ? null : replay.timestamp;
        return health.snapshot(captureMode, replay == null ? captureInterface : replay.filename, isRunning(),
                replay == null ? null : replay.state, captureError, reference, System.currentTimeMillis(),
                replay == null ? monotonicMillis() : replay.now());
    }

    public PassiveWifiSession getPassiveWifi() { return passiveWifi; }

    public synchronized MyNetworkProfile.View myNetwork() throws IOException {
        return networkView(myNetwork.get());
    }

    public synchronized WifiInventory.Detail inventoryDetail(String id) throws IOException {
        var detail = passiveWifi == null ? null : passiveWifi.inventoryDetail(id);
        if (detail == null || detail.fingerprints().isEmpty() || enrolled(myNetwork.get(), id)) return detail;
        return detail.withoutFingerprints();
    }

    public synchronized List<MyNetworkProfile.FingerprintSample> fingerprintSamples() throws IOException {
        return myNetwork.get().fingerprintSamples();
    }

    public synchronized List<MyNetworkProfile.FingerprintSample> saveFingerprintSample(MyNetworkProfile.SampleChange change)
            throws IOException {
        var profile = myNetwork.get();
        if (change == null || change.observedId() == null || !enrolled(profile, change.observedId()))
            throw new IllegalArgumentException("Select an observed device enrolled in My Network");
        var detail = passiveWifi.inventoryDetail(change.observedId());
        var evidence = detail == null ? null : detail.fingerprints().stream()
                .filter(candidate -> candidate.hash().equals(change.hash()) && candidate.source() == change.source())
                .findFirst().orElse(null);
        if (evidence == null) throw new IllegalArgumentException("That fingerprint is no longer available");
        var next = profile.saveSample(change, evidence);
        myNetwork.save(next);
        reportSettings++;
        passiveWifi.useFingerprintSamples(next.fingerprintSamples());
        return next.fingerprintSamples();
    }

    public synchronized List<MyNetworkProfile.FingerprintSample> removeFingerprintSample(UUID id) throws IOException {
        var next = myNetwork.get().removeSample(id);
        myNetwork.save(next);
        reportSettings++;
        if (passiveWifi != null) passiveWifi.useFingerprintSamples(next.fingerprintSamples());
        return next.fingerprintSamples();
    }

    private boolean enrolled(MyNetworkProfile profile, String id) {
        return passiveWifi != null && Stream.concat(profile.accessPoints().stream(), profile.devices().stream())
                .anyMatch(entry -> id.equals(passiveWifi.addressId(entry.address())));
    }

    public synchronized MyNetworkProfile.View changeMyNetwork(MyNetworkProfile.Change change) throws IOException {
        if (change == null) throw new IllegalArgumentException("A setup action is required");
        if ("scope".equals(change.action()) && commandLineScope())
            throw new IllegalArgumentException("Capture scope is set by rf.bssids for this run");
        String observedBssid = null;
        if ("save-ap".equals(change.action()) && change.id() == null && change.observedId() != null) {
            observedBssid = passiveWifi == null ? null : passiveWifi.observedBssid(change.observedId());
            if (observedBssid == null) throw new IllegalArgumentException("That access point has expired. Refresh or enter its BSSID.");
        }
        var next = myNetwork.get().change(change, observedBssid);
        myNetwork.save(next);
        reportSettings++;
        if (passiveWifi != null && passiveWifi.configure(next)) {
            profiler.clear();
            probeCount = 0;
        }
        return networkView(next);
    }

    private MyNetworkProfile.View networkView(MyNetworkProfile profile) {
        return new MyNetworkProfile.View(named(profile.accessPoints()), named(profile.devices()),
                passiveWifi == null ? List.of() : passiveWifi.observedAccessPoints(),
                profile.restrictCapture(), commandLineScope());
    }

    private boolean commandLineScope() {
        return passiveWifi == null ? !System.getProperty("rf.bssids", "").isBlank() : passiveWifi.commandLineScope();
    }

    private List<MyNetworkProfile.NamedEntry> named(List<MyNetworkProfile.Entry> entries) {
        return entries.stream().map(entry -> new MyNetworkProfile.NamedEntry(entry.id(), entry.label(),
                passiveWifi == null ? null : passiveWifi.addressId(entry.address()))).toList();
    }

    private void startCapture(String iface, AdaptiveScanner scanner, String mode, boolean collectLabTargets,
                              boolean resetSession, Integer confirmedFrequencyMhz) throws IOException {
        if (iface == null || iface.isBlank()) throw new IllegalArgumentException("Interface must not be blank");
        if (isRunning()) throw new IllegalStateException("Capture is already running");
        captureStoppedWhilePaused = false;
        List<String> command = PassiveCommandGuard.monitor(iface);
        var builder = new ProcessBuilder(command);
        builder.redirectError(ProcessBuilder.Redirect.PIPE);
        builder.environment().put("LC_ALL", "C");
        PassiveWifiSession reports = !resetSession && passiveWifi != null
                ? passiveWifi : new PassiveWifiSession(profiler, myNetwork.get());
        var channels = resetSession ? List.copyOf(radioChannels.apply(iface).orElse(RadioStatus.FALLBACK_CHANNELS))
                : captureChannels;
        if (scanner != null) scanner = scanner.forBandCount(Math.max(1, channels.size()));
        PassiveCommandGuard.requireWifi(builder.command(), iface);
        Process process = processStarter.start(builder);
        CaptureHealth sessionHealth = !resetSession && health != null ? health : new CaptureHealth();
        Session started = new Session(process, scanner, sessionHealth, collectLabTargets, channels);
        if (resetSession) {
            sniper = new SniperController(reports::addressId);
            sniper.useSweepChannels(channels);
            probeCount = 0;
            profiler.clear();
        }
        sniper.receiverInterrupted();
        captureChannels = channels;
        if (confirmedFrequencyMhz != null) {
            started.confirmTune(confirmedFrequencyMhz, System.nanoTime(), System.currentTimeMillis());
        }
        channel = legacyChannel(started.tunedFrequencyMhz);
        replay = null;
        health = started.health;
        session = started;
        passiveWifi = reports;
        captureMode = mode;
        if (resetSession) captureStartedAt = System.currentTimeMillis();
        captureInterface = iface;
        captureError = null;
        try {
            started.reader = new Thread(() -> readMonitor(started, reports, collectLabTargets), "ewave-packet-reader");
            started.reader.setDaemon(true);
            int timerMs = Math.min(tickMs, DEFAULT_TICK_MS);
            started.timer.scheduleAtFixedRate(() -> onTimer(started, iface), timerMs, timerMs, TimeUnit.MILLISECONDS);
            started.timer.scheduleAtFixedRate(reports::purge, 1, 1, TimeUnit.MINUTES);
            started.timer.scheduleWithFixedDelay(() -> sampleMonitor(started, iface), 0, 5, TimeUnit.SECONDS);
            started.diagnostics = Thread.ofPlatform().daemon().name("ewave-monitor-diagnostics")
                    .start(() -> readDiagnostics(started));
            started.reader.start();
        } catch (RuntimeException | Error failure) {
            session = null;
            terminate(started);
            throw failure;
        }
    }

    /** Records the channel selected by the receiver; this does not tune hardware. */
    public void setChannel(int channel) {
        if (channel < 1 || channel > 14) throw new IllegalArgumentException("Channel must be in 1..14");
        this.channel = channel;
    }

    /** Wi-Fi observation events, with immutable payloads. */
    public BlockingQueue<EwaveEvent> getEventQueue() { return eventQueue; }

    /** Capacity of the bounded event queue. */
    public int getEventQueueCapacity() { return eventCapacity; }

    /** Events discarded because the bounded event queue was full; cumulative across stop/start. */
    public long getDroppedEvents() { return droppedEvents.get(); }

    /** Revisions are independent of the bounded legacy event queue and survive frame bursts. */
    public synchronized ReportProgress reportProgress() {
        return new ReportProgress(passiveWifi == null ? null : passiveWifi.sessionId(), reportFrames,
                reportInventory, reportTopology, reportProbes, reportSettings, getCaptureStatus(), sniperState());
    }

    public record ReportProgress(UUID sessionId, long frames, long inventory, long topology,
                                 long probes, long settings, Map<String, Object> status, SniperState sniper) { }

    private void recordReportObservation(Dot11Frame frame, PassiveWifiSession.Observation observation) {
        if (observation.inventory()) reportInventory++;
        if (observation.topology() && !frame.probe()) reportTopology++;
        if (observation.probe()) {
            reportProbes++;
            probeCount++;
        }
    }

    public synchronized Map<String, Object> getCaptureStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("captureRunning", isRunning());
        status.put("capturePausedForOps", capturePausedForOps && !captureStoppedWhilePaused);
        if (replay != null) {
            status.put("replayState", replay.state);
            status.put("captureSource", replay.filename);
            if (replay.recordingId != null) status.put("recordingId", replay.recordingId);
            if (replay.timestamp >= 0) status.put("referenceTime", replay.timestamp);
        }
        if (channel != 0) status.put("channel", channel);
        if (session != null && session.tunedFrequencyMhz != 0) status.put("frequencyMhz", session.tunedFrequencyMhz);
        status.put("captureMode", captureMode);
        if (captureStartedAt != 0) status.put("captureStartedAt", captureStartedAt);
        status.put("scannerAttached", session != null && session.scanner != null);
        if (captureInterface != null) status.put("captureInterface", captureInterface);
        status.put("probeRequests", probeCount);
        status.put("eventQueueCapacity", eventCapacity);
        status.put("eventsDropped", droppedEvents.get());
        status.put("profileLimit", profiler.profileLimit());
        status.put("profilesEvicted", profiler.evictedCount());
        if (captureError != null) status.put("captureError", captureError);
        if (passiveWifi != null) {
            status.put("sessionId", passiveWifi.sessionId());
            status.put("scopedBssidCount", passiveWifi.scopedBssidCount());
            status.put("neighborhoodProbes", passiveWifi.neighborhoodProbes());
            if (passiveWifi.preferredApId() != null) status.put("preferredApId", passiveWifi.preferredApId());
        }
        return Map.copyOf(status);
    }

    public record ApWatchEvent(int channel, long timestamp) {}
    public record ApWatchRun(UUID id, String apId, boolean adaptive, long startedAt, Long endedAt,
                             ApWatchEvent lastHeard, ApWatchEvent tuned, ApWatchEvent heardAgain) {}
    public record ApWatchState(boolean available, ApWatchRun run) {}

    public synchronized ApWatchState apWatchState() {
        return new ApWatchState(session != null && session.watchAllowed, apWatch == null ? null : apWatch.snapshot());
    }

    public synchronized ApWatchState startApWatch(String apId) {
        if (session == null || !session.watchAllowed)
            throw new IllegalStateException("Start live passive Wi-Fi capture to watch an access point.");
        if (apWatch != null && apWatch.active()) throw new IllegalStateException("Stop the current watch first.");
        String bssid = passiveWifi.observedBssid(apId);
        if (bssid == null) throw new IllegalArgumentException("Choose an access point from the current capture.");
        apWatch = new PassiveApWatch(apId, bssid, session.scanner != null, System.currentTimeMillis());
        return apWatchState();
    }

    public synchronized ApWatchState stopApWatch(UUID id) {
        if (apWatch == null || !apWatch.id().equals(id)) throw new IllegalArgumentException("Watch run has changed.");
        apWatch.stop(System.currentTimeMillis());
        return apWatchState();
    }

    public record SniperState(boolean available, SniperController.Snapshot run) {}

    public synchronized SniperState sniperState() {
        return new SniperState(session != null && session.watchAllowed, sniper.snapshot());
    }

    public synchronized SniperState startSniperBySsid(String ssid) {
        if (ssid == null) throw new IllegalArgumentException("Enter a network name of 1–32 Wi-Fi bytes");
        return startSniperBySsidBytes(ssid.getBytes(StandardCharsets.UTF_8), ssid);
    }

    public synchronized SniperState startSniperBySsidBytes(byte[] ssidBytes, String displaySsid) {
        if (session == null || !session.watchAllowed)
            throw new IllegalStateException("Start live passive Wi-Fi capture to run Sniper.");
        var run = sniper.startBySsid(ssidBytes, displaySsid);
        session.sniperSweep.reset();
        session.survey.interruptListening();
        return new SniperState(true, run);
    }

    public synchronized SniperState startSniperByApId(String apId) {
        if (session == null || !session.watchAllowed)
            throw new IllegalStateException("Start live passive Wi-Fi capture to run Sniper.");
        var details = passiveWifi == null ? null : passiveWifi.observedAp(apId);
        if (details == null) throw new IllegalArgumentException("Choose an access point from the current capture.");
        var run = sniper.startByAp(apId, details.bssid(), details.ssidBytes(),
                details.ssid(), details.channel(), details.frequencyMhz(),
                details.beaconIntervalTu(), details.lastSeen(), details.advertisement());
        session.sniperSweep.reset();
        return new SniperState(true, run);
    }

    public synchronized SniperState selectSniperCandidate(String apId) {
        if (session == null || !session.watchAllowed)
            throw new IllegalStateException("Start live passive Wi-Fi capture to run Sniper.");
        return new SniperState(true, sniper.selectCandidate(apId));
    }

    public synchronized SniperState switchSniperAffiliatedLink(int frequencyMhz) {
        if (session == null || !session.watchAllowed)
            throw new IllegalStateException("Start live passive Wi-Fi capture to run Sniper.");
        sniper.switchAffiliatedLink(frequencyMhz);
        if (!session.retunePending) tuneForSniper(session, captureInterface, frequencyMhz, System.currentTimeMillis());
        return sniperState();
    }

    public synchronized SniperState stopSniper() {
        return new SniperState(session != null && session.watchAllowed, sniper.cancel());
    }

    public synchronized SniperState stopSniper(UUID id) {
        var current = sniper.snapshot();
        if (current.id() == null || !current.id().equals(id))
            throw new IllegalArgumentException("Sniper run has changed.");
        return stopSniper();
    }

    public record ChannelCoverage(int channel, int frequencyMhz, Long lastTuneAtMs, Long lastFrameAtMs,
                                  Long lastFrameWhileTunedAtMs, long airtimeMicrosWhileTuned, Integer medianNoiseDbm) {}

    public record RadioTelemetry(Integer lastConfirmedChannel, Integer lastObservedChannel, boolean retuning, long successfulRetunes,
                                 long failedRetunes, Double meanRetuneMs, List<Long> dwellMs,
                                 List<ChannelCoverage> coverage, Integer lastConfirmedFrequencyMhz,
                                 Integer lastObservedFrequencyMhz) {}

    public record HeldAnomaly(int channel, int freqMhz, double deviation, Instant detectedAt, Instant lastActiveAt,
                              String reason, String floodType, boolean activeNow) {}

    public record ChannelSnapshot(AdaptiveScanner.Snapshot scanner, Integer activeChannel, Integer lastChosen,
                                  Instant timestamp, RadioTelemetry radio, List<RadioStatus.Channel> channels,
                                  Integer lastChosenFrequencyMhz, Map<Integer, HeldAnomaly> heldAnomalies,
                                  List<HeldAnomaly> recentAnomalies) {
        public int slotForFrequency(int frequencyMhz) {
            for (int slot = 0; slot < channels.size(); slot++) {
                if (channels.get(slot).frequencyMhz() == frequencyMhz) return slot;
            }
            return -1;
        }
    }

    /** Summary scanner and radio state at the next capture tick, or null without a running scanner. */
    public synchronized ChannelSnapshot getChannelSnapshot() {
        if (session == null || session.scanner == null) return null;
        synchronized (session.scanner) {
            var scanner = session.scanner.snapshot(tick, tickMs);
            long now = System.nanoTime();
            Instant timestamp = Instant.now();
            var held = new HashMap<Integer, HeldAnomaly>();
            for (int slot = 0; slot < session.channels.size(); slot++) {
                var anomaly = session.lookoutAnomalies.onChannel(slot, now);
                if (anomaly != null) held.put(anomaly.freqMhz(), anomaly);
            }
            return new ChannelSnapshot(scanner,
                    session.tunedChannel == 0 ? null : session.tunedChannel, session.lastChosenFrequencyMhz == null ? null
                    : Dot11FrameDecoder.channel(session.lastChosenFrequencyMhz), timestamp, session.radioTelemetry(),
                    session.channels, session.lastChosenFrequencyMhz, Map.copyOf(held), session.lookoutAnomalies.recent(now));
        }
    }

    public static Integer channelFrequencyMhz(int channel) {
        return channel < 1 || channel > 13 ? null : 2407 + channel * 5;
    }

    private static int legacyChannel(int frequencyMhz) {
        return frequencyMhz >= 2412 && frequencyMhz <= 2484 ? Dot11FrameDecoder.channel(frequencyMhz) : 0;
    }

    public synchronized boolean isRunning() { return session != null || replay != null && replay.running(); }

    /** Replay observations remain analysis-only after completion, failure, or stop. */
    public synchronized boolean isReplaySession() {
        return passiveWifi != null && passiveWifi.isReplaySession();
    }

    private record PausedSession(String iface, AdaptiveScanner scanner, String mode, boolean collectLabTargets) {}

    /** Exclusive physical-radio lease for active Lab Ops; restores the current desired passive policy on close. */
    public final class OpsLease implements AutoCloseable {
        private final String wiphy;
        private final PausedSession paused;
        private final java.util.concurrent.atomic.AtomicBoolean released = new java.util.concurrent.atomic.AtomicBoolean();

        private OpsLease(String wiphy, PausedSession paused) {
            this.wiphy = wiphy;
            this.paused = paused;
        }

        @Override public void close() {
            if (released.compareAndSet(false, true)) releaseOpsLease(wiphy, paused);
        }
    }

    public OpsLease acquireOpsLease(String requestedInterface, boolean pauseMonitorCapture) {
        String target = requestedInterface == null || requestedInterface.isBlank() ? "wlo1" : requestedInterface;
        String wiphy = wiphyResolver.apply(target);
        if (wiphy == null || wiphy.isBlank()) wiphy = target;
        Session toPause = null;
        PausedSession pausedInfo = null;
        synchronized (this) {
            if (isReplaySession()) {
                throw new IllegalStateException("Lab operations are unavailable for replay sessions");
            }
            if (activeOpsLeases.containsKey(wiphy)) {
                throw new IllegalStateException("An active operation already owns radio " + wiphy);
            }
            activeOpsLeases.put(wiphy, target);
            Session current = session;
            boolean sameRadio = current != null && captureInterface != null
                    && wiphy.equals(Objects.requireNonNullElse(wiphyResolver.apply(captureInterface), captureInterface));
            if (sameRadio) {
                current.opsPaused = true;
                sniper.setOpsPaused(true);
                current.sniperSweep.reset();
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
                while (session == current && (current.retunePending || current.tuning)) {
                    long remainingMs = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime());
                    if (remainingMs <= 0) break;
                    try {
                        wait(Math.min(200, remainingMs));
                    } catch (InterruptedException interrupted) {
                        activeOpsLeases.remove(wiphy);
                        current.opsPaused = false;
                        sniper.setOpsPaused(false);
                        Thread.currentThread().interrupt();
                        throw new IllegalStateException("Interrupted while waiting for radio retune", interrupted);
                    }
                }
                if (pauseMonitorCapture && current.health != null && session == current) {
                    toPause = current;
                    pausedInfo = new PausedSession(captureInterface, current.scanner, captureMode,
                            current.collectLabTargets);
                    capturePausedForOps = true;
                    session = null;
                }
            }
        }
        if (toPause != null) terminate(toPause);
        return new OpsLease(wiphy, pausedInfo);
    }

    private void releaseOpsLease(String wiphy, PausedSession paused) {
        synchronized (this) {
            activeOpsLeases.remove(wiphy);
            if (paused != null) capturePausedForOps = false;
            sniper.setOpsPaused(false);
            if (captureStoppedWhilePaused) return;
            if (paused != null && session == null) {
                try {
                    startCapture(paused.iface(), paused.scanner(), paused.mode(), paused.collectLabTargets(), false, null);
                } catch (IOException failure) {
                    captureError = "Failed to resume capture after Lab Ops: " + failure.getMessage();
                    LOG.log(System.Logger.Level.WARNING, captureError, failure);
                }
            }
            Session current = session;
            if (current != null && captureInterface != null
                    && wiphy.equals(Objects.requireNonNullElse(wiphyResolver.apply(captureInterface), captureInterface))) {
                current.opsPaused = false;
                current.tunedChannel = 0;
                current.tunedFrequencyMhz = 0;
                Integer desired = sniper.desiredFrequencyMhz();
                if (desired == null && !sniper.needsSweep() && current.scanner == null) {
                    desired = fixedFrequencyMhz;
                }
                if (desired != null) {
                    var purpose = sniper.desiredFrequencyMhz() == null ? TunePurpose.FIXED : TunePurpose.SNIPER_LOCK;
                    requestRetune(current, captureInterface, desired, purpose);
                } else if (sniper.needsSweep() || current.scanner != null) {
                    current.survey.interruptListening();
                }
            }
            notifyAll();
        }
    }

    /** Stops capture and preserves collected observations. */
    public void stop() {
        stopCaptureOnly(true);
    }

    @Override public void close() { stop(); }

    private void readMonitor(Session current, PassiveWifiSession reports, boolean collectLabTargets) {
        try (InputStream input = current.process.getInputStream()) {
            MonitorPcapReader.readRecords(input, (packet, link, timestamp, complete) -> {
                var frame = complete ? Dot11FrameDecoder.decodeAny(packet, link, timestamp) : null;
                int control = Dot11FrameDecoder.frameControl(packet, link);
                synchronized (this) {
                    if (session != current) return;
                    long now = System.currentTimeMillis();
                    current.receivedFrame = true;
                    reportFrames++;
                    current.health.record(control, complete, frame, timestamp, now, monotonicMillis());
                    if (frame == null) return;
                    long receivedAt = System.nanoTime();
                    if (current.scanner != null) advanceTicks(current, receivedAt);
                    int frequency = frame.frequencyMhz();
                    int slot = current.slot(frequency);
                    if (slot >= 0) {
                        current.counts[slot]++;
                        current.lastFrameAtMs[slot] = Math.max(current.lastFrameAtMs[slot], frame.timestamp());
                        if (current.scanner != null && current.lookoutAnomalies.observeFrame(slot, frame, receivedAt)) {
                            synchronized (current.scanner) {
                                current.lookoutAnomalies.update(slot, current.scanner.activeAnomaly(slot),
                                        receivedAt, Instant.ofEpochMilli(now));
                            }
                        }
                        if (!current.tuning && current.tunedFrequencyMhz == frequency) {
                            current.recordTunedFrame(slot, frame);
                            if (current.lastTuneAtMs[slot] != 0 && frame.timestamp() >= current.lastTuneAtMs[slot]) {
                                current.survey.frame(receivedAt, frequency);
                                current.lastFrameWhileTunedAtMs[slot] = Math.max(
                                        current.lastFrameWhileTunedAtMs[slot], frame.timestamp());
                            }
                        }
                    }
                    if (current.watchAllowed) {
                        sniper.observeTransmitterActivity(frame);
                        if (apWatch != null) apWatch.observe(frame);
                    }
                }
                var observed = reports.observe(frame);
                long now = System.currentTimeMillis();
                synchronized (this) {
                    if (session != current) return;
                    if (frame.apAdvertisement() && (frame.capability() & 1) != 0 && frame.addr3().equals(frame.addr2())) {
                        String apId = reports.addressId(frame.addr3());
                        var details = reports.observedAp(apId);
                        sniper.observeFrame(frame, apId, frame.addr3(),
                                details != null ? details.ssidBytes() : frame.ies().first(0),
                                details != null ? details.ssid() : null);
                    }
                    if (collectLabTargets && observed.inventory() && frame.type() != 1
                            && !(frame.management() && (frame.subtype() == 10 || frame.subtype() == 12))) {
                        profiler.observe(new PacketEvent(frame.addr2(), frame.addr1(),
                                Dot11FrameDecoder.channel(frame.frequencyMhz()), frame.rssi(), frame.frameLength(),
                                "802.11", frame.timestamp(), null));
                    }
                    recordReportObservation(frame, observed);
                    if (observed.inventory() && now >= current.nextDeviceEvent) {
                        current.nextDeviceEvent = now + 1000;
                        publishEvent(new EwaveEvent("WIFI_DEVICE_SEEN", now, null));
                    }
                    if (observed.probe() && now >= current.nextProbeEvent) {
                        current.nextProbeEvent = now + 1000;
                        publishEvent(new EwaveEvent("PROBE_RECEIVED", now, null));
                    }
                }
            }, () -> session != current);
            reportProbeFailure(current, "Monitor capture ended");
        } catch (IOException | RuntimeException failure) {
            reportProbeFailure(current, Objects.toString(failure.getMessage(), "Monitor capture failed"));
        } finally {
            endSession(current);
        }
    }

    private void readReplay(Replay current, PassiveWifiSession reports) {
        String error = null;
        try (var input = current.input) {
            MonitorPcapReader.readRecords(input, (packet, link, timestamp, complete) -> {
                var frame = complete ? Dot11FrameDecoder.decodeAny(packet, link, timestamp) : null;
                int control = Dot11FrameDecoder.frameControl(packet, link);
                synchronized (this) {
                    if (replay != current || !current.running()) return;
                    current.timestamp = Math.max(current.timestamp, timestamp);
                    reportFrames++;
                    current.health.record(control, complete, frame,
                            timestamp, System.currentTimeMillis(), timestamp);
                    if (frame == null) return;
                }
                var observed = reports.observe(frame);
                synchronized (this) {
                    if (replay == current && current.running()) recordReportObservation(frame, observed);
                }
            }, () -> !current.running());
        } catch (IOException | RuntimeException failure) {
            error = Objects.toString(failure.getMessage(), "PCAP replay failed");
        } finally {
            synchronized (this) {
                if (replay == current && current.running()) {
                    current.state = error == null ? "COMPLETE" : "FAILED";
                    captureError = error;
                }
            }
        }
    }

    private void sampleMonitor(Session current, String iface) {
        var settings = radioSettings.apply(iface);
        synchronized (this) {
            if (session != current) return;
            if (settings != null) current.health.updateRadio(settings);
            if (!current.receivedFrame) return;
        }
        requestTcpdumpStatistics(current.process);
    }

    private static void requestTcpdumpStatistics(Process capture) {
        if (!System.getProperty("os.name", "").equals("Linux")) return;
        try {
            var handle = capture.toHandle();
            String command = handle.info().command().orElse("");
            if (!handle.isAlive() || !(command.equals("tcpdump") || command.endsWith("/tcpdump"))) return;
            // Only signal our own tcpdump child after its first frame, when its handlers are installed.
            Process signal = new ProcessBuilder("kill", "-USR1", Long.toString(handle.pid()))
                    .redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
            if (!signal.waitFor(500, TimeUnit.MILLISECONDS)) signal.destroyForcibly();
        } catch (IOException | UnsupportedOperationException unavailable) {
            // Kernel counters remain unavailable until tcpdump prints a summary.
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private void readDiagnostics(Session current) {
        try (var reader = new BufferedReader(new InputStreamReader(current.process.getErrorStream(), StandardCharsets.UTF_8))) {
            for (String line; (line = reader.readLine()) != null;) {
                boolean stats;
                synchronized (this) {
                    if (health != current.health) return;
                    stats = current.health.diagnostics(line, System.currentTimeMillis());
                    String diag = current.health.diagnosticError();
                    if (diag != null && captureError != null) {
                        captureError = formatCaptureError(exitCodeOrNull(current.process), diag, captureError);
                    }
                }
                if (!stats) System.err.println(line);
            }
        } catch (IOException closed) {
            LOG.log(System.Logger.Level.DEBUG, "Monitor diagnostics stream closed", closed);
        }
    }

    private static long monotonicMillis() { return TimeUnit.NANOSECONDS.toMillis(System.nanoTime()); }

    private void reportProbeFailure(Session current, String fallback) {
        // Never hold the bridge lock while waiting for the child or diagnostics stream to finish.
        try {
            current.process.waitFor(250, TimeUnit.MILLISECONDS);
            if (current.diagnostics != null && current.diagnostics != Thread.currentThread()) {
                current.diagnostics.join(250);
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
        Integer exitCode = exitCodeOrNull(current.process);
        synchronized (this) {
            if (session != current) return;
            String diag = current.health == null ? null : current.health.diagnosticError();
            captureError = formatCaptureError(exitCode, diag, fallback);
            LOG.log(System.Logger.Level.WARNING, captureError);
        }
    }

    private static Integer exitCodeOrNull(Process process) {
        try {
            return process.exitValue();
        } catch (IllegalThreadStateException running) {
            // A read failure can occur while tcpdump is still running.
            return null;
        }
    }

    private static String formatCaptureError(Integer exitCode, String diagnostic, String fallback) {
        String message = diagnostic != null && !diagnostic.isBlank() ? diagnostic : fallback;
        String text = exitCode != null && exitCode != 0
                ? "tcpdump exited with code " + exitCode + ": " + message
                : message;
        return text.length() > MAX_CAPTURE_ERROR ? text.substring(0, MAX_CAPTURE_ERROR - 1) + "…" : text;
    }

    private void onTimer(Session current, String iface) {
        try {
            synchronized (this) {
                if (session != current || current.opsPaused) return;
                long now = System.nanoTime();
                if (current.scanner != null) {
                    if (now - current.nextBoundary >= 0) {
                        advanceTicks(current, now);
                    } else {
                        // Rolling frame counts can expire between scanner samples.
                        synchronized (current.scanner) {
                            Instant wallTime = Instant.now();
                            for (int slot = 0; slot < current.channels.size(); slot++) {
                                current.lookoutAnomalies.update(slot, current.scanner.activeAnomaly(slot), now, wallTime);
                            }
                        }
                    }
                }
                if (sniper.tick()) {
                    current.sniperSweep.reset();
                    current.survey.interruptListening();
                }
                if (current.retunePending) return;
                Integer sniperFreq = sniper.desiredFrequencyMhz();
                if (sniperFreq != null) {
                    tuneForSniper(current, iface, sniperFreq, System.currentTimeMillis());
                    return;
                }
                if (sniper.needsSweep()) {
                    sweepForSniper(current, iface, now);
                    return;
                }
                if (current.scanner == null || current.channels.isEmpty()) return;
                var survey = current.survey;
                if (survey.listeningChannel() != 0 && !survey.dwellFinished(now)) return;
                int frequency;
                if (!survey.bootstrapComplete()) {
                    if (tick == current.lastSurveyTick) return;
                    current.lastSurveyTick = tick;
                    frequency = survey.channel(now);
                } else {
                    if (survey.failedTuneCoolingDown(now)) return;
                    synchronized (current.scanner) {
                        int[] choices = current.scanner.choose(tick, Math.min(2, current.channels.size()),
                                current.scannerWeights).bands();
                        int slot = choices[0];
                        if (choices.length > 1 && slot == current.slot(survey.lastAttempted())) slot = choices[1];
                        frequency = current.channels.get(slot).frequencyMhz();
                    }
                }
                if (current.tunedFrequencyMhz == frequency) {
                    current.lastChosenFrequencyMhz = frequency;
                    survey.listenOnConfirmedChannel(now, frequency);
                    return;
                }
                requestRetune(current, iface, frequency, TunePurpose.SURVEY);
            }
        } catch (RuntimeException failure) {
            LOG.log(System.Logger.Level.WARNING, "Capture tick failed", failure);
            endSession(current);
        }
    }

    private void sweepForSniper(Session current, String iface, long now) {
        var planner = current.sniperSweep;
        int finished = planner.finishDwell(now);
        if (finished != 0) {
            sniper.setActiveSweepFrequency(null);
            sniper.sweepFrequencyFinished(finished, true);
            Integer locked = sniper.desiredFrequencyMhz();
            if (locked != null) {
                tuneForSniper(current, iface, locked, System.currentTimeMillis());
                return;
            }
            if (!sniper.needsSweep()) return;
        }
        if (planner.listeningFrequency() != 0) return;
        AdaptiveScanner.Snapshot scanner = null;
        if (current.scanner != null) {
            synchronized (current.scanner) {
                scanner = current.scanner.snapshot(tick);
            }
        }
        int frequency = planner.nextFrequency(scanner, sniper.prioritySweepFrequencies(), sniper.lostSweepOrigin());
        if (frequency == 0) return;
        if (current.tunedFrequencyMhz == frequency) {
            current.lastChosenFrequencyMhz = frequency;
            planner.tuneFinished(now, frequency, true, 0);
            sniper.setActiveSweepFrequency(frequency);
        } else {
            requestRetune(current, iface, frequency, TunePurpose.SNIPER_SWEEP);
        }
    }

    private void tuneForSniper(Session current, String iface, int frequency, long wallTime) {
        if (current.tunedFrequencyMhz == frequency) {
            current.lastChosenFrequencyMhz = frequency;
            sniper.tuneConfirmed(current.tunedChannel, frequency, wallTime);
        } else {
            requestRetune(current, iface, frequency, TunePurpose.SNIPER_LOCK);
        }
    }

    private enum TunePurpose { FIXED, SURVEY, SNIPER_SWEEP, SNIPER_LOCK }

    private void requestRetune(Session current, String iface, int frequency, TunePurpose purpose) {
        current.lastChosenFrequencyMhz = frequency;
        if (current.tunedFrequencyMhz == frequency) return;
        UUID runId = sniper.runId();
        current.retunePending = true;
        current.retuner.execute(() -> retune(current, iface, frequency, purpose, runId));
    }

    private boolean canRetune(int frequency, TunePurpose purpose, UUID runId) {
        return switch (purpose) {
            case SNIPER_SWEEP -> Objects.equals(runId, sniper.runId()) && sniper.needsSweep();
            case SNIPER_LOCK -> Objects.equals(runId, sniper.runId()) && Objects.equals(frequency, sniper.desiredFrequencyMhz());
            case SURVEY, FIXED -> !sniper.needsSweep() && sniper.desiredFrequencyMhz() == null;
        };
    }

    private void retune(Session current, String iface, int frequency, TunePurpose purpose, UUID runId) {
        if (Thread.currentThread().isInterrupted()) return;
        synchronized (this) {
            if (session != current || current.opsPaused || !canRetune(frequency, purpose, runId)) {
                current.retunePending = false;
                notifyAll();
                return;
            }
            if (current.tunedFrequencyMhz == frequency) {
                current.retunePending = false;
                notifyAll();
                return;
            }
            current.recordDwell(System.nanoTime());
            current.tuning = true;
        }
        long started = System.nanoTime();
        var builder = new ProcessBuilder("sudo", "iw", "dev", iface, "set", "freq", Integer.toString(frequency))
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(ProcessBuilder.Redirect.DISCARD);
        LOG.log(System.Logger.Level.DEBUG, "Retuning passive receiver to " + frequency + " MHz");
        Process tuning = null;
        boolean succeeded = false;
        try {
            tuning = processStarter.start(builder);
            if (tuning.waitFor(2, TimeUnit.SECONDS) && tuning.exitValue() == 0) {
                succeeded = true;
            }
        } catch (IOException failure) {
            LOG.log(System.Logger.Level.DEBUG, "Could not launch radio retune", failure);
        } catch (InterruptedException stopped) {
            Thread.currentThread().interrupt();
        } finally {
            if (tuning != null && tuning.isAlive()) {
                destroyDescendants(tuning, true);
                tuning.destroyForcibly();
            }
            synchronized (this) {
                if (session == current) {
                    long completed = System.nanoTime();
                    current.dwellStarted = completed;
                    if (succeeded) {
                        current.successfulRetunes++;
                        current.retuneNanos += completed - started;
                        long confirmedAt = System.currentTimeMillis();
                        current.confirmTune(frequency, completed, confirmedAt);
                        channel = legacyChannel(frequency);
                        sniper.tuneConfirmed(current.tunedChannel, frequency, confirmedAt);
                        if (apWatch != null && Objects.equals(channelFrequencyMhz(channel), frequency)) {
                            apWatch.tuneConfirmed(channel, confirmedAt);
                        }
                    } else {
                        current.failedRetunes++;
                        current.tunedChannel = 0;
                        current.tunedFrequencyMhz = 0;
                        channel = 0;
                    }
                    if (!current.opsPaused && canRetune(frequency, purpose, runId)) {
                        if (purpose == TunePurpose.SURVEY) {
                            current.survey.tuneFinished(completed, frequency, succeeded, completed - started);
                        } else if (purpose == TunePurpose.SNIPER_SWEEP) {
                            current.sniperSweep.tuneFinished(completed, frequency, succeeded, completed - started);
                            sniper.setActiveSweepFrequency(succeeded ? frequency : null);
                            if (!succeeded) sniper.sweepFrequencyFinished(frequency, false);
                        } else if (purpose == TunePurpose.SNIPER_LOCK && !succeeded) {
                            sniper.tuneFailed(frequency);
                        }
                    }
                }
                current.retunePending = false;
                current.tuning = false;
                notifyAll();
            }
        }
    }

    private void advanceTicks(Session current, long now) {
        while (now - current.nextBoundary >= 0) {
            synchronized (current.scanner) {
                int tunedSlot = current.slot(current.tunedFrequencyMhz);
                Instant wallTime = Instant.now();
                for (int slot = 0; slot < current.channels.size(); slot++) {
                    boolean detected = current.counts[slot] > 0;
                    // A monitor radio cannot report quiet observations on channels it did not sample.
                    boolean valid = detected || !current.tuning && tunedSlot == slot
                            && current.nextBoundary - current.dwellStarted >= tickNanos;
                    current.scanner.observe(slot, tick, detected, valid);
                    current.lookoutAnomalies.update(slot, current.scanner.activeAnomaly(slot), now, wallTime);
                }
            }
            Arrays.fill(current.counts, 0);
            tick++;
            current.nextBoundary += tickNanos;
        }
    }

    private static double scannerWeight(RadioStatus.Channel channel) {
        int frequency = channel.frequencyMhz();
        int number = channel.channel();
        boolean preferred = frequency >= 2400 && frequency < 2500 && (number == 1 || number == 6 || number == 11)
                || frequency >= 4900 && frequency < 5925 && !Boolean.TRUE.equals(channel.radarDetection())
                || frequency >= 5925 && frequency <= 7125 && (number - 5) % 16 == 0;
        return preferred ? 1.25 : 0.8;
    }

    private void publishEvent(EwaveEvent event) {
        if (eventQueue.offer(event)) return;
        if (eventQueue.poll() != null) recordEventDrop();
        if (!eventQueue.offer(event)) recordEventDrop();
    }

    private void recordEventDrop() {
        if (droppedEvents.incrementAndGet() == 1) {
            LOG.log(System.Logger.Level.WARNING,
                    "Event queue reached capacity " + eventCapacity + "; oldest events are being discarded.");
        }
    }

    private void endSession(Session current) {
        synchronized (this) {
            if (session != current) return; // A stopped reader cannot tear down a newer capture.
            session = null;
            if (apWatch != null) apWatch.stop(System.currentTimeMillis());
            sniper.cancel();
        }
        terminate(current);
    }

    private static void terminate(Session current) {
        current.timer.shutdownNow();
        if (current.retuner != null) current.retuner.shutdownNow();
        if (current.reader != null && current.reader != Thread.currentThread()) current.reader.interrupt();
        if (current.diagnostics != null && current.diagnostics != Thread.currentThread()) current.diagnostics.interrupt();
        destroyDescendants(current.process, false);
        current.process.destroy();
        boolean interrupted = false;
        try {
            if (!current.process.waitFor(500, TimeUnit.MILLISECONDS)) {
                destroyDescendants(current.process, true);
                current.process.destroyForcibly();
                if (!current.process.waitFor(500, TimeUnit.MILLISECONDS)) {
                    LOG.log(System.Logger.Level.WARNING, "tcpdump did not exit after forced termination");
                }
            }
        } catch (InterruptedException failure) {
            interrupted = true;
            destroyDescendants(current.process, true);
            current.process.destroyForcibly();
        }
        closeStream(current.process.getInputStream());
        closeStream(current.process.getOutputStream());
        closeStream(current.process.getErrorStream());
        interrupted |= joinThread(current.reader);
        interrupted |= joinThread(current.diagnostics);
        if (interrupted) Thread.currentThread().interrupt();
    }

    private static boolean joinThread(Thread thread) {
        if (thread == null || thread == Thread.currentThread()) return false;
        try {
            thread.join(1_000);
            return false;
        } catch (InterruptedException failure) {
            return true;
        }
    }

    private static void destroyDescendants(Process process, boolean forcible) {
        try {
            process.descendants().toList().reversed()
                    .forEach(forcible ? ProcessHandle::destroyForcibly : ProcessHandle::destroy);
        } catch (UnsupportedOperationException ignored) {
            // Fake Process implementations in tests may lack handles.
        }
    }

    private static void closeStream(Closeable stream) {
        try {
            stream.close();
        } catch (IOException failure) {
            LOG.log(System.Logger.Level.DEBUG, "Failed to close tcpdump stream", failure);
        }
    }

    private static Map<String, String> loadBundledVendors() {
        try (InputStream input = PacketBridge.class.getResourceAsStream("/oui.txt")) {
            if (input == null) {
                LOG.log(System.Logger.Level.WARNING, "No classpath oui.txt; device vendors will be Unknown");
                return Map.of();
            }
            return loadVendors(input);
        } catch (IOException failure) {
            LOG.log(System.Logger.Level.WARNING, "Unable to load classpath oui.txt", failure);
            return Map.of();
        }
    }

    // Accepts IEEE (hex)/(base 16) entries and simple prefix/vendor text files.
    static Map<String, String> loadVendors(InputStream input) throws IOException {
        Map<String, String> result = new HashMap<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                Matcher entry = OUI.matcher(line);
                if (entry.matches()) {
                    String[] names = entry.group(2).split("\\t+| {2,}", 2);
                    result.put(entry.group(1).replace(":", "").replace("-", "")
                            .toLowerCase(Locale.ROOT), names[names.length - 1].strip());
                }
            }
        }
        return Map.copyOf(result);
    }

    private final class Session {
        final Process process;
        final AdaptiveScanner scanner;
        final CaptureHealth health;
        final boolean watchAllowed;
        final boolean collectLabTargets;
        final List<RadioStatus.Channel> channels;
        final Map<Integer, Integer> slots = new HashMap<>();
        final PassiveChannelSurvey survey;
        final SniperSweepPlanner sniperSweep;
        final ThreadPoolExecutor retuner;
        final long[] counts;
        final double[] scannerWeights;
        final LookoutAnomalies lookoutAnomalies;
        long nextDeviceEvent, nextProbeEvent;
        long lastSurveyTick = tick;
        Integer lastChosenFrequencyMhz;
        int tunedChannel;
        int tunedFrequencyMhz;
        boolean receivedFrame;
        boolean tuning, retunePending, opsPaused;
        long successfulRetunes, failedRetunes, retuneNanos, dwellStarted;
        final long[] dwellNanos;
        final long[] lastTuneAtMs;
        final long[] lastFrameAtMs;
        final long[] lastFrameWhileTunedAtMs;
        final long[] airtimeMicrosWhileTuned;
        final int[][] noiseSamples;
        final int[] noiseSampleCounts;
        final int[] noiseSampleCursors;

        int slot(int frequencyMhz) { return slots.getOrDefault(frequencyMhz, -1); }

        void confirmTune(int frequencyMhz, long now, long wallTime) {
            tunedFrequencyMhz = frequencyMhz;
            tunedChannel = Dot11FrameDecoder.channel(frequencyMhz);
            dwellStarted = now;
            int slot = slot(frequencyMhz);
            if (slot >= 0) lastTuneAtMs[slot] = wallTime;
        }

        void recordDwell(long now) {
            int slot = slot(tunedFrequencyMhz);
            if (!tuning && slot >= 0) dwellNanos[slot] += now - dwellStarted;
            dwellStarted = now;
        }

        void recordTunedFrame(int slot, Dot11Frame frame) {
            airtimeMicrosWhileTuned[slot] += FrameAirtime.estimateMicros(frame);
            Integer noise = frame.radiotap() == null ? null : frame.radiotap().noiseDbm();
            if (noise == null || noise <= -128 || noise >= 0) return;
            int[] samples = noiseSamples[slot];
            int cursor = noiseSampleCursors[slot];
            samples[cursor] = noise;
            noiseSampleCursors[slot] = (cursor + 1) % samples.length;
            if (noiseSampleCounts[slot] < samples.length) noiseSampleCounts[slot]++;
        }

        private Integer medianNoiseDbm(int slot) {
            int size = noiseSampleCounts[slot];
            if (size == 0) return null;
            int[] samples = Arrays.copyOf(noiseSamples[slot], size);
            Arrays.sort(samples);
            return (int) Math.round((samples[(size - 1) / 2] + samples[size / 2]) / 2.0);
        }

        RadioTelemetry radioTelemetry() {
            long[] dwell = dwellNanos.clone();
            int slot = slot(tunedFrequencyMhz);
            if (!tuning && slot >= 0) dwell[slot] += System.nanoTime() - dwellStarted;
            int observedFrequency = health.observedFrequencyMhz();
            Integer observed = slot(observedFrequency) < 0 ? null : health.observedChannel();
            return new RadioTelemetry(tunedChannel == 0 ? null : tunedChannel, observed,
                    tuning, successfulRetunes,
                    failedRetunes, successfulRetunes == 0 ? null : retuneNanos / (successfulRetunes * 1_000_000.0),
                    Arrays.stream(dwell).map(TimeUnit.NANOSECONDS::toMillis).boxed().toList(), channelCoverage(),
                    tunedFrequencyMhz == 0 ? null : tunedFrequencyMhz, observedFrequency == 0 ? null : observedFrequency);
        }

        private List<ChannelCoverage> channelCoverage() {
            var coverage = new ArrayList<ChannelCoverage>(lastTuneAtMs.length);
            for (int band = 0; band < lastTuneAtMs.length; band++) {
                var channel = channels.get(band);
                coverage.add(new ChannelCoverage(channel.channel(), channel.frequencyMhz(),
                        lastTuneAtMs[band] == 0 ? null : lastTuneAtMs[band],
                        lastFrameAtMs[band] == 0 ? null : lastFrameAtMs[band],
                        lastFrameWhileTunedAtMs[band] == 0 ? null : lastFrameWhileTunedAtMs[band],
                        airtimeMicrosWhileTuned[band], medianNoiseDbm(band)));
            }
            return List.copyOf(coverage);
        }

        final ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor(task -> {
            Thread thread = new Thread(task, "ewave-capture-ticks");
            thread.setDaemon(true);
            return thread;
        });
        long nextBoundary = System.nanoTime() + tickNanos;
        Thread reader;
        Thread diagnostics;

        Session(Process process, AdaptiveScanner scanner, CaptureHealth health, boolean collectLabTargets,
                List<RadioStatus.Channel> channels) {
            this.process = process;
            this.scanner = scanner;
            this.health = health;
            this.watchAllowed = true;
            this.collectLabTargets = collectLabTargets;
            this.channels = channels;
            int size = channels.size();
            for (int i = 0; i < size; i++) slots.put(channels.get(i).frequencyMhz(), i);
            counts = new long[size];
            scannerWeights = channels.stream().mapToDouble(PacketBridge::scannerWeight).toArray();
            lookoutAnomalies = scanner == null ? null : new LookoutAnomalies(channels);
            dwellNanos = new long[size];
            lastTuneAtMs = new long[size];
            lastFrameAtMs = new long[size];
            lastFrameWhileTunedAtMs = new long[size];
            airtimeMicrosWhileTuned = new long[size];
            noiseSamples = new int[size][32];
            noiseSampleCounts = new int[size];
            noiseSampleCursors = new int[size];
            survey = new PassiveChannelSurvey(channels.stream().map(RadioStatus.Channel::frequencyMhz).toList(), 1200);
            sniperSweep = new SniperSweepPlanner(channels);
            // Serialize commands and keep only the latest pending choice if iw is slow.
            retuner = new ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS,
                    new ArrayBlockingQueue<>(1),
                    task -> Thread.ofPlatform().daemon().name("ewave-radio-retune").unstarted(task),
                    new ThreadPoolExecutor.DiscardOldestPolicy());
        }
    }

    private static final class Replay {
        final String filename;
        final UUID recordingId;
        final CaptureHealth health = new CaptureHealth();
        InputStream input;
        volatile long timestamp = -1;
        volatile String state = "RUNNING";

        Replay(String filename, UUID recordingId) {
            this.filename = filename;
            this.recordingId = recordingId;
        }
        long now() { return Math.max(0, timestamp); }
        boolean running() { return state.equals("RUNNING"); }
    }
}
