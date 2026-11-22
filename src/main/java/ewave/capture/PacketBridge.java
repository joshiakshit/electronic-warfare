package ewave.capture;

import ewave.core.AdaptiveScanner;
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
    public static final int DEFAULT_TICK_MS = 100;
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
    private final DeviceProfiler profiler;
    private volatile int channel;
    // Guarded by this, including every session's counters and pending packets.
    private volatile Session session;
    private long tick;
    private long probeCount;
    private String captureMode = "idle";
    private long captureStartedAt;
    private String captureInterface;
    private Integer fixedFrequencyMhz;
    private boolean captureStoppedWhilePaused;
    private String captureError;
    private final Map<String, String> activeOpsLeases = new HashMap<>();
    private volatile PassiveWifiSession passiveWifi;
    private PassiveApWatch apWatch;
    private final SniperController sniper = new SniperController();
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
                EVENT_QUEUE_CAPACITY, RadioStatus::read, RadioStatus::readWiphy);
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
        this.radioSettings = radioSettings;
        this.wiphyResolver = Objects.requireNonNull(wiphyResolver);
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
        startCapture(iface, scanner, scanner == null ? "watch" : "scan", collectLabTargets, true);
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
        sniper.cancel();
        var started = new Replay(name, recordingId);
        var reports = PassiveWifiSession.forReplay(profiler, myNetwork.get(), started::now);
        started.input = Files.newInputStream(file);
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
        if (frequencyMhz != null && frequencyMhz >= 2412 && frequencyMhz <= 2484) {
            int ch = Dot11FrameDecoder.channel(frequencyMhz);
            if (ch >= 1 && ch <= 14) this.channel = ch;
        }
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
                        ? new AdaptiveScanner(AdaptiveScanner.Config.defaults(bands, 2048, 42L),
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
                startCapture(iface, scanner, mode, collectLabTargets, !preserveSession);
            }
            default -> throw new IllegalArgumentException("Unsupported capture mode: " + mode);
        }
        return getCaptureStatus();
    }

    /** Stops live capture or replay while keeping collected observations available for inspection. */
    public synchronized Map<String, Object> stopRuntimeCapture() {
        if (!activeOpsLeases.isEmpty()) {
            throw new IllegalStateException("Stop active Lab Ops before stopping capture");
        }
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
        int ch24 = (frequencyMhz >= 2412 && frequencyMhz <= 2484) ? Dot11FrameDecoder.channel(frequencyMhz) : 0;
        current.tunedFrequencyMhz = frequencyMhz;
        current.tunedChannel = ch24;
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
            if (stopped != null) {
                session = null;
                if (apWatch != null) apWatch.stop(System.currentTimeMillis());
                if (cancelSniper) sniper.cancel();
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
        return new WifiInventory.Detail(detail.signalHistory(), List.of());
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
        return next.fingerprintSamples();
    }

    public synchronized List<MyNetworkProfile.FingerprintSample> removeFingerprintSample(UUID id) throws IOException {
        var next = myNetwork.get().removeSample(id);
        myNetwork.save(next);
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
                              boolean resetSession) throws IOException {
        if (iface == null || iface.isBlank()) throw new IllegalArgumentException("Interface must not be blank");
        if (isRunning()) throw new IllegalStateException("Capture is already running");
        captureStoppedWhilePaused = false;
        List<String> command = PassiveCommandGuard.monitor(iface);
        var builder = new ProcessBuilder(command);
        builder.redirectError(ProcessBuilder.Redirect.PIPE);
        builder.environment().put("LC_ALL", "C");
        PassiveWifiSession reports = !resetSession && passiveWifi != null
                ? passiveWifi : new PassiveWifiSession(profiler, myNetwork.get());
        PassiveCommandGuard.requireWifi(builder.command(), iface);
        Process process = processStarter.start(builder);
        CaptureHealth sessionHealth = !resetSession && health != null ? health : new CaptureHealth();
        Session started = new Session(process, scanner, sessionHealth, collectLabTargets);
        if (resetSession) sniper.cancel();
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
            started.timer.scheduleAtFixedRate(() -> onTimer(started, iface), tickMs, tickMs, TimeUnit.MILLISECONDS);
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

    public synchronized Map<String, Object> getCaptureStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("captureRunning", isRunning());
        if (replay != null) {
            status.put("replayState", replay.state);
            status.put("captureSource", replay.filename);
            if (replay.recordingId != null) status.put("recordingId", replay.recordingId);
            if (replay.timestamp >= 0) status.put("referenceTime", replay.timestamp);
        }
        if (channel != 0) status.put("channel", channel);
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
        if (session.survey != null) session.survey.reset();
        return new SniperState(true, sniper.startBySsid(ssidBytes, displaySsid));
    }

    public synchronized SniperState startSniperByApId(String apId) {
        if (session == null || !session.watchAllowed)
            throw new IllegalStateException("Start live passive Wi-Fi capture to run Sniper.");
        var details = passiveWifi == null ? null : passiveWifi.observedAp(apId);
        if (details == null) throw new IllegalArgumentException("Choose an access point from the current capture.");
        return new SniperState(true, sniper.startByAp(apId, details.bssid(), details.ssidBytes(),
                details.ssid(), details.channel(), details.frequencyMhz(),
                details.beaconIntervalTu(), details.lastSeen()));
    }

    public synchronized SniperState selectSniperCandidate(String apId) {
        if (session == null || !session.watchAllowed)
            throw new IllegalStateException("Start live passive Wi-Fi capture to run Sniper.");
        return new SniperState(true, sniper.selectCandidate(apId));
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

    public record ChannelCoverage(int channel, Long lastTuneAtMs, Long lastFrameAtMs,
                                  Long lastFrameWhileTunedAtMs) {}

    public record RadioTelemetry(Integer lastConfirmedChannel, Integer lastObservedChannel, boolean retuning, long successfulRetunes,
                                 long failedRetunes, Double meanRetuneMs, List<Long> dwellMs,
                                 List<ChannelCoverage> coverage) {
        public RadioTelemetry(Integer lastConfirmedChannel, Integer lastObservedChannel, boolean retuning,
                              long successfulRetunes, long failedRetunes, Double meanRetuneMs, List<Long> dwellMs) {
            this(lastConfirmedChannel, lastObservedChannel, retuning, successfulRetunes, failedRetunes, meanRetuneMs,
                    dwellMs, List.of());
        }
    }

    public record ChannelSnapshot(AdaptiveScanner.Snapshot scanner, Integer activeChannel, Integer lastChosen,
                                  Instant timestamp, RadioTelemetry radio) {
        public ChannelSnapshot(AdaptiveScanner.Snapshot scanner, Integer activeChannel, Integer lastChosen,
                               Instant timestamp) {
            this(scanner, activeChannel, lastChosen, timestamp, null);
        }
    }

    /** Summary scanner and radio state at the next capture tick, or null without a running scanner. */
    public synchronized ChannelSnapshot getChannelSnapshot() {
        if (session == null || session.scanner == null) return null;
        synchronized (session.scanner) {
            return new ChannelSnapshot(session.scanner.snapshot(tick, tickMs),
                    channel == 0 ? null : channel, session.lastChosen, Instant.now(), session.radioTelemetry());
        }
    }

    public static Integer channelFrequencyMhz(int channel) {
        return channel < 1 || channel > 13 ? null : 2407 + channel * 5;
    }

    public synchronized boolean isRunning() { return session != null || replay != null && replay.running(); }

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
            sniper.setOpsPaused(false);
            if (captureStoppedWhilePaused) return;
            if (paused != null && session == null) {
                try {
                    startCapture(paused.iface(), paused.scanner(), paused.mode(), paused.collectLabTargets(), false);
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
                if (desired != null && current.retuner != null) {
                    int targetFreq = desired;
                    int ch = Dot11FrameDecoder.channel(targetFreq);
                    int requestedCh = ch >= 1 && ch <= 13 ? ch : 0;
                    current.retunePending = true;
                    current.retuner.execute(() -> retune(current, captureInterface, requestedCh, targetFreq));
                } else if ((sniper.needsSweep() || current.scanner != null) && current.survey != null) {
                    current.survey.reset();
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
                    current.health.record(control, complete, frame, timestamp, now, monotonicMillis());
                    if (frame == null) return;
                    if (current.scanner != null) {
                        advanceTicks(current, System.nanoTime());
                    }
                    int observedChannel = Dot11FrameDecoder.channel(frame.frequencyMhz());
                    if (observedChannel >= 1 && observedChannel <= 13
                            && Integer.valueOf(frame.frequencyMhz()).equals(channelFrequencyMhz(observedChannel))) {
                        if (current.scanner != null) current.counts[observedChannel]++;
                        if (current.survey != null) {
                            int band = observedChannel - 1;
                            current.lastFrameAtMs[band] = Math.max(current.lastFrameAtMs[band], frame.timestamp());
                            if (!current.tuning && current.tunedChannel == observedChannel
                                    && current.lastTuneAtMs[band] != 0 && frame.timestamp() >= current.lastTuneAtMs[band]) {
                                current.survey.frame(System.nanoTime(), observedChannel);
                                current.lastFrameWhileTunedAtMs[band] = Math.max(
                                        current.lastFrameWhileTunedAtMs[band], frame.timestamp());
                            }
                        }
                    }
                    if (current.watchAllowed && apWatch != null) apWatch.observe(frame);
                }
                var observed = reports.observe(frame);
                if (frame.apAdvertisement() && (frame.capability() & 1) != 0 && frame.addr3().equals(frame.addr2())) {
                    String apId = reports.addressId(frame.addr3());
                    var details = reports.observedAp(apId);
                    sniper.observeFrame(frame, apId, frame.addr3(),
                            details != null ? details.ssidBytes() : frame.ies().first(0),
                            details != null ? details.ssid() : null);
                }
                if (collectLabTargets && observed.inventory()) {
                    profiler.observe(new PacketEvent(frame.addr2(), frame.addr1(),
                            Dot11FrameDecoder.channel(frame.frequencyMhz()), frame.rssi(), frame.frameLength(),
                            "802.11", frame.timestamp(), null));
                }
                long now = System.currentTimeMillis();
                synchronized (this) {
                    if (session != current) return;
                    if (observed.probe()) probeCount++;
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
                    current.health.record(control, complete, frame,
                            timestamp, System.currentTimeMillis(), timestamp);
                    if (frame == null) return;
                }
                var observed = reports.observe(frame);
                if (observed.probe()) {
                    synchronized (this) {
                        if (replay == current && current.running()) probeCount++;
                    }
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
                    advanceTicks(current, now);
                }
                sniper.tick();
                Integer sniperFreq = sniper.desiredFrequencyMhz();
                boolean sniperSweep = sniperFreq == null && sniper.needsSweep();
                if (sniperFreq == null && !sniperSweep) {
                    if (current.scanner == null) return;
                    if (tick == current.lastDecisionTick) return;
                    // The packet reader can also close windows, so check the tick even
                    // when advanceTicks did not close a window in this callback.
                    current.lastDecisionTick = tick;
                }
                var survey = current.survey;
                if (survey != null && current.retunePending) return;
                if (sniperFreq != null) {
                    if (current.tunedFrequencyMhz == sniperFreq) return;
                    int ch = Dot11FrameDecoder.channel(sniperFreq);
                    current.lastChosen = ch >= 1 && ch <= 13 ? ch : null;
                    if (survey != null) current.retunePending = true;
                    current.retuner.execute(() -> retune(current, iface, ch, sniperFreq));
                    return;
                }
                int chosen;
                if (survey != null) {
                    chosen = survey.channel(now);
                    int listening = survey.listeningChannel();
                    if (sniperSweep && listening != 0 && listening == current.tunedChannel && chosen != listening) {
                        sniper.sweepChannelFinished(listening);
                        Integer lockedFreq = sniper.desiredFrequencyMhz();
                        if (lockedFreq != null) {
                            int lockedCh = Dot11FrameDecoder.channel(lockedFreq);
                            current.lastChosen = lockedCh >= 1 && lockedCh <= 13 ? lockedCh : null;
                            if (current.tunedFrequencyMhz == lockedFreq) return;
                            current.retunePending = true;
                            current.retuner.execute(() -> retune(current, iface, lockedCh, lockedFreq));
                            return;
                        }
                        if (!sniper.needsSweep() && current.scanner == null) return;
                    }
                } else {
                    synchronized (current.scanner) {
                        chosen = current.scanner.choose(tick, 1).bands()[0] + 1;
                    }
                }
                current.lastChosen = chosen;
                Integer frequency = channelFrequencyMhz(chosen);
                if (frequency == null) return;
                if (survey != null && current.tunedChannel == chosen && current.tunedFrequencyMhz == frequency) {
                    survey.listenOnConfirmedChannel(now, chosen);
                    return;
                }
                int requested = chosen;
                if (survey != null) current.retunePending = true;
                current.retuner.execute(() -> retune(current, iface, requested, frequency));
            }
        } catch (RuntimeException failure) {
            LOG.log(System.Logger.Level.WARNING, "Capture tick failed", failure);
            endSession(current);
        }
    }

    private void retune(Session current, String iface, int chosen, int frequency) {
        if (Thread.currentThread().isInterrupted()) return;
        synchronized (this) {
            if (session != current || current.opsPaused) {
                current.retunePending = false;
                notifyAll();
                return;
            }
            if (current.health != null && current.tunedFrequencyMhz == frequency) {
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
        LOG.log(System.Logger.Level.INFO, "[AdaptiveScanner] chose channel " + chosen + " → " + frequency + "MHz");
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
                    int ch24 = (frequency >= 2412 && frequency <= 2484) ? Dot11FrameDecoder.channel(frequency) : 0;
                    if (succeeded) {
                        current.successfulRetunes++;
                        current.retuneNanos += completed - started;
                        current.tunedFrequencyMhz = frequency;
                        current.tunedChannel = ch24;
                        if (ch24 >= 1 && ch24 <= 14) channel = ch24;
                        long confirmedAt = System.currentTimeMillis();
                        sniper.tuneConfirmed(Dot11FrameDecoder.channel(frequency), frequency, confirmedAt);
                        if (current.survey != null && ch24 >= 1 && ch24 <= 13) {
                            current.lastTuneAtMs[ch24 - 1] = confirmedAt;
                            if (apWatch != null) apWatch.tuneConfirmed(ch24, confirmedAt);
                        }
                    } else {
                        current.failedRetunes++;
                        current.tunedChannel = 0;
                        current.tunedFrequencyMhz = 0;
                    }
                    if (current.survey != null && chosen >= 1 && chosen <= 13 && sniper.desiredFrequencyMhz() == null) {
                        current.survey.tuneFinished(completed, chosen, succeeded, completed - started);
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
                for (int band = 1; band <= 13; band++) {
                    boolean detected = current.counts[band] > 0;
                    // A monitor radio cannot report quiet observations on channels it did not sample.
                    boolean valid = current.health == null || detected || !current.tuning && current.tunedChannel == band
                            && current.nextBoundary - current.dwellStarted >= tickNanos;
                    current.scanner.observe(band - 1, tick, detected, valid);
                }
            }
            Arrays.fill(current.counts, 0);
            tick++;
            current.nextBoundary += tickNanos;
        }
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
        final PassiveChannelSurvey survey;
        final ThreadPoolExecutor retuner;
        final long[] counts = new long[14];
        long nextDeviceEvent, nextProbeEvent;
        long lastDecisionTick = tick;
        Integer lastChosen;
        int tunedChannel;
        int tunedFrequencyMhz;
        boolean receivedFrame;
        boolean tuning, retunePending, opsPaused;
        long successfulRetunes, failedRetunes, retuneNanos, dwellStarted;
        final long[] dwellNanos = new long[13];
        final long[] lastTuneAtMs = new long[dwellNanos.length];
        final long[] lastFrameAtMs = new long[dwellNanos.length];
        final long[] lastFrameWhileTunedAtMs = new long[dwellNanos.length];

        void recordDwell(long now) {
            if (!tuning && tunedChannel >= 1 && tunedChannel <= 13) dwellNanos[tunedChannel - 1] += now - dwellStarted;
            dwellStarted = now;
        }

        RadioTelemetry radioTelemetry() {
            long[] dwell = dwellNanos.clone();
            if (!tuning && tunedChannel >= 1 && tunedChannel <= 13) dwell[tunedChannel - 1] += System.nanoTime() - dwellStarted;
            int observed = health == null ? 0 : health.observedChannel();
            if (health != null && !Objects.equals(channelFrequencyMhz(observed), health.observedFrequencyMhz())) {
                observed = 0;
            }
            return new RadioTelemetry(tunedChannel == 0 ? null : tunedChannel, observed == 0 ? null : observed,
                    tuning, successfulRetunes,
                    failedRetunes, successfulRetunes == 0 ? null : retuneNanos / (successfulRetunes * 1_000_000.0),
                    Arrays.stream(dwell).map(TimeUnit.NANOSECONDS::toMillis).boxed().toList(), channelCoverage());
        }

        private List<ChannelCoverage> channelCoverage() {
            if (survey == null || scanner == null) return List.of();
            var coverage = new ArrayList<ChannelCoverage>(lastTuneAtMs.length);
            for (int band = 0; band < lastTuneAtMs.length; band++) {
                coverage.add(new ChannelCoverage(band + 1, lastTuneAtMs[band] == 0 ? null : lastTuneAtMs[band],
                        lastFrameAtMs[band] == 0 ? null : lastFrameAtMs[band],
                        lastFrameWhileTunedAtMs[band] == 0 ? null : lastFrameWhileTunedAtMs[band]));
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

        Session(Process process, AdaptiveScanner scanner, CaptureHealth health, boolean collectLabTargets) {
            this.process = process;
            this.scanner = scanner;
            this.health = health;
            this.watchAllowed = true;
            this.collectLabTargets = collectLabTargets;
            survey = health != null ? new PassiveChannelSurvey() : null;
            // Serialize commands and keep only the latest pending choice if iw is slow.
            retuner = (health != null || scanner != null) ? new ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS,
                    new ArrayBlockingQueue<>(1),
                    task -> Thread.ofPlatform().daemon().name("ewave-radio-retune").unstarted(task),
                    new ThreadPoolExecutor.DiscardOldestPolicy()) : null;
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
