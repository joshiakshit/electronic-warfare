package ewave.capture;

import ewave.core.AdaptiveScanner;
import ewave.decoder.Dot11Frame;
import ewave.decoder.Dot11FrameDecoder;
import ewave.model.DeviceRecord;
import ewave.model.PacketEvent;
import ewave.model.ProbeRequest;
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
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Tcpdump capture: line-oriented packets or named probe requests.
 * Summary mode uses configurable (default 100 ms), monotonic-clock observation windows.
 * Channels 1..13 map to scanner band indexes 0..12,
 * so the scanner must have at least 13 bands. Channel 14 packets are queued only.
 * Summary-mode feedback marks every channel valid, including quiet channels.
 * Probe mode parses tcpdump text without feeding the general scanner.
 *
 * <p>Call {@link #setChannel(int)} when tuning the receiver if tcpdump does not
 * print channel metadata. Unavailable channels are represented by 0 and unavailable
 * RSSI by NaN; neither is guessed. Lines lacking timestamps, both addresses or a
 * printed length are skipped in summary mode. Probe text does not supply a frame length.
 * Text probes preserve any previously observed signal measurement.
 *
 * <p>Ticks, discovered devices and queued events survive stop/start. A scanner
 * supplied to a new bridge must have fresh feedback chronology. All bridge access
 * to the single-threaded scanner is synchronized on the scanner; callers sharing
 * it must use the same monitor. The optional packet retention queue is bounded
 * and evicts the oldest packets; overflow is counted by {@link #getDroppedPackets()}.
 * The event queue is unbounded and should be drained.
 */
public final class PacketBridge implements AutoCloseable {
    private static final System.Logger LOG = System.getLogger(PacketBridge.class.getName());
    public static final int DEFAULT_TICK_MS = 100;
    private final int tickMs;
    private final long tickNanos;
    private static final String MAC = "(?:[0-9a-f]{2}:){5}[0-9a-f]{2}";
    private static final Pattern TIMESTAMP = Pattern.compile("^\\s*(\\d+(?:\\.\\d+)?)\\s+");
    private static final Pattern ETHERNET = Pattern.compile("(" + MAC + ")\\s*>\\s*(" + MAC + ")", Pattern.CASE_INSENSITIVE);
    private static final Pattern SOURCE = Pattern.compile("\\bSA:(" + MAC + ")", Pattern.CASE_INSENSITIVE);
    private static final Pattern DESTINATION = Pattern.compile("\\bDA:(" + MAC + ")", Pattern.CASE_INSENSITIVE);
    private static final Pattern TRANSMITTER = Pattern.compile("\\bTA:(" + MAC + ")", Pattern.CASE_INSENSITIVE);
    private static final Pattern RECEIVER = Pattern.compile("\\bRA:(" + MAC + ")", Pattern.CASE_INSENSITIVE);
    private static final Pattern PROBE_SENDER = Pattern.compile(
            "\\b(" + MAC + ")(?:\\s+\\([^)]*\\))?\\s*>", Pattern.CASE_INSENSITIVE);
    private static final Pattern PROBE_SSID = Pattern.compile("\\bSSID\\s+'((?:\\\\.|[^'\\\\])*)'", Pattern.CASE_INSENSITIVE);
    private static final Pattern PROBE_NAME = Pattern.compile(
            "\\bProbe Request\\s+\\((.*?)\\)(?=\\s*(?:,|\\[|$))", Pattern.CASE_INSENSITIVE);
    private static final Pattern LENGTH = Pattern.compile("\\blength\\s+(\\d+)\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern FREQUENCY = Pattern.compile("\\b(\\d{4})\\s*MHz\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern CHANNEL = Pattern.compile("\\b(?:channel|chan)\\s*[=:]?\\s*(\\d+)\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern SIGNAL = Pattern.compile("(-?\\d+(?:\\.\\d+)?)\\s*dBm\\s+signal\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern PROTOCOL = Pattern.compile("\\bethertype\\s+([^\\s,(]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern OUI = Pattern.compile(
            "^\\s*([0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}|[0-9a-f]{6})"
                    + "\\s+(?:\\((?:hex|base 16)\\)\\s+)?(.+?)\\s*$", Pattern.CASE_INSENSITIVE);

    private final ConcurrentHashMap<String, DeviceRecord> devices = new ConcurrentHashMap<>();
    private final Map<String, DeviceRecord> deviceView = Collections.unmodifiableMap(devices);
    /** Default cap for the diagnostic packet queue; production does not drain it. */
    public static final int PACKET_QUEUE_CAPACITY = 1024;
    private final BlockingQueue<PacketEvent> packetQueue;
    private final int packetCapacity;
    private final AtomicLong droppedPackets = new AtomicLong();
    private final BlockingQueue<EwaveEvent> eventQueue = new LinkedBlockingQueue<>();
    public static final int RECENT_PROBE_LIMIT = 256;
    private final ArrayDeque<ProbeRequest> recentProbes = new ArrayDeque<>();
    private final Map<String, String> vendors;
    private final ProcessStarter processStarter;
    private final DeviceProfiler profiler;
    private volatile int channel;
    // Guarded by this, including every session's counters and pending packets.
    private Session session;
    private long tick;
    private long probeCount;
    private String captureMode = "packets";
    private String captureInterface;
    private String captureError;
    private PassiveWifiSession passiveWifi;
    private PassiveApWatch apWatch;
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
        this(ProcessBuilder::start, loadBundledVendors(), profiler, tickMs);
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
        this(processStarter, vendors, profiler, tickMs, PACKET_QUEUE_CAPACITY);
    }

    PacketBridge(ProcessStarter processStarter, Map<String, String> vendors, DeviceProfiler profiler, int tickMs,
                 int packetCapacity) {
        if (tickMs < 10 || tickMs > 2000) throw new IllegalArgumentException("--tick-ms must be 10..2000");
        if (packetCapacity < 1) throw new IllegalArgumentException("packetCapacity must be positive");
        this.tickMs = tickMs;
        tickNanos = TimeUnit.MILLISECONDS.toNanos(tickMs);
        this.packetCapacity = packetCapacity;
        this.packetQueue = new ArrayBlockingQueue<>(packetCapacity);
        this.processStarter = Objects.requireNonNull(processStarter);
        this.vendors = Map.copyOf(vendors);
        this.profiler = Objects.requireNonNull(profiler);
    }

    public int getTickMs() { return tickMs; }

    public DeviceProfiler getProfiler() { return profiler; }

    /** Starts a new capture, or throws if already running; launch failures leave it restartable. */
    public synchronized void start(String iface, AdaptiveScanner scanner) throws IOException {
        Objects.requireNonNull(scanner, "scanner");
        if (scanner.config().bands() < 13) {
            throw new IllegalArgumentException("Channels 1..13 require at least 13 scanner bands");
        }
        startCapture(iface, scanner, "packets", false);
    }

    /** Passive, filtered capture on an already prepared monitor-mode interface.
     * Probe-only traffic does not supply generic scanner observations or quiet misses.
     */
    public synchronized void startProbes(String iface) throws IOException {
        startCapture(iface, null, "probes", false);
    }

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
        startCapture(iface, scanner, "passive-rf", collectLabTargets);
    }

    /** Reads an existing PCAP in order, as fast as the decoder can process it. */
    public synchronized void startReplay(Path file) throws IOException {
        if (isRunning()) throw new IllegalStateException("Capture is already running");
        if (!Files.isRegularFile(file)) throw new IOException("Replay requires a regular PCAP file");
        var started = new Replay(file.getFileName().toString());
        var reports = PassiveWifiSession.forReplay(profiler, myNetwork.get(), started::now);
        started.input = Files.newInputStream(file);
        replay = started;
        health = started.health;
        passiveWifi = reports;
        captureMode = "replay";
        captureInterface = null;
        captureError = null;
        probeCount = 0;
        try {
            Thread.ofPlatform().daemon().name("ewave-pcap-replay").start(() -> readReplay(started, reports));
        } catch (RuntimeException | Error failure) {
            started.state = "FAILED";
            closeStream(started.input);
            throw failure;
        }
    }

    public synchronized CaptureHealth.Report getCaptureHealth() {
        if (health == null) return null;
        Long reference = replay == null || replay.timestamp < 0 ? null : replay.timestamp;
        return health.snapshot(captureMode, replay == null ? captureInterface : replay.filename, isRunning(),
                replay == null ? null : replay.state, captureError, reference, System.currentTimeMillis(),
                replay == null ? monotonicMillis() : replay.now());
    }

    public synchronized PassiveWifiSession getPassiveWifi() { return passiveWifi; }

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

    private void startCapture(String iface, AdaptiveScanner scanner, String mode, boolean collectLabTargets) throws IOException {
        if (iface == null || iface.isBlank()) throw new IllegalArgumentException("Interface must not be blank");
        if (isRunning()) throw new IllegalStateException("Capture is already running");
        boolean probes = mode.equals("probes"), monitor = mode.equals("passive-rf");
        List<String> command = monitor ? PassiveCommandGuard.monitor(iface) : probes
                ? PassiveCommandGuard.probes(iface) : PassiveCommandGuard.packets(iface);
        var builder = new ProcessBuilder(command);
        builder.redirectError(monitor ? ProcessBuilder.Redirect.PIPE
                : probes ? ProcessBuilder.Redirect.DISCARD : ProcessBuilder.Redirect.INHERIT);
        if (monitor) builder.environment().put("LC_ALL", "C");
        PassiveWifiSession reports = monitor ? new PassiveWifiSession(profiler, myNetwork.get()) : null;
        PassiveCommandGuard.requireWifi(builder.command(), iface);
        Process process = processStarter.start(builder);
        Session started = new Session(process, scanner, monitor ? new CaptureHealth() : null,
                monitor && !collectLabTargets);
        replay = null;
        health = started.health;
        session = started;
        passiveWifi = reports;
        captureMode = mode;
        captureInterface = iface;
        captureError = null;
        try {
            started.reader = new Thread(() -> {
                if (monitor) readMonitor(started, reports, collectLabTargets);
                else if (probes) readProbes(started);
                else readPackets(started);
            }, "ewave-packet-reader");
            started.reader.setDaemon(true);
            if (scanner != null) started.timer.scheduleAtFixedRate(() -> onTimer(started, iface),
                    tickMs, tickMs, TimeUnit.MILLISECONDS);
            if (reports != null) {
                started.timer.scheduleAtFixedRate(reports::purge, 1, 1, TimeUnit.MINUTES);
                started.timer.scheduleWithFixedDelay(() -> sampleMonitor(started, iface), 0, 5, TimeUnit.SECONDS);
                Thread.ofPlatform().daemon().name("ewave-monitor-diagnostics").start(() -> readDiagnostics(started));
            }
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

    public Map<String, DeviceRecord> getDevices() { return deviceView; }

    public BlockingQueue<PacketEvent> getPacketQueue() { return packetQueue; }

    /** Capacity of the bounded diagnostic packet queue. */
    public int getPacketQueueCapacity() { return packetCapacity; }

    /** Packets discarded because the bounded packet queue was full; cumulative across stop/start. */
    public long getDroppedPackets() { return droppedPackets.get(); }

    /** Device lifecycle and decoded-probe events, with immutable payloads. */
    public BlockingQueue<EwaveEvent> getEventQueue() { return eventQueue; }

    /** Most recent requests, oldest first, bounded across stop/start. */
    public synchronized List<ProbeRequest> getProbeRequests() { return List.copyOf(recentProbes); }

    public synchronized Map<String, Object> getCaptureStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("captureRunning", isRunning());
        if (replay != null) {
            status.put("replayState", replay.state);
            if (replay.timestamp >= 0) status.put("referenceTime", replay.timestamp);
        }
        if (channel != 0) status.put("channel", channel);
        status.put("captureMode", captureMode);
        status.put("scannerAttached", session != null && session.scanner != null);
        if (captureInterface != null) status.put("captureInterface", captureInterface);
        status.put("probeRequests", probeCount);
        status.put("recentProbeLimit", RECENT_PROBE_LIMIT);
        status.put("packetQueueCapacity", packetCapacity);
        status.put("packetsDropped", droppedPackets.get());
        if (captureError != null) status.put("captureError", captureError);
        if (passiveWifi != null) {
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

    /** Stops capture and publishes pending packets without inventing a complete final tick. */
    public void stop() {
        Session stopped;
        InputStream replayInput = null;
        synchronized (this) {
            stopped = session;
            if (stopped != null) {
                session = null;
                if (apWatch != null) apWatch.stop(System.currentTimeMillis());
                publishPending(stopped);
            }
            if (replay != null && replay.running()) {
                replay.state = "STOPPED";
                replayInput = replay.input;
            }
        }
        if (stopped != null) terminate(stopped);
        if (replayInput != null) closeStream(replayInput);
    }

    @Override public void close() { stop(); }

    private void readPackets(Session current) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                current.process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while (!Thread.currentThread().isInterrupted() && (line = reader.readLine()) != null) {
                synchronized (this) {
                    if (session != current) return;
                    advanceTicks(current, System.nanoTime());
                    PacketEvent packet = parseLine(line, channel);
                    if (packet == null) continue;
                    profiler.observe(packet);
                    if (packet.channel() >= 1 && packet.channel() <= 13) current.counts[packet.channel()]++;
                    current.pending.add(packet);
                    if (current.pending.size() >= packetCapacity) publishPending(current);
                    updateDevice(packet.srcMac(), packet, true);
                    if (!packet.dstMac().equals(packet.srcMac())) updateDevice(packet.dstMac(), packet, false);
                }
            }
            synchronized (this) {
                if (session == current) LOG.log(System.Logger.Level.WARNING, "tcpdump stdout closed; stopping capture");
            }
        } catch (IOException | RuntimeException failure) {
            synchronized (this) {
                if (session == current) LOG.log(System.Logger.Level.WARNING, "Capture reader failed", failure);
            }
        } finally {
            endSession(current);
        }
    }

    private void readMonitor(Session current, PassiveWifiSession reports, boolean collectLabTargets) {
        try (InputStream input = current.process.getInputStream()) {
            MonitorPcapReader.readRecords(input, (packet, link, timestamp, complete) -> {
                var frame = complete ? Dot11FrameDecoder.decodeAny(packet, link, timestamp) : null;
                synchronized (this) {
                    if (session != current) return;
                    long now = System.currentTimeMillis();
                    current.health.record(Dot11FrameDecoder.frameControl(packet, link), complete, frame,
                            timestamp, now, monotonicMillis());
                    if (frame == null) return;
                    if (current.scanner != null) {
                        advanceTicks(current, System.nanoTime());
                        int observedChannel = Dot11FrameDecoder.channel(frame.frequencyMhz());
                        if (observedChannel >= 1 && observedChannel <= 13) {
                            current.counts[observedChannel]++;
                            if (current.survey != null && frame.frequencyMhz() == channelFrequencyMhz(observedChannel)) {
                                int band = observedChannel - 1;
                                current.lastFrameAtMs[band] = Math.max(current.lastFrameAtMs[band], frame.timestamp());
                                if (!current.tuning && current.tunedChannel == observedChannel
                                        && current.lastTuneAtMs[band] != 0 && frame.timestamp() >= current.lastTuneAtMs[band]) {
                                    current.lastFrameWhileTunedAtMs[band] = Math.max(
                                            current.lastFrameWhileTunedAtMs[band], frame.timestamp());
                                }
                            }
                        }
                    }
                    if (current.watchAllowed && apWatch != null) apWatch.observe(frame);
                    var observed = recordMonitorFrame(frame, reports, collectLabTargets);
                    if (observed.inventory() && now >= current.nextDeviceEvent) {
                        current.nextDeviceEvent = now + 1000;
                        eventQueue.add(new EwaveEvent("WIFI_DEVICE_SEEN", now, null));
                    }
                    if (observed.probe() && now >= current.nextProbeEvent) {
                        current.nextProbeEvent = now + 1000;
                        eventQueue.add(new EwaveEvent("PROBE_RECEIVED", now, null));
                    }
                }
            });
            reportProbeFailure(current, "Monitor capture ended");
        } catch (IOException | RuntimeException failure) {
            reportProbeFailure(current, Objects.toString(failure.getMessage(), "Monitor capture failed"));
        } finally {
            endSession(current);
        }
    }

    private PassiveWifiSession.Observation recordMonitorFrame(Dot11Frame frame, PassiveWifiSession reports,
                                                                boolean collectLabTargets) {
        var observed = reports.observe(frame);
        if (collectLabTargets && observed.inventory()) profiler.observe(new PacketEvent(frame.addr2(), frame.addr1(),
                Dot11FrameDecoder.channel(frame.frequencyMhz()), frame.rssi(), frame.frameLength(),
                "802.11", frame.timestamp(), null));
        if (observed.probe()) probeCount++;
        return observed;
    }

    private void readReplay(Replay current, PassiveWifiSession reports) {
        String error = null;
        try (var input = current.input) {
            MonitorPcapReader.readRecords(input, (packet, link, timestamp, complete) -> {
                var frame = complete ? Dot11FrameDecoder.decodeAny(packet, link, timestamp) : null;
                synchronized (this) {
                    if (replay != current || !current.running()) return;
                    current.timestamp = Math.max(current.timestamp, timestamp);
                    current.health.record(Dot11FrameDecoder.frameControl(packet, link), complete, frame,
                            timestamp, System.currentTimeMillis(), timestamp);
                    if (frame != null) recordMonitorFrame(frame, reports, false);
                }
            });
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
        var settings = RadioStatus.read(iface);
        synchronized (this) {
            if (session != current) return;
            if (settings != null) current.health.updateRadio(settings);
            if (!current.health.hasFrames()) return;
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
                synchronized (this) { stats = current.health.diagnostics(line, System.currentTimeMillis()); }
                if (!stats) System.err.println(line);
            }
        } catch (IOException closed) {
            LOG.log(System.Logger.Level.DEBUG, "Monitor diagnostics stream closed", closed);
        }
    }

    private static long monotonicMillis() { return TimeUnit.NANOSECONDS.toMillis(System.nanoTime()); }

    private void readProbes(Session current) {
        try (var reader = new BufferedReader(new InputStreamReader(
                current.process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while (!Thread.currentThread().isInterrupted() && (line = reader.readLine()) != null) {
                ProbeRequest probe = parseProbeLine(line);
                if (probe == null) continue;
                synchronized (this) {
                    if (session != current) return;
                    recordProbe(probe);
                }
            }
            reportProbeFailure(current, "Probe capture ended; check the monitor interface and tcpdump permissions");
        } catch (IOException | RuntimeException failure) {
            reportProbeFailure(current, Objects.toString(failure.getMessage(), "Probe capture failed"));
        } finally {
            endSession(current);
        }
    }

    private void reportProbeFailure(Session current, String fallback) {
        // Never hold the bridge lock while waiting for the child to exit.
        try {
            current.process.waitFor(250, TimeUnit.MILLISECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
        String error = fallback;
        try {
            int exit = current.process.exitValue();
            if (exit != 0) error = "tcpdump exited with code " + exit + ": " + fallback;
        } catch (IllegalThreadStateException running) {
            // A read failure can occur while tcpdump is still running.
        }
        synchronized (this) {
            if (session != current) return;
            captureError = error;
            LOG.log(System.Logger.Level.WARNING, error);
        }
    }

    private void recordProbe(ProbeRequest probe) {
        profiler.observeProbe(probe.sourceMac(), probe.ssid());
        if (recentProbes.size() == RECENT_PROBE_LIMIT) recentProbes.removeFirst();
        recentProbes.addLast(probe);
        probeCount++;
        DeviceRecord previous = devices.get(probe.sourceMac());
        var ssids = profiler.get(probe.sourceMac()).probedSsids();
        var metadata = new HashMap<>(previous == null ? Map.<String, String>of() : previous.metadata());
        metadata.put("probeRequests", Long.toString(Long.parseLong(metadata.getOrDefault("probeRequests", "0")) + 1));
        metadata.put("macAddressType", probe.locallyAdministered() ? "locally administered" : "globally administered");
        double rssi = previous == null ? Double.NaN : previous.rssi();
        String vendor = probe.locallyAdministered() ? "Unknown"
                : vendors.getOrDefault(probe.sourceMac().substring(0, 8).replace(":", ""), "Unknown");
        DeviceRecord updated = new DeviceRecord(probe.sourceMac(), previous == null ? vendor : previous.vendor(),
                previous == null ? null : previous.hostname(),
                previous == null ? DeviceRecord.DeviceType.UNKNOWN : previous.type(), rssi,
                previous == null ? probe.timestamp() : Math.min(previous.firstSeen(), probe.timestamp()),
                previous == null ? probe.timestamp() : Math.max(previous.lastSeen(), probe.timestamp()), ssids, metadata);
        devices.put(probe.sourceMac(), updated);
        eventQueue.add(previous == null ? EwaveEvent.deviceAppeared(updated) : EwaveEvent.deviceUpdated(updated));
        eventQueue.add(EwaveEvent.probeRequest(probe));
    }

    private void onTimer(Session current, String iface) {
        try {
            synchronized (this) {
                if (session != current) return;
                long now = System.nanoTime();
                advanceTicks(current, now);
                if (tick == current.lastDecisionTick) return;
                // The packet reader can also close windows, so check the tick even
                // when advanceTicks did not close a window in this callback.
                current.lastDecisionTick = tick;
                var survey = current.survey;
                if (survey != null && current.retunePending) return;
                int chosen = survey == null ? 0 : survey.channel(now);
                if (chosen == 0) {
                    synchronized (current.scanner) {
                        chosen = current.scanner.choose(tick, 1).bands()[0] + 1;
                    }
                }
                current.lastChosen = chosen;
                Integer frequency = channelFrequencyMhz(chosen);
                if (frequency == null || survey != null && current.tunedChannel == chosen) return;
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
            if (session != current) return;
            if (current.health != null && current.tunedChannel == chosen) return;
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
            if (tuning != null && tuning.isAlive()) tuning.destroyForcibly();
            synchronized (this) {
                if (session == current) {
                    long completed = System.nanoTime();
                    current.dwellStarted = completed;
                    if (succeeded) {
                        current.successfulRetunes++;
                        current.retuneNanos += completed - started;
                        channel = chosen;
                        current.tunedChannel = chosen;
                        if (current.survey != null) {
                            long confirmedAt = System.currentTimeMillis();
                            current.lastTuneAtMs[chosen - 1] = confirmedAt;
                            if (apWatch != null) apWatch.tuneConfirmed(chosen, confirmedAt);
                        }
                    } else {
                        current.failedRetunes++;
                        current.tunedChannel = 0;
                    }
                    if (current.survey != null) current.survey.tuneFinished(completed, chosen, succeeded);
                }
                current.retunePending = false;
                current.tuning = false;
            }
        }
    }

    private void advanceTicks(Session current, long now) {
        while (now - current.nextBoundary >= 0) {
            synchronized (current.scanner) {
                for (int band = 1; band <= 13; band++) {
                    boolean detected = current.counts[band] > 0;
                    // A monitor radio cannot report quiet observations on channels it did not sample.
                    boolean valid = current.health == null || detected || !current.tuning && current.tunedChannel == band;
                    current.scanner.observe(band - 1, tick, detected, valid);
                }
            }
            Arrays.fill(current.counts, 0);
            publishPending(current);
            tick++;
            current.nextBoundary += tickNanos;
        }
    }

    /** Publishes collected packets, evicting the oldest when the bounded queue is full. Caller holds this. */
    private void publishPending(Session current) {
        if (current.pending.isEmpty()) return;
        for (PacketEvent packet : current.pending) {
            if (packetQueue.offer(packet)) continue;
            PacketEvent evicted = packetQueue.poll();
            if (evicted != null) recordDrop();
            if (!packetQueue.offer(packet)) recordDrop();
        }
        current.pending.clear();
    }

    private void recordDrop() {
        if (droppedPackets.incrementAndGet() == 1) {
            LOG.log(System.Logger.Level.WARNING,
                    "Packet retention queue reached capacity " + packetCapacity
                            + "; oldest packets are being discarded. The launcher does not drain this diagnostic queue.");
        }
    }

    private void updateDevice(String mac, PacketEvent packet, boolean transmitter) {
        // Broadcast/multicast addresses identify groups, not individual devices.
        if ((Integer.parseInt(mac.substring(0, 2), 16) & 1) != 0 || mac.equals("00:00:00:00:00:00")) return;
        DeviceRecord previous = devices.get(mac);
        double rssi = transmitter && !Double.isNaN(packet.rssi()) ? packet.rssi()
                : previous == null ? Double.NaN : previous.rssi();
        DeviceRecord updated = previous == null
                ? new DeviceRecord(mac, vendors.getOrDefault(mac.substring(0, 8).replace(":", ""), "Unknown"),
                        null, DeviceRecord.DeviceType.UNKNOWN, rssi, packet.timestamp(), packet.timestamp(), null, null)
                : new DeviceRecord(mac, previous.vendor(), previous.hostname(), previous.type(), rssi,
                        Math.min(previous.firstSeen(), packet.timestamp()), Math.max(previous.lastSeen(), packet.timestamp()),
                        previous.probedSsids(), previous.metadata());
        devices.put(mac, updated);
        eventQueue.add(previous == null ? EwaveEvent.deviceAppeared(updated) : EwaveEvent.deviceUpdated(updated));
    }

    private void endSession(Session current) {
        synchronized (this) {
            if (session != current) return; // A stopped reader cannot tear down a newer capture.
            session = null;
            if (apWatch != null) apWatch.stop(System.currentTimeMillis());
            publishPending(current);
        }
        terminate(current);
    }

    private static void terminate(Session current) {
        current.timer.shutdownNow();
        if (current.retuner != null) current.retuner.shutdownNow();
        if (current.reader != null && current.reader != Thread.currentThread()) current.reader.interrupt();
        current.process.destroy();
        boolean interrupted = false;
        try {
            if (!current.process.waitFor(500, TimeUnit.MILLISECONDS)) {
                current.process.destroyForcibly();
                if (!current.process.waitFor(500, TimeUnit.MILLISECONDS)) {
                    LOG.log(System.Logger.Level.WARNING, "tcpdump did not exit after forced termination");
                }
            }
        } catch (InterruptedException failure) {
            interrupted = true;
            current.process.destroyForcibly();
        }
        closeStream(current.process.getInputStream());
        closeStream(current.process.getOutputStream());
        closeStream(current.process.getErrorStream());
        if (current.reader != null && current.reader != Thread.currentThread()) {
            try {
                current.reader.join(1_000);
            } catch (InterruptedException failure) {
                interrupted = true;
            }
        }
        if (interrupted) Thread.currentThread().interrupt();
    }

    private static void closeStream(Closeable stream) {
        try {
            stream.close();
        } catch (IOException failure) {
            LOG.log(System.Logger.Level.DEBUG, "Failed to close tcpdump stream", failure);
        }
    }

    /** Parses named requests only; time-of-day text has no date, so use receipt time. */
    static ProbeRequest parseProbeLine(String line) {
        if (line == null) return null;
        Matcher ssidField = PROBE_SSID.matcher(line);
        Matcher probeName = PROBE_NAME.matcher(line);
        boolean hasSsid = ssidField.find(), hasName = probeName.find();
        if (!hasSsid && !hasName) return null;
        Matcher name = hasSsid && (!hasName || ssidField.start() < probeName.start()) ? ssidField : probeName;
        String ssid = name.group(1);
        if (ssid.isBlank()) return null;
        // A network name can itself contain address-like text; only inspect the header.
        String header = line.substring(0, name.start());
        String mac = matchAddress(SOURCE, header);
        if (mac == null) mac = matchAddress(TRANSMITTER, header);
        if (mac == null) mac = matchAddress(PROBE_SENDER, header);
        if (mac == null) return null;
        mac = mac.toLowerCase(Locale.ROOT);
        int prefix = Integer.parseInt(mac.substring(0, 2), 16);
        if ((prefix & 1) != 0 || mac.equals("00:00:00:00:00:00")) return null;
        // Exact SSID octets, destination/BSSID and frame length are unavailable in this text path.
        return new ProbeRequest(mac, null, null, ssid, "", false, (prefix & 2) != 0,
                0, 0, Double.NaN, System.currentTimeMillis(), 0, List.of(), List.of());
    }

    /** Returns null for non-packet output or incomplete/malformed summaries. */
    static PacketEvent parseLine(String line, int fallbackChannel) {
        Matcher timestamp = TIMESTAMP.matcher(line);
        Matcher length = LENGTH.matcher(line);
        if (!timestamp.find() || !length.find()) return null;
        Matcher ethernet = ETHERNET.matcher(line);
        String src;
        String dst;
        boolean wireless = !ethernet.find();
        if (!wireless) {
            src = ethernet.group(1);
            dst = ethernet.group(2);
        } else {
            src = matchAddress(SOURCE, line);
            dst = matchAddress(DESTINATION, line);
            if (src == null) src = matchAddress(TRANSMITTER, line);
            if (dst == null) dst = matchAddress(RECEIVER, line);
            if (src == null || dst == null) return null;
        }
        try {
            double seconds = Double.parseDouble(timestamp.group(1));
            double millis = seconds * 1_000;
            if (!Double.isFinite(millis) || millis >= Long.MAX_VALUE) return null;
            Matcher signal = SIGNAL.matcher(line);
            Matcher protocol = PROTOCOL.matcher(line);
            return new PacketEvent(src.toLowerCase(Locale.ROOT), dst.toLowerCase(Locale.ROOT),
                    parseChannel(line, fallbackChannel), signal.find() ? Double.parseDouble(signal.group(1)) : Double.NaN,
                    Integer.parseInt(length.group(1)), protocol.find() ? protocol.group(1) : wireless ? "802.11" : "Unknown",
                    (long) millis, line);
        } catch (NumberFormatException failure) {
            return null;
        }
    }

    private static String matchAddress(Pattern pattern, String line) {
        Matcher matcher = pattern.matcher(line);
        return matcher.find() ? matcher.group(1) : null;
    }

    private static int parseChannel(String line, int fallback) {
        Matcher frequency = FREQUENCY.matcher(line);
        if (frequency.find()) {
            int mhz = Integer.parseInt(frequency.group(1));
            if (mhz == 2484) return 14;
            if (mhz >= 2412 && mhz <= 2472 && (mhz - 2407) % 5 == 0) return (mhz - 2407) / 5;
            return 0; // An explicit non-2.4 GHz frequency must not use a stale fallback.
        }
        Matcher explicit = CHANNEL.matcher(line);
        if (explicit.find()) {
            int parsed = Integer.parseInt(explicit.group(1));
            return parsed >= 1 && parsed <= 14 ? parsed : 0;
        }
        return fallback;
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
        final PassiveChannelSurvey survey;
        final ThreadPoolExecutor retuner;
        final long[] counts = new long[14];
        final List<PacketEvent> pending = new ArrayList<>();
        long nextDeviceEvent, nextProbeEvent;
        long lastDecisionTick = tick;
        Integer lastChosen;
        int tunedChannel;
        boolean tuning, retunePending;
        long successfulRetunes, failedRetunes, retuneNanos, dwellStarted;
        final long[] dwellNanos = new long[13];
        final long[] lastTuneAtMs = new long[dwellNanos.length];
        final long[] lastFrameAtMs = new long[dwellNanos.length];
        final long[] lastFrameWhileTunedAtMs = new long[dwellNanos.length];

        void recordDwell(long now) {
            if (!tuning && tunedChannel != 0) dwellNanos[tunedChannel - 1] += now - dwellStarted;
            dwellStarted = now;
        }

        RadioTelemetry radioTelemetry() {
            long[] dwell = dwellNanos.clone();
            if (!tuning && tunedChannel != 0) dwell[tunedChannel - 1] += System.nanoTime() - dwellStarted;
            int observed = health == null ? 0 : health.observedChannel();
            return new RadioTelemetry(tunedChannel == 0 ? null : tunedChannel, observed == 0 ? null : observed,
                    tuning, successfulRetunes,
                    failedRetunes, successfulRetunes == 0 ? null : retuneNanos / (successfulRetunes * 1_000_000.0),
                    Arrays.stream(dwell).map(TimeUnit.NANOSECONDS::toMillis).boxed().toList(), channelCoverage());
        }

        private List<ChannelCoverage> channelCoverage() {
            if (survey == null) return List.of();
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

        Session(Process process, AdaptiveScanner scanner, CaptureHealth health, boolean watchAllowed) {
            this.process = process;
            this.scanner = scanner;
            this.health = health;
            this.watchAllowed = watchAllowed;
            survey = watchAllowed && scanner != null ? new PassiveChannelSurvey(System.nanoTime(), tickNanos) : null;
            // Serialize commands and keep only the latest pending choice if iw is slow.
            retuner = scanner == null ? null : new ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS,
                    new ArrayBlockingQueue<>(1),
                    task -> Thread.ofPlatform().daemon().name("ewave-radio-retune").unstarted(task),
                    new ThreadPoolExecutor.DiscardOldestPolicy());
        }
    }

    private static final class Replay {
        final String filename;
        final CaptureHealth health = new CaptureHealth();
        InputStream input;
        volatile long timestamp = -1;
        String state = "RUNNING";

        Replay(String filename) { this.filename = filename; }
        long now() { return Math.max(0, timestamp); }
        boolean running() { return state.equals("RUNNING"); }
    }
}
