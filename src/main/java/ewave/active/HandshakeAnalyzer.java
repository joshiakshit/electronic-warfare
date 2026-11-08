package ewave.active;

import ewave.capture.MonitorPcapReader;
import ewave.model.HandshakeResult;
import ewave.model.HandshakeResult.Outcome;
import ewave.model.PskVerificationResult;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

/** Passive lab capture and dictionary verification, one operation at a time. */
public final class HandshakeAnalyzer {
    private static final Pattern MAC = Pattern.compile("(?i)(?:[0-9a-f]{2}:){5}[0-9a-f]{2}");
    private static final Pattern INTERFACE = Pattern.compile("[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,14}");
    private static final Pattern ANSI = Pattern.compile("\u001B\\[[0-?]*[ -/]*[@-~]");
    private static final Pattern KEY = Pattern.compile("KEY FOUND!\\s*\\[ (.*) \\]");
    private static final int CAPTURE_OUTPUT_LIMIT = 1_048_576;
    public static final String DEFAULT_CAPTURE_DIR = "/tmp/ewave-captures/";
    public static final String WORDLIST_MISSING = "Wordlist not found. Install: sudo dnf install wordlists";

    @FunctionalInterface public interface ProcessStarter {
        Process start(ProcessBuilder builder) throws IOException;
    }
    public record Status(boolean running, String stage) {}
    record Timing(Duration beacon, Duration observe, Duration poll, Duration verify) {
        static final Timing DEFAULT = new Timing(Duration.ofSeconds(8), Duration.ofSeconds(90),
                Duration.ofMillis(100), Duration.ofMinutes(5));
    }

    private final String monitorInterface;
    private final String apBssid;
    private final String clientMac;
    private final int channel;
    private final int frequency;
    private final Path captureDir;
    private final ProcessStarter starter;
    private final Timing timing;
    private final AtomicBoolean inUse = new AtomicBoolean();
    private final Set<Process> processes = new HashSet<>();
    private volatile boolean cancelled;
    private volatile boolean running;
    private volatile String stage = "Ready";

    public HandshakeAnalyzer() { this("wlo1", null, null, 6); }

    public HandshakeAnalyzer(String monitorInterface, String apBssid, String clientMac, int channel) {
        this(monitorInterface, apBssid, clientMac, channel, frequencyMhz(channel));
    }

    /** Retained for callers that previously supplied a display name. The BSSID identifies the radio. */
    public HandshakeAnalyzer(String monitorInterface, String apBssid, String clientMac, int channel, String ssid) {
        this(monitorInterface, apBssid, clientMac, channel);
    }

    public HandshakeAnalyzer(String monitorInterface, String apBssid, String clientMac, int channel, int frequency) {
        this(monitorInterface, apBssid, clientMac, channel, frequency, DEFAULT_CAPTURE_DIR, ProcessBuilder::start);
    }

    public HandshakeAnalyzer(String monitorInterface, String apBssid, String clientMac, int channel,
                             String captureDir, ProcessStarter starter) {
        this(monitorInterface, apBssid, clientMac, channel, frequencyMhz(channel), captureDir, starter);
    }

    public HandshakeAnalyzer(String monitorInterface, String apBssid, String clientMac, int channel,
                             String captureDir, ProcessStarter starter, String ssid) {
        this(monitorInterface, apBssid, clientMac, channel, captureDir, starter);
    }

    /** Process creation boundary for embedding and hardware-free tests. */
    public HandshakeAnalyzer(String monitorInterface, String apBssid, String clientMac, int channel,
                             int frequency, String captureDir, ProcessStarter starter) {
        this(monitorInterface, apBssid, clientMac, channel, frequency, captureDir, starter, Timing.DEFAULT);
    }

    HandshakeAnalyzer(String monitorInterface, String apBssid, String clientMac, int channel,
                      int frequency, String captureDir, ProcessStarter starter, Timing timing) {
        if (monitorInterface == null || !INTERFACE.matcher(monitorInterface).matches())
            throw new IllegalArgumentException("interface must be a Linux interface name (1–15 letters, digits, _, . or -)");
        validateFrequency(frequency);
        this.monitorInterface = monitorInterface;
        this.apBssid = apBssid;
        this.clientMac = clientMac;
        this.channel = normalizeChannel(channel);
        this.frequency = frequency;
        this.captureDir = Path.of(Objects.requireNonNull(captureDir)).toAbsolutePath().normalize();
        this.starter = Objects.requireNonNull(starter);
        this.timing = Objects.requireNonNull(timing);
    }

    public HandshakeResult capture() throws IOException, InterruptedException {
        validateTarget(apBssid, clientMac, channel);
        begin();
        Output tuning = null, recorderErrors = null, decoderErrors = null;
        Path cap = null;
        try {
            stage = "Tuning to " + frequency + " MHz…";
            var iw = List.of("sudo", "iw", "dev", monitorInterface, "set", "freq", Integer.toString(frequency));
            System.out.println("[HandshakeAnalyzer] iw cmd: " + iw);
            Process tune = launch(iw);
            tuning = new Output(tune.getInputStream(), CAPTURE_OUTPUT_LIMIT);
            if (!tune.waitFor(5, TimeUnit.SECONDS)) throw new IOException("Frequency tuning timed out");
            tuning.finish();
            checkCancelled();
            if (tune.exitValue() != 0) throw new IOException("Frequency tuning failed: " + tuning.text());

            Files.createDirectories(captureDir);
            cap = Files.createTempFile(captureDir, "hs-" + apBssid.replace(":", "") + "-", ".cap");
            var decode = new ArrayList<>(List.of("tshark", "-n", "-l", "-r", "-", "-F", "pcap", "-w", cap.toString(),
                    "-P", "-T", "fields", "-E", "occurrence=f", "-o", "wlan.enable_decryption:FALSE"));
            for (String field : HandshakePackets.FIELDS) decode.addAll(List.of("-e", field));
            Process decoder = launch(new ProcessBuilder(decode), false);
            decoderErrors = new Output(decoder.getErrorStream(), CAPTURE_OUTPUT_LIMIT);
            var packets = new HandshakePackets(apBssid, clientMac, frequency, channel);
            var rows = background(() -> {
                try (var input = new BufferedReader(new InputStreamReader(decoder.getInputStream(), StandardCharsets.UTF_8))) {
                    for (String row; (row = input.readLine()) != null;) packets.accept(row);
                }
                return null;
            });

            stage = "Waiting for target AP beacon on " + frequency + " MHz…";
            Process recorder = launch(new ProcessBuilder("sudo", "tcpdump", "-i", monitorInterface, "-s", "0", "-U", "-w", "-"), true);
            recorderErrors = new Output(recorder.getErrorStream(), CAPTURE_OUTPUT_LIMIT);
            var stopping = new AtomicBoolean();
            var relay = background(() -> {
                try (var input = recorder.getInputStream(); var output = decoder.getOutputStream()) {
                    MonitorPcapReader.relay(input, output, stopping::get);
                }
                return null;
            });
            long started = System.nanoTime();
            long deadline = started + timing.observe().toNanos();
            long beaconDeadline = started + timing.beacon().toNanos();
            boolean ready = false;
            while (recorder.isAlive() && decoder.isAlive() && !relay.isDone() && !rows.isDone()) {
                checkCancelled();
                if (packets.observation().complete() || System.nanoTime() >= deadline) break;
                if (!ready && packets.beaconSeen()) {
                    ready = true;
                    stage = "Ready — reconnect your device now";
                }
                if (!ready && System.nanoTime() >= beaconDeadline) break;
                TimeUnit.NANOSECONDS.sleep(timing.poll().toNanos());
            }
            checkCancelled();
            boolean earlyExit = !recorder.isAlive() || !decoder.isAlive() || relay.isDone() || rows.isDone();
            stage = "Finishing capture…";
            stopping.set(true);
            stop(recorder);
            // Let tcpdump's final bytes reach TShark and close its input before inspecting the file.
            String relayError = finishTask(relay);
            boolean decoderFinished = decoder.waitFor(3, TimeUnit.SECONDS);
            if (!decoderFinished) stop(decoder);
            String decodeError = finishTask(rows);
            checkCancelled();

            String diagnostics = recorderErrors.diagnostics() + decoderErrors.diagnostics();
            boolean pipelineFailed = !decoderFinished || decoder.exitValue() != 0 || !relayError.isEmpty() || !decodeError.isEmpty();
            diagnostics += relayError + decodeError;
            if (!decoderFinished) diagnostics += "Packet decoder did not finish writing the capture.\n";
            if (Files.size(cap) < 24) throw new IOException("No readable 802.11 capture was written.\n" + diagnostics);
            var observed = packets.observation();
            Outcome outcome;
            if (pipelineFailed) outcome = Outcome.CAPTURE_ENDED;
            else if (observed.complete()) outcome = Outcome.COMPLETE;
            else if (!observed.messages().isEmpty()) outcome = Outcome.PARTIAL;
            else if (earlyExit) outcome = Outcome.CAPTURE_ENDED;
            else if (!packets.beaconSeen()) outcome = Outcome.TARGET_NOT_SEEN;
            else outcome = Outcome.NO_EAPOL;
            stage = "Capture complete";
            return new HandshakeResult(outcome == Outcome.COMPLETE, cap.toString(), apBssid,
                    observed.clientMac(), diagnostics, Instant.now(), frequency, outcome, observed.messages());
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw interrupted;
        } finally {
            cleanup(tuning, recorderErrors, decoderErrors);
            if (cap != null) {
                try { if (Files.size(cap) < 24) Files.deleteIfExists(cap); }
                catch (IOException ignored) { /* Preserve any recording that could aid diagnosis. */ }
            }
        }
    }

    private static FutureTask<Void> background(Callable<Void> action) {
        var task = new FutureTask<>(action);
        Thread.startVirtualThread(task);
        return task;
    }

    private static String finishTask(FutureTask<Void> task) throws InterruptedException {
        try {
            task.get(2, TimeUnit.SECONDS);
            return "";
        } catch (TimeoutException timeout) {
            task.cancel(true);
            return "Timed out draining the packet stream.\n";
        } catch (ExecutionException failure) {
            return "Packet stream ended: " + failure.getCause().getMessage() + "\n";
        }
    }

    public PskVerificationResult verifyPsk(String capFilePath, String wordlistPath)
            throws IOException, InterruptedException, TimeoutException {
        Path cap = readableFile(capFilePath, "Capture file not found or unreadable");
        Path wordlist = readableFile(wordlistPath, WORDLIST_MISSING);
        begin();
        Output output = null;
        try {
            stage = "Verifying PSK strength...";
            Process process = launch(List.of("aircrack-ng", cap.toString(), "-w", wordlist.toString()));
            output = new Output(process.getInputStream(), Integer.MAX_VALUE);
            if (!process.waitFor(timing.verify().toMillis(), TimeUnit.MILLISECONDS))
                throw new TimeoutException("PSK verification timed out after " + timing.verify().toSeconds() + " seconds");
            output.finish();
            checkCancelled();
            String fullOutput = output.text();
            String plain = ANSI.matcher(fullOutput).replaceAll("");
            var key = KEY.matcher(plain);
            if (key.find() && process.exitValue() == 0)
                return new PskVerificationResult(true, key.group(1), fullOutput, Instant.now());
            // aircrack-ng also exits nonzero after successfully exhausting a dictionary.
            if (!plain.contains("KEY NOT FOUND") || plain.contains("KEY FOUND!"))
                throw new IOException("PSK verification failed (exit " + process.exitValue() + "): " + fullOutput);
            return new PskVerificationResult(false, null, fullOutput, Instant.now());
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw interrupted;
        } finally {
            cleanup(output);
        }
    }

    public static void validateTarget(String apBssid, String clientMac, int channel) {
        if (!isStationAddress(apBssid)) throw new IllegalArgumentException("apBssid must be a unicast MAC address");
        if (clientMac != null && (!isStationAddress(clientMac) || clientMac.equalsIgnoreCase(apBssid)))
            throw new IllegalArgumentException("clientMac must be a different unicast MAC address or null for any client");
        if (normalizeChannel(channel) > 233) throw new IllegalArgumentException("channel must be an integer in 1–233");
    }

    static boolean isStationAddress(String mac) {
        return mac != null && MAC.matcher(mac).matches() && (Character.digit(mac.charAt(1), 16) & 1) == 0
                && !mac.equals("00:00:00:00:00:00");
    }

    public static void validateFrequency(int frequency) {
        if (frequency < 2300 || frequency > 7125)
            throw new IllegalArgumentException("frequencyMhz must be between 2300 and 7125");
    }

    public static int normalizeChannel(int channel) { return channel <= 0 ? 6 : channel; }

    /** Legacy channel-only requests use 2.4/5 GHz numbering. Prefer the measured frequency. */
    public static int frequencyMhz(int channel) {
        channel = normalizeChannel(channel);
        if (channel > 233) throw new IllegalArgumentException("channel must be an integer in 1–233");
        if (channel == 14) return 2484;
        return channel <= 13 ? 2407 + channel * 5 : 5000 + channel * 5;
    }

    public static Path readableFile(String value, String message) throws IOException {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("A nonempty file path is required");
        Path path = Path.of(value).toAbsolutePath().normalize();
        if (!Files.isRegularFile(path) || !Files.isReadable(path)) throw new IOException(message);
        return path;
    }

    public Status status() { return new Status(running, stage); }

    public synchronized void terminate() {
        cancelled = true;
        for (Process process : processes) forceStop(process);
    }

    private void begin() {
        checkCancelled();
        if (!inUse.compareAndSet(false, true)) throw new IllegalStateException("This analyzer is already running");
        running = true;
    }

    private void checkCancelled() {
        if (cancelled) throw new CancellationException("Stopped by request");
    }

    private Process launch(List<String> command) throws IOException {
        return launch(new ProcessBuilder(command).redirectErrorStream(true), true);
    }

    private synchronized Process launch(ProcessBuilder builder, boolean closeInput) throws IOException {
        checkCancelled();
        builder.environment().put("TERM", "xterm");
        Process process = starter.start(builder);
        processes.add(process);
        if (closeInput) process.getOutputStream().close();
        return process;
    }

    private static List<ProcessHandle> descendants(Process process) {
        try { return process.descendants().toList().reversed(); }
        catch (UnsupportedOperationException ignored) { return List.of(); }
    }

    private static void forceStop(Process process) {
        descendants(process).forEach(ProcessHandle::destroyForcibly);
        if (process.isAlive()) process.destroyForcibly();
    }

    private static void stop(Process process) throws InterruptedException {
        var children = descendants(process);
        children.forEach(ProcessHandle::destroy);
        if (process.isAlive()) {
            // Signal the recorder without closing its stdout before the relay has drained it.
            try { process.toHandle().destroy(); }
            catch (UnsupportedOperationException ignored) { process.destroy(); }
        }
        if (!process.waitFor(500, TimeUnit.MILLISECONDS)) process.destroyForcibly();
        children.stream().filter(ProcessHandle::isAlive).forEach(ProcessHandle::destroyForcibly);
        process.waitFor(500, TimeUnit.MILLISECONDS);
    }

    private void cleanup(Output... outputs) {
        synchronized (this) {
            for (Process process : processes) forceStop(process);
            processes.clear();
        }
        for (Output output : outputs) if (output != null) output.close();
        running = false;
        inUse.set(false);
    }

    private static final class Output {
        private final InputStream stream;
        private final int limit;
        private final StringBuilder buffer = new StringBuilder();
        private final Thread reader;
        private volatile IOException failure;
        private boolean truncated;

        Output(InputStream stream, int limit) {
            this.stream = stream;
            this.limit = limit;
            reader = Thread.ofVirtual().name("ewave-handshake-output").start(() -> {
                try (var input = new InputStreamReader(stream, StandardCharsets.UTF_8)) {
                    char[] chunk = new char[4096];
                    for (int size; (size = input.read(chunk)) != -1;) append(chunk, size);
                } catch (IOException error) {
                    failure = error;
                }
            });
        }

        private synchronized void append(char[] value, int size) {
            int remaining = Math.max(0, limit - buffer.length());
            buffer.append(value, 0, Math.min(remaining, size));
            if (size > remaining && !truncated) {
                buffer.append("\n[Output truncated at 1 MiB]\n");
                truncated = true;
            }
        }

        synchronized String text() { return buffer.toString(); }

        void finish() throws InterruptedException, IOException {
            reader.join(1_000);
            if (reader.isAlive()) throw new IOException("Process output did not close after termination");
            if (failure != null) throw failure;
        }

        String diagnostics() throws InterruptedException {
            try { finish(); }
            catch (IOException error) { return text() + "\n" + error.getMessage() + "\n"; }
            return text();
        }

        void close() {
            try { stream.close(); } catch (IOException ignored) { }
            reader.interrupt();
        }
    }
}
