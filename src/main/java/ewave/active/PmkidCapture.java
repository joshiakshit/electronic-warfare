package ewave.active;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

/** Bounded hcxdumptool capture, hcxpcapngtool conversion, and aircrack-ng PMKID verification. */
public final class PmkidCapture {
    private static final Pattern INTERFACE = Pattern.compile("[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,14}");
    private static final Pattern ANSI = Pattern.compile("\u001B\\[[0-?]*[ -/]*[@-~]");
    private static final Pattern KEY = Pattern.compile("KEY FOUND!\\s*\\[ (.*) \\]");
    private static final int OUTPUT_LIMIT = 1_048_576;
    public static final String DEFAULT_CAPTURE_DIR = "/tmp/ewave-captures/";

    @FunctionalInterface public interface ProcessStarter {
        Process start(ProcessBuilder builder) throws IOException;
    }

    public record Status(boolean running, String stage) {}
    public record Result(boolean captured, boolean vulnerable, String psk, String pcapngPath, String hashPath,
                         String command, String output, Instant timestamp) {}

    private final String monitorInterface;
    private final Path captureDir;
    private final ProcessStarter starter;
    private final AtomicBoolean inUse = new AtomicBoolean();
    private final Set<Process> processes = new HashSet<>();
    private final StringBuilder output = new StringBuilder();
    private volatile Process process;
    private volatile boolean running;
    private volatile boolean cancelled;
    private volatile String stage = "Ready";
    private volatile IOException readFailure;
    private boolean truncated;

    public PmkidCapture(String monitorInterface) {
        this(monitorInterface, DEFAULT_CAPTURE_DIR, ProcessBuilder::start);
    }

    public PmkidCapture(String monitorInterface, String captureDir) {
        this(monitorInterface, captureDir, ProcessBuilder::start);
    }

    /** Process creation boundary for embedding and hardware-free tests. */
    public PmkidCapture(String monitorInterface, String captureDir, ProcessStarter starter) {
        if (monitorInterface == null || !INTERFACE.matcher(monitorInterface).matches())
            throw new IllegalArgumentException("interface must be a Linux interface name (1–15 letters, digits, _, . or -)");
        this.monitorInterface = monitorInterface;
        this.captureDir = Path.of(Objects.requireNonNull(captureDir)).toAbsolutePath().normalize();
        this.starter = Objects.requireNonNull(starter);
    }

    public Result run(String wordlistPath, int durationSeconds)
            throws IOException, InterruptedException, TimeoutException {
        Path wordlist = HandshakeAnalyzer.readableFile(wordlistPath, HandshakeAnalyzer.WORDLIST_MISSING);
        if (durationSeconds < 1 || durationSeconds > 300)
            throw new IllegalArgumentException("durationSeconds must be between 1 and 300");
        begin();
        Path pcapng = null, hash = null;
        String command = "";
        try {
            Files.createDirectories(captureDir);
            pcapng = Files.createTempFile(captureDir, "pmkid-", ".pcapng");
            Files.deleteIfExists(pcapng);
            hash = captureDir.resolve(pcapng.getFileName().toString().replaceFirst("\\.pcapng$", "") + ".22000");
            Files.deleteIfExists(hash);

            stage = "Capturing PMKIDs on " + monitorInterface + "…";
            var captureCommand = List.of("sudo", "hcxdumptool", "-i", monitorInterface, "-w", pcapng.toString(),
                    "--tot=" + Math.max(1, (durationSeconds + 59) / 60));
            command = String.join(" ", captureCommand);
            Process capture = launch(captureCommand);
            Thread captureReader = drain(capture);
            boolean captured = capture.waitFor(durationSeconds, TimeUnit.SECONDS);
            if (!captured) {
                append("\nCapture window ended.\n");
                stopProcess(capture);
            }
            captureReader.join(1_000);
            checkCancelled();
            if (!Files.exists(pcapng) || Files.size(pcapng) == 0) {
                stage = "Capture complete";
                return result(false, false, null, pcapng, hash, command);
            }

            stage = "Converting capture…";
            var convertCommand = List.of("hcxpcapngtool", "-o", hash.toString(), pcapng.toString());
            command = String.join(" ", convertCommand);
            Process convert = launch(convertCommand);
            Thread convertReader = drain(convert);
            if (!convert.waitFor(60, TimeUnit.SECONDS)) {
                stopProcess(convert);
                convertReader.join(1_000);
                throw new TimeoutException("PMKID capture conversion timed out");
            }
            convertReader.join(1_000);
            checkCancelled();
            if (!Files.exists(hash) || Files.size(hash) == 0) {
                stage = "Capture complete";
                return result(false, false, null, pcapng, hash, command);
            }

            PmkidHash pmkid = PmkidHash.read(hash);
            if (pmkid == null) {
                append("\nNo PMKID hash found. hcxpcapngtool produced EAPOL-only hashes that aircrack-ng "
                        + "cannot verify directly. Use the Handshake card for an EAPOL capture.\n");
                stage = "Complete";
                return result(false, false, null, pcapng, hash, "");
            }
            stage = "Verifying PMKID hash…";
            var verifyCommand = List.of("aircrack-ng", "-I", pmkid.aircrackString(),
                    "-e", pmkid.essid(), "-w", wordlist.toString());
            command = String.join(" ", verifyCommand);
            Process verify = launch(verifyCommand);
            Thread verifyReader = drain(verify);
            if (!verify.waitFor(300, TimeUnit.SECONDS)) {
                stopProcess(verify);
                verifyReader.join(1_000);
                throw new TimeoutException("PMKID verification timed out after 300 seconds");
            }
            verifyReader.join(1_000);
            checkCancelled();
            String plain = ANSI.matcher(outputText()).replaceAll("");
            var key = KEY.matcher(plain);
            if (key.find() && verify.exitValue() == 0) {
                stage = "Complete";
                return result(true, true, key.group(1), pcapng, hash, command);
            }
            if (!plain.contains("KEY NOT FOUND") || plain.contains("KEY FOUND!"))
                throw new IOException("PMKID verification failed (exit " + verify.exitValue() + "): " + outputText());
            stage = "Complete";
            return result(true, false, null, pcapng, hash, command);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw interrupted;
        } finally {
            cleanup();
        }
    }

    public Status status() { return new Status(running, stage); }

    /** Also cancels a run reserved by the server before process creation. */
    public synchronized void terminate() {
        cancelled = true;
        for (Process current : processes) forceStop(current);
        stage = "Stopped";
    }

    private void begin() {
        checkCancelled();
        if (!inUse.compareAndSet(false, true)) throw new IllegalStateException("A PMKID capture is already running");
        running = true;
        stage = "Ready";
    }

    private void checkCancelled() {
        if (cancelled) throw new CancellationException("Stopped by request");
    }

    private Process launch(List<String> command) throws IOException {
        checkCancelled();
        Process started;
        synchronized (this) {
            if (cancelled) throw new CancellationException("Stopped by request");
            started = starter.start(new ProcessBuilder(command).redirectErrorStream(true));
            process = started;
            processes.add(started);
        }
        started.getOutputStream().close();
        return started;
    }

    private Thread drain(Process source) {
        return Thread.ofVirtual().name("ewave-pmkid-output").start(() -> {
            try (var input = new InputStreamReader(source.getInputStream(), StandardCharsets.UTF_8)) {
                char[] buffer = new char[4096];
                int size;
                while ((size = input.read(buffer)) != -1) append(new String(buffer, 0, size));
            } catch (IOException failure) {
                readFailure = failure;
            }
        });
    }

    private Result result(boolean captured, boolean vulnerable, String psk, Path pcapng, Path hash, String command) {
        if (readFailure != null) append("\nCould not read process output: " + readFailure.getMessage() + "\n");
        return new Result(captured, vulnerable, psk, pcapng.toString(), hash.toString(), command, outputText(),
                Instant.now());
    }

    private synchronized void append(String value) {
        int remaining = Math.max(0, OUTPUT_LIMIT - output.length());
        if (remaining > 0) output.append(value, 0, Math.min(remaining, value.length()));
        if (value.length() > remaining && !truncated) {
            output.append("\n[Output truncated at 1 MiB]\n");
            truncated = true;
        }
    }

    private synchronized String outputText() { return output.toString(); }

    private void cleanup() {
        synchronized (this) {
            for (Process current : processes) forceStop(current);
            processes.clear();
            process = null;
        }
        running = false;
        inUse.set(false);
    }

    private static void forceStop(Process process) {
        try { process.descendants().toList().reversed().forEach(ProcessHandle::destroyForcibly); }
        catch (UnsupportedOperationException ignored) { /* Embedded Process may lack handles. */ }
        if (process.isAlive()) process.destroyForcibly();
    }

    private record PmkidHash(String pmkid, String apMac, String stationMac, String essid) {
        static PmkidHash read(Path hashFile) throws IOException {
            for (String line : Files.readAllLines(hashFile, StandardCharsets.UTF_8)) {
                if (!line.startsWith("WPA*01*")) continue;
                var fields = line.split("\\*", -1);
                if (fields.length < 6) continue;
                String essid;
                try { essid = new String(HexFormat.of().parseHex(fields[5]), StandardCharsets.UTF_8); }
                catch (IllegalArgumentException invalid) { essid = fields[5]; }
                return new PmkidHash(fields[2], fields[3], fields[4], essid);
            }
            return null;
        }

        String aircrackString() { return pmkid + "*" + apMac + "*" + stationMac + "*" + essid; }
    }

    private static void stopProcess(Process process) throws InterruptedException {
        try { process.descendants().toList().reversed().forEach(ProcessHandle::destroy); }
        catch (UnsupportedOperationException ignored) { /* Embedded Process may lack handles. */ }
        if (process.isAlive()) process.destroy();
        if (!process.waitFor(500, TimeUnit.MILLISECONDS)) process.destroyForcibly();
    }
}
