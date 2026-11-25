package ewave.active;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/** Bounded hcxdumptool capture, hcxpcapngtool conversion, and aircrack-ng PMKID verification. */
public final class PmkidCapture {
    private static final Pattern INTERFACE = Pattern.compile("[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,14}");
    private static final int OUTPUT_LIMIT = 1_048_576;
    public static final String DEFAULT_CAPTURE_DIR = System.getProperty("java.io.tmpdir");

    @FunctionalInterface public interface ProcessStarter {
        Process start(ProcessBuilder builder) throws IOException;
    }

    public record Status(boolean running, String stage) {}
    public record Result(boolean captured, boolean vulnerable, String psk, String pcapngPath, String hashPath,
                         String command, String output, Instant timestamp, String targetApBssid, Integer frequencyMhz) {
        public Result(boolean captured, boolean vulnerable, String psk, String pcapngPath, String hashPath,
                      String command, String output, Instant timestamp) {
            this(captured, vulnerable, psk, pcapngPath, hashPath, command, output, timestamp, null, null);
        }
    }

    private final String monitorInterface;
    private final String targetApBssid;
    private final int frequencyMhz;
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
        this(monitorInterface, null, 0, DEFAULT_CAPTURE_DIR, ProcessBuilder::start);
    }

    public PmkidCapture(String monitorInterface, String captureDir) {
        this(monitorInterface, null, 0, captureDir, ProcessBuilder::start);
    }

    /** Process creation boundary for embedding and hardware-free tests. */
    public PmkidCapture(String monitorInterface, String captureDir, ProcessStarter starter) {
        this(monitorInterface, null, 0, captureDir, starter);
    }

    public PmkidCapture(String monitorInterface, String targetApBssid, int frequencyMhz) {
        this(monitorInterface, targetApBssid, frequencyMhz, DEFAULT_CAPTURE_DIR, ProcessBuilder::start);
    }

    /** Process creation boundary with optional target AP BSSID and frequency scoping. */
    public PmkidCapture(String monitorInterface, String targetApBssid, int frequencyMhz,
                        String captureDir, ProcessStarter starter) {
        if (monitorInterface == null || !INTERFACE.matcher(monitorInterface).matches())
            throw new IllegalArgumentException("interface must be a Linux interface name (1–15 letters, digits, _, . or -)");
        if (targetApBssid != null) {
            if (targetApBssid.isBlank()) throw new IllegalArgumentException("apBssid must not be blank");
            HandshakeAnalyzer.validateTarget(targetApBssid, null, 6);
        }
        if (frequencyMhz != 0) HandshakeAnalyzer.validateFrequency(frequencyMhz);
        this.monitorInterface = monitorInterface;
        this.targetApBssid = targetApBssid == null ? null : targetApBssid.strip();
        this.frequencyMhz = frequencyMhz;
        this.captureDir = Path.of(Objects.requireNonNull(captureDir)).toAbsolutePath().normalize();
        this.starter = Objects.requireNonNull(starter);
    }

    public Result run(String wordlistPath, int durationSeconds)
            throws IOException, InterruptedException, TimeoutException {
        Path wordlist = HandshakeAnalyzer.readableFile(wordlistPath, HandshakeAnalyzer.WORDLIST_MISSING);
        if (durationSeconds < 1 || durationSeconds > 300)
            throw new IllegalArgumentException("durationSeconds must be between 1 and 300");
        begin();
        Path pcapng = null, hash = null, runDirectory = null, bpfFile = null;
        String command = "";
        String targetHex = targetApBssid == null ? null : targetApBssid.replace(":", "").toLowerCase(Locale.ROOT);
        try {
            Path defaultBase = Path.of(DEFAULT_CAPTURE_DIR).toAbsolutePath().normalize();
            if (!captureDir.equals(defaultBase)) {
                if (Files.notExists(captureDir, LinkOption.NOFOLLOW_LINKS))
                    PrivateWorkspace.create(captureDir);
                else PrivateWorkspace.requireDirectory(captureDir);
            }
            runDirectory = PrivateWorkspace.create(captureDir.resolve("ewave-pmkid-" + UUID.randomUUID()));
            pcapng = runDirectory.resolve("pmkid.pcapng");
            hash = runDirectory.resolve("pmkid.22000");

            stage = "Capturing PMKIDs on " + monitorInterface + "…";
            List<String> captureCommand;
            if (targetHex == null && frequencyMhz == 0) {
                captureCommand = List.of("sudo", "hcxdumptool", "-i", monitorInterface, "-w", pcapng.toString(),
                        "--tot=" + Math.max(1, (durationSeconds + 59) / 60));
            } else {
                var scoped = new ArrayList<>(List.of("sudo", "hcxdumptool", "-i", monitorInterface,
                        "-w", pcapng.toString()));
                if (frequencyMhz > 0) scoped.addAll(List.of("-f", Integer.toString(frequencyMhz)));
                if (targetHex != null) {
                    bpfFile = compileBpfFilter(runDirectory, targetHex);
                    if (bpfFile != null) scoped.add("--bpf=" + bpfFile);
                }
                scoped.add("--tot=" + Math.max(1, (durationSeconds + 59) / 60));
                captureCommand = List.copyOf(scoped);
            }
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
            if (captured && capture.exitValue() != 0 && (!Files.exists(pcapng) || Files.size(pcapng) == 0)) {
                throw new IOException("PMKID capture failed (exit " + capture.exitValue() + "): " + outputText().strip());
            }
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
            if (convert.exitValue() != 0 && (!Files.exists(hash) || Files.size(hash) == 0)) {
                throw new IOException("PMKID conversion failed (exit " + convert.exitValue() + "): " + outputText().strip());
            }
            if (!Files.exists(hash) || Files.size(hash) == 0) {
                stage = "Capture complete";
                return result(false, false, null, pcapng, hash, command);
            }

            try (var hashes = PmkidHash.read(hash)) {
                var entries = hashes
                        .filter(entry -> targetHex == null || entry.apMac().equalsIgnoreCase(targetHex))
                        .iterator();
                if (!entries.hasNext()) {
                    append(targetApBssid != null
                            ? "\nNo PMKID hash found for target AP " + targetApBssid + ".\n"
                            : "\nNo PMKID hash found. hcxpcapngtool produced EAPOL-only or invalid hashes. "
                            + "Use the Handshake card for an EAPOL capture.\n");
                    stage = "Complete";
                    return result(false, false, null, pcapng, hash, "");
                }
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(300);
                while (entries.hasNext()) {
                    checkCancelled();
                    PmkidHash pmkid = entries.next();
                    stage = "Verifying PMKID for " + pmkid.apMac() + "…";
                    var verifyCommand = List.of("aircrack-ng", "-q", "-I", pmkid.aircrackString(),
                            "-e", pmkid.essid(), "-w", wordlist.toString());
                    command = String.join(" ", verifyCommand);
                    append("\nVerifying PMKID for " + pmkid.apMac() + "\n");
                    Process verify = launch(verifyCommand);
                    var verifyOutput = new HandshakeAnalyzer.Output(verify.getInputStream(), OUTPUT_LIMIT);
                    boolean recordedOutput = false;
                    try {
                        long remaining = deadline - System.nanoTime();
                        if (remaining <= 0 || !verify.waitFor(remaining, TimeUnit.NANOSECONDS)) {
                            stopProcess(verify);
                            throw new TimeoutException("PMKID verification timed out after 300 seconds");
                        }
                        verifyOutput.finish();
                        checkCancelled();
                        append(verifyOutput.text());
                        recordedOutput = true;
                        String key = verifyOutput.key();
                        if (key != null && verify.exitValue() == 0) {
                            stage = "Complete";
                            return result(true, true, key, pcapng, hash, command);
                        }
                        if (!verifyOutput.keyNotFound() || key != null)
                            throw new IOException("PMKID verification failed (exit " + verify.exitValue() + "): " + verifyOutput.text());
                    } finally {
                        forceStop(verify);
                        if (!recordedOutput) append(verifyOutput.text());
                        verifyOutput.close();
                        synchronized (this) { processes.remove(verify); }
                    }
                }
            }
            stage = "Complete";
            return result(true, false, null, pcapng, hash, command);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw interrupted;
        } finally {
            cleanup();
            if (bpfFile != null) {
                try { Files.deleteIfExists(bpfFile); }
                catch (IOException ignored) { /* Temporary filter file cleanup. */ }
            }
            deleteIfEmpty(pcapng);
            deleteIfEmpty(hash);
            if (runDirectory != null) {
                try { Files.delete(runDirectory); }
                catch (IOException ignored) { /* Retain directories containing captures for later verification. */ }
            }
        }
    }

    private static void deleteIfEmpty(Path file) {
        if (file == null) return;
        try {
            if (Files.exists(file, LinkOption.NOFOLLOW_LINKS) && Files.size(file) == 0) Files.deleteIfExists(file);
        } catch (IOException ignored) { /* Preserve any recording that could aid diagnosis. */ }
    }

    private Path compileBpfFilter(Path runDirectory, String targetHex) throws InterruptedException {
        Process bpfCompile;
        try {
            bpfCompile = launch(List.of("hcxdumptool", "--bpfc=wlan addr1 " + targetHex
                    + " or wlan addr2 " + targetHex + " or wlan addr3 " + targetHex));
        } catch (IOException unavailable) {
            checkCancelled();
            append("Target BPF filter compilation unavailable (" + unavailable.getMessage()
                    + "); post-capture BSSID filtering remains active.\n");
            return null;
        }
        var bpfOutput = new HandshakeAnalyzer.Output(bpfCompile.getInputStream(), 65_536);
        try {
            if (bpfCompile.waitFor(5, TimeUnit.SECONDS)) {
                bpfOutput.finish();
                checkCancelled();
                String compiled = bpfOutput.text().strip();
                if (bpfCompile.exitValue() == 0 && !compiled.isEmpty()) {
                    Path bpf = runDirectory.resolve("target.bpf");
                    Files.writeString(bpf, compiled + "\n", StandardCharsets.UTF_8);
                    try { Files.setPosixFilePermissions(bpf, PosixFilePermissions.fromString("rw-------")); }
                    catch (UnsupportedOperationException ignored) { /* Non-POSIX filesystem. */ }
                    return bpf;
                }
            }
            checkCancelled();
            append("Target BPF filter compilation unavailable; post-capture BSSID filtering remains active.\n");
            return null;
        } catch (IOException failure) {
            checkCancelled();
            append("Target BPF filter compilation unavailable; post-capture BSSID filtering remains active.\n");
            return null;
        } finally {
            forceStop(bpfCompile);
            bpfOutput.close();
            synchronized (this) { processes.remove(bpfCompile); }
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
            var builder = new ProcessBuilder(command).redirectErrorStream(true);
            builder.environment().put("TERM", "dumb");
            started = starter.start(builder);
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
                Instant.now(), targetApBssid, frequencyMhz > 0 ? frequencyMhz : null);
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
        static Stream<PmkidHash> read(Path hashFile) throws IOException {
            return Files.lines(hashFile, StandardCharsets.UTF_8).map(PmkidHash::parse).filter(Objects::nonNull);
        }

        private static PmkidHash parse(String line) {
            if (!line.startsWith("WPA*01*")) return null;
            var fields = line.split("\\*", -1);
            if (fields.length < 6 || !fields[2].matches("[0-9a-fA-F]{32}")
                    || !fields[3].matches("[0-9a-fA-F]{12}") || !fields[4].matches("[0-9a-fA-F]{12}")) return null;
            try {
                String essid = new String(HexFormat.of().parseHex(fields[5]), StandardCharsets.UTF_8);
                return new PmkidHash(fields[2], fields[3], fields[4], essid);
            } catch (IllegalArgumentException invalid) {
                return null;
            }
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
