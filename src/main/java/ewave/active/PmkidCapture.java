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

    public record ExtractedPmkid(String pmkid, String apBssid, String stationMac, String essid) {}

    public record Status(boolean running, String stage, String phase, Integer remainingSeconds,
                         int pmkidCount, int eapolPairCount, int verifiedCount, String output) {
        public Status(boolean running, String stage) {
            this(running, stage, running ? "RUNNING" : "IDLE", null, 0, 0, 0, "");
        }
    }

    public record Result(boolean captured, boolean vulnerable, String psk, String pcapngPath, String hashPath,
                         String command, String output, Instant timestamp, String targetApBssid, Integer frequencyMhz,
                         List<ExtractedPmkid> pmkids, int eapolPairCount, boolean verificationSkipped) {
        public Result {
            pmkids = pmkids == null ? List.of() : List.copyOf(pmkids);
        }

        public Result(boolean captured, boolean vulnerable, String psk, String pcapngPath, String hashPath,
                      String command, String output, Instant timestamp) {
            this(captured, vulnerable, psk, pcapngPath, hashPath, command, output, timestamp,
                    null, null, List.of(), 0, false);
        }

        public Result(boolean captured, boolean vulnerable, String psk, String pcapngPath, String hashPath,
                      String command, String output, Instant timestamp, String targetApBssid, Integer frequencyMhz) {
            this(captured, vulnerable, psk, pcapngPath, hashPath, command, output, timestamp,
                    targetApBssid, frequencyMhz, List.of(), 0, false);
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
    private volatile boolean finishCaptureRequested;
    private volatile String stage = "Ready";
    private volatile String phase = "IDLE";
    private volatile Integer remainingSeconds;
    private volatile int pmkidCount;
    private volatile int eapolPairCount;
    private volatile int verifiedCount;
    private volatile Path retainedHashFile;
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
        return run(wordlistPath, durationSeconds, false);
    }

    public Result run(String wordlistPath, int durationSeconds, boolean captureOnly)
            throws IOException, InterruptedException, TimeoutException {
        Path wordlist = captureOnly ? null
                : HandshakeAnalyzer.readableFile(wordlistPath, HandshakeAnalyzer.WORDLIST_MISSING);
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

            phase = "CAPTURING";
            stage = "Capturing PMKIDs on " + monitorInterface + "…";
            remainingSeconds = durationSeconds;
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
            long captureDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(durationSeconds);
            boolean captured = false;
            while (true) {
                checkCancelled();
                if (finishCaptureRequested) break;
                long now = System.nanoTime();
                long remainingNanos = captureDeadline - now;
                if (remainingNanos <= 0) break;
                remainingSeconds = Math.max(0, (int) Math.ceil(remainingNanos / 1_000_000_000.0));
                long stepMs = Math.min(200L, Math.max(1L, TimeUnit.NANOSECONDS.toMillis(remainingNanos)));
                long stepStart = System.nanoTime();
                if (capture.waitFor(stepMs, TimeUnit.MILLISECONDS)) {
                    captured = true;
                    break;
                }
                if (!finishCaptureRequested && System.nanoTime() - stepStart < TimeUnit.MILLISECONDS.toNanos(10)) {
                    TimeUnit.MILLISECONDS.sleep(20);
                }
            }
            remainingSeconds = null;
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
                phase = "COMPLETE";
                return result(false, false, null, pcapng, hash, command, List.of(), 0, captureOnly);
            }

            phase = "CONVERTING";
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
                phase = "COMPLETE";
                return result(false, false, null, pcapng, hash, command, List.of(), 0, captureOnly);
            }
            restrictToOwner(pcapng);
            restrictToOwner(hash);

            return processHashes(hash, pcapng, wordlist, targetHex, captureOnly, command);
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

    public Result verifyCapturedHashes(Path hashFile, String wordlistPath)
            throws IOException, InterruptedException, TimeoutException {
        Path wordlist = HandshakeAnalyzer.readableFile(wordlistPath, HandshakeAnalyzer.WORDLIST_MISSING);
        PrivateWorkspace.requireFile(hashFile);
        Path normalizedHash = hashFile.toAbsolutePath().normalize();
        String targetHex = targetApBssid == null ? null : targetApBssid.replace(":", "").toLowerCase(Locale.ROOT);
        begin();
        try {
            Path siblingPcapng = normalizedHash.resolveSibling("pmkid.pcapng");
            Path pcapng = Files.isRegularFile(siblingPcapng, LinkOption.NOFOLLOW_LINKS) ? siblingPcapng : Path.of("");
            return processHashes(normalizedHash, pcapng, wordlist, targetHex, false, "");
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw interrupted;
        } finally {
            cleanup();
        }
    }

    private Result processHashes(Path hash, Path pcapng, Path wordlist, String targetHex, boolean captureOnly,
                                 String initialCommand) throws IOException, InterruptedException, TimeoutException {
        var parsed = readHashSummary(hash, targetHex);
        var entries = parsed.entries();
        var extracted = parsed.extracted();
        int eapolPairs = parsed.eapolPairs();
        pmkidCount = extracted.size();
        eapolPairCount = eapolPairs;
        if (entries.isEmpty()) {
            append(targetApBssid != null
                    ? "\nNo PMKID hash found for target AP " + targetApBssid + ".\n"
                    : "\nNo PMKID hash found. hcxpcapngtool produced EAPOL-only or invalid hashes. "
                    + "Use the Handshake card for an EAPOL capture.\n");
            stage = "Complete";
            phase = "COMPLETE";
            return result(false, false, null, pcapng, hash, "", List.of(), eapolPairs, captureOnly);
        }
        retainedHashFile = hash.toAbsolutePath().normalize();
        if (captureOnly) {
            stage = "Complete";
            phase = "COMPLETE";
            return result(true, false, null, pcapng, hash, initialCommand, extracted, eapolPairs, true);
        }
        phase = "VERIFYING";
        verifiedCount = 0;
        String command = initialCommand;
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(300);
        for (PmkidHash pmkid : entries) {
            checkCancelled();
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
                remainingSeconds = Math.max(0, (int) Math.ceil(remaining / 1_000_000_000.0));
                if (remaining <= 0 || !verify.waitFor(remaining, TimeUnit.NANOSECONDS)) {
                    stopProcess(verify);
                    throw new TimeoutException("PMKID verification timed out after 300 seconds");
                }
                verifyOutput.finish();
                checkCancelled();
                append(verifyOutput.text());
                recordedOutput = true;
                verifiedCount++;
                String key = verifyOutput.key();
                if (key != null && verify.exitValue() == 0) {
                    stage = "Complete";
                    phase = "COMPLETE";
                    return result(true, true, key, pcapng, hash, command, extracted, eapolPairs, false);
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
        stage = "Complete";
        phase = "COMPLETE";
        return result(true, false, null, pcapng, hash, command, extracted, eapolPairs, false);
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

    public Status status() {
        return new Status(running, stage, phase, remainingSeconds, pmkidCount, eapolPairCount,
                verifiedCount, outputText());
    }

    public Path capturedHashFile() { return retainedHashFile; }

    public boolean finishCaptureEarly() {
        if (!running || cancelled || !"CAPTURING".equals(phase)) return false;
        finishCaptureRequested = true;
        return true;
    }

    /** Also cancels a run reserved by the server before process creation. */
    public synchronized void terminate() {
        cancelled = true;
        for (Process current : processes) forceStop(current);
        stage = "Stopped";
        phase = "STOPPED";
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

    private Result result(boolean captured, boolean vulnerable, String psk, Path pcapng, Path hash, String command,
                          List<ExtractedPmkid> pmkids, int eapolPairs, boolean verificationSkipped) {
        if (readFailure != null) append("\nCould not read process output: " + readFailure.getMessage() + "\n");
        String pcapPath = pcapng == null || pcapng.toString().isEmpty() ? "" : pcapng.toString();
        return new Result(captured, vulnerable, psk, pcapPath, hash.toString(), command, outputText(),
                Instant.now(), targetApBssid, frequencyMhz > 0 ? frequencyMhz : null,
                pmkids, eapolPairs, verificationSkipped);
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
        remainingSeconds = null;
        running = false;
        if (cancelled) phase = "STOPPED";
        else if (!"COMPLETE".equals(phase)) phase = "STOPPED";
        inUse.set(false);
    }

    private record HashSummary(List<PmkidHash> entries, List<ExtractedPmkid> extracted, int eapolPairs) { }

    private static HashSummary readHashSummary(Path hashFile, String targetHex) throws IOException {
        var entries = new ArrayList<PmkidHash>();
        var extracted = new ArrayList<ExtractedPmkid>();
        int eapolPairs = 0;
        try (Stream<String> lines = Files.lines(hashFile, StandardCharsets.UTF_8)) {
            for (String line : (Iterable<String>) lines::iterator) {
                if (line.startsWith("WPA*02*")) {
                    var fields = line.split("\\*", -1);
                    if (fields.length >= 6 && (targetHex == null || targetHex.equalsIgnoreCase(fields[3]))) {
                        eapolPairs++;
                    }
                    continue;
                }
                PmkidHash parsed = PmkidHash.parse(line);
                if (parsed == null) continue;
                if (targetHex == null || parsed.apMac().equalsIgnoreCase(targetHex)) {
                    entries.add(parsed);
                    extracted.add(new ExtractedPmkid(parsed.pmkid(), formatMac(parsed.apMac()),
                            formatMac(parsed.stationMac()), parsed.essid()));
                }
            }
        }
        return new HashSummary(List.copyOf(entries), List.copyOf(extracted), eapolPairs);
    }

    private static String formatMac(String hex12) {
        if (hex12 == null || hex12.length() != 12) return hex12;
        var out = new StringBuilder(17);
        for (int i = 0; i < 12; i += 2) {
            if (i > 0) out.append(':');
            out.append(Character.toLowerCase(hex12.charAt(i))).append(Character.toLowerCase(hex12.charAt(i + 1)));
        }
        return out.toString();
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

    private static void restrictToOwner(Path path) throws IOException {
        if (path == null || !Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return;
        try {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException ignored) {
            /* Non-POSIX filesystems lack POSIX permissions. */
        }
    }

    private static void stopProcess(Process process) throws InterruptedException {
        try { process.descendants().toList().reversed().forEach(ProcessHandle::destroy); }
        catch (UnsupportedOperationException ignored) { /* Embedded Process may lack handles. */ }
        if (process.isAlive()) process.destroy();
        if (!process.waitFor(500, TimeUnit.MILLISECONDS)) process.destroyForcibly();
    }
}
