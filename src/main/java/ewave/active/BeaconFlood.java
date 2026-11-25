package ewave.active;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

/** Continuous mdk4 beacon flooding with an mdk3 fallback for installations without mdk4. */
public final class BeaconFlood {
    private static final Pattern INTERFACE = Pattern.compile("[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,14}");
    private static final int OUTPUT_LIMIT = 1_048_576;
    private static final int MAX_SSIDS = 50;
    private static final Pattern MISSING_MDK4 = Pattern.compile("(?m)^sudo: mdk4: command not found\\s*$");

    @FunctionalInterface public interface ProcessStarter {
        Process start(ProcessBuilder builder) throws IOException;
    }

    public record Status(boolean running, String tool, String command, String output, String error,
                         int ssidCount, long elapsedSeconds) {
        public Status(boolean running, String tool, String command, String output, String error) {
            this(running, tool, command, output, error, 0, 0L);
        }
    }

    private final String monitorInterface;
    private final ProcessStarter starter;
    private final AtomicBoolean used = new AtomicBoolean();
    private final Set<Process> processes = new HashSet<>();
    private final StringBuilder output = new StringBuilder();
    private volatile Process process;
    private volatile Path ssidDir;
    private volatile Path ssidFile;
    private volatile boolean running;
    private volatile boolean terminated;
    private volatile String tool = "";
    private volatile String command = "";
    private volatile String error;
    private volatile int ssidCount;
    private volatile long startedAtNanos;
    private volatile long stoppedElapsedSeconds;
    private volatile IOException readFailure;
    private boolean truncated;

    public BeaconFlood(String monitorInterface) { this(monitorInterface, ProcessBuilder::start); }

    /** Process creation boundary for embedding and hardware-free tests. */
    public BeaconFlood(String monitorInterface, ProcessStarter starter) {
        if (monitorInterface == null || !INTERFACE.matcher(monitorInterface).matches())
            throw new IllegalArgumentException("interface must be a Linux interface name (1–15 letters, digits, _, . or -)");
        this.monitorInterface = monitorInterface;
        this.starter = Objects.requireNonNull(starter);
    }

    public Status start(String ssid, int channel, int rate) throws IOException {
        validate(ssid, channel, rate);
        return startInternal(List.of(ssid), channel, rate, false);
    }

    public Status start(List<String> ssids, int channel, int rate) throws IOException {
        if (ssids == null || ssids.isEmpty() || ssids.size() > MAX_SSIDS) {
            throw new IllegalArgumentException("ssids must contain between 1 and " + MAX_SSIDS + " entries");
        }
        for (String ssid : ssids) validate(ssid, channel, rate);
        if (ssids.size() == 1) return start(ssids.getFirst(), channel, rate);
        return startInternal(List.copyOf(ssids), channel, rate, true);
    }

    private Status startInternal(List<String> ssids, int channel, int rate, boolean multiSsid) throws IOException {
        if (!used.compareAndSet(false, true)) throw new IllegalStateException("This beacon flood has already been used");
        ssidCount = ssids.size();
        startedAtNanos = System.nanoTime();
        stoppedElapsedSeconds = 0L;
        try {
            return launchMdk4(ssids, channel, rate, multiSsid);
        } catch (IOException missing) {
            if (terminated) throw new CancellationException("Stopped by request");
            if (!missingProgram(missing, "mdk4")) {
                fail(missing);
                throw missing;
            }
            try {
                return launchMdk3(ssids, channel, rate);
            } catch (IOException fallbackFailure) {
                fail(fallbackFailure);
                throw fallbackFailure;
            }
        }
    }

    public Status status() {
        long elapsed = startedAtNanos == 0L ? 0L
                : running ? TimeUnit.NANOSECONDS.toSeconds(Math.max(0L, System.nanoTime() - startedAtNanos))
                : stoppedElapsedSeconds;
        return new Status(running, tool, command, outputText(), error, ssidCount, elapsed);
    }

    public synchronized void terminate() {
        terminated = true;
        for (Process current : processes) forceStop(current);
        processes.clear();
        latchElapsed();
        running = false;
        deleteSsidFile();
    }

    private Status launchMdk4(List<String> ssids, int channel, int rate, boolean multiSsid) throws IOException {
        tool = "mdk4";
        List<String> args;
        if (multiSsid) {
            Path file = ensureSsidFile(ssids);
            args = List.of("sudo", "mdk4", monitorInterface, "b", "-f", file.toString(),
                    "-c", Integer.toString(channel), "-s", Integer.toString(rate));
        } else {
            args = List.of("sudo", "mdk4", monitorInterface, "b", "-n", ssids.getFirst(),
                    "-c", Integer.toString(channel), "-s", Integer.toString(rate));
        }
        command = String.join(" ", args);
        return started(starter.start(builder(args)), ssids, channel, rate, true);
    }

    private Status launchMdk3(List<String> ssids, int channel, int rate) throws IOException {
        Path file = ensureSsidFile(ssids);
        tool = "mdk3";
        var args = List.of("sudo", "mdk3", monitorInterface, "b", "-f", file.toString(),
                "-c", Integer.toString(channel), "-s", Integer.toString(rate));
        command = String.join(" ", args);
        return started(starter.start(builder(args)), ssids, channel, rate, false);
    }

    private synchronized Path ensureSsidFile(List<String> ssids) throws IOException {
        if (terminated) throw new CancellationException("Stopped by request");
        if (ssidFile != null && Files.isRegularFile(ssidFile)) return ssidFile;
        Path dir = PrivateWorkspace.create(Path.of(System.getProperty("java.io.tmpdir"),
                "ewave-beacon-" + UUID.randomUUID()));
        Path file = Files.createFile(dir.resolve("ssids.txt"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        ssidDir = dir;
        ssidFile = file;
        String content = String.join(System.lineSeparator(), ssids) + System.lineSeparator();
        Files.writeString(file, content, StandardCharsets.UTF_8);
        return file;
    }

    private static ProcessBuilder builder(List<String> args) {
        var builder = new ProcessBuilder(args).redirectErrorStream(true);
        builder.environment().put("LC_ALL", "C");
        return builder;
    }

    private Status started(Process started, List<String> ssids, int channel, int rate, boolean allowFallback)
            throws IOException {
        if (started == null) throw new IOException("The beacon tool did not start");
        synchronized (this) {
            if (terminated) {
                forceStop(started);
                throw new CancellationException("Stopped by request");
            }
            process = started;
            processes.add(started);
            running = true;
            error = null;
        }
        started.getOutputStream().close();
        Thread.ofVirtual().name("ewave-beacon-watch").start(() -> watch(started, ssids, channel, rate, allowFallback));
        return status();
    }

    private void watch(Process source, List<String> ssids, int channel, int rate, boolean allowFallback) {
        // Read the complete diagnostic before deciding whether a failed sudo invocation needs mdk3.
        drain(source);
        try {
            source.waitFor();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
        synchronized (this) {
            processes.remove(source);
            if (process != source) return;
            boolean failed = !source.isAlive() && source.exitValue() != 0;
            boolean fallback = !terminated && failed && allowFallback && MISSING_MDK4.matcher(output).find();
            if (!fallback) {
                if (!terminated && failed && error == null) error = tool + " exited with code " + source.exitValue();
                process = null;
                latchElapsed();
                running = false;
                deleteSsidFile();
                return;
            }
            // Keep running true while the replacement starts so the server retains its operation slot and radio lease.
        }
        try {
            launchMdk3(ssids, channel, rate);
        } catch (CancellationException stopped) {
            // terminate() already cleared running and removed any temporary SSID file.
        } catch (IOException failure) {
            synchronized (this) {
                if (!terminated) fail(failure);
            }
        }
    }

    private void drain(Process source) {
        try (var input = new InputStreamReader(source.getInputStream(), StandardCharsets.UTF_8)) {
            char[] buffer = new char[4096];
            int size;
            while ((size = input.read(buffer)) != -1) append(new String(buffer, 0, size));
        } catch (IOException failure) {
            readFailure = failure;
        }
    }

    private void fail(IOException failure) {
        error = Objects.toString(failure.getMessage(), "Beacon flood failed");
        latchElapsed();
        running = false;
        append("\nCould not start beacon flood: " + error + "\n");
        deleteSsidFile();
    }

    private void latchElapsed() {
        if (startedAtNanos != 0L && running) {
            stoppedElapsedSeconds = TimeUnit.NANOSECONDS.toSeconds(Math.max(0L, System.nanoTime() - startedAtNanos));
        }
    }

    private synchronized void append(String value) {
        int remaining = Math.max(0, OUTPUT_LIMIT - output.length());
        if (remaining > 0) output.append(value, 0, Math.min(remaining, value.length()));
        if (value.length() > remaining && !truncated) {
            output.append("\n[Output truncated at 1 MiB]\n");
            truncated = true;
        }
    }

    private synchronized String outputText() {
        if (readFailure != null) return output + "\nCould not read process output: " + readFailure.getMessage() + "\n";
        return output.toString();
    }

    private synchronized void deleteSsidFile() {
        if (ssidFile != null) {
            try { Files.deleteIfExists(ssidFile); }
            catch (IOException ignored) { /* A stale temporary wordlist is harmless. */ }
            ssidFile = null;
        }
        if (ssidDir != null) {
            try { Files.deleteIfExists(ssidDir); }
            catch (IOException ignored) { /* Private directory cleanup is best-effort. */ }
            ssidDir = null;
        }
    }

    private static boolean missingProgram(IOException failure, String name) {
        String message = Objects.toString(failure.getMessage(), "").toLowerCase(Locale.ROOT);
        return message.contains("cannot run program \"" + name + "\"")
                && (message.contains("no such file") || message.contains("error=2"));
    }

    private static void validate(String ssid, int channel, int rate) {
        if (ssid == null || ssid.isBlank() || ssid.getBytes(StandardCharsets.UTF_8).length > 32
                || ssid.indexOf('\n') >= 0 || ssid.indexOf('\r') >= 0)
            throw new IllegalArgumentException("ssid must be 1–32 UTF-8 bytes on one line");
        if (channel < 1 || channel > 233) throw new IllegalArgumentException("channel must be an integer in 1–233");
        if (rate < 1 || rate > 10_000) throw new IllegalArgumentException("rate must be between 1 and 10000 packets per second");
    }

    private static void forceStop(Process process) {
        try { process.descendants().toList().reversed().forEach(ProcessHandle::destroyForcibly); }
        catch (UnsupportedOperationException ignored) { /* Embedded Process may lack handles. */ }
        if (process.isAlive()) process.destroyForcibly();
    }
}
