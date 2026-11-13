package ewave.active;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

/** Continuous mdk4 beacon flooding with an mdk3 fallback for installations without mdk4. */
public final class BeaconFlood {
    private static final Pattern INTERFACE = Pattern.compile("[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,14}");
    private static final int OUTPUT_LIMIT = 1_048_576;

    @FunctionalInterface public interface ProcessStarter {
        Process start(ProcessBuilder builder) throws IOException;
    }

    public record Status(boolean running, String tool, String command, String output, String error) {}

    private final String monitorInterface;
    private final ProcessStarter starter;
    private final AtomicBoolean used = new AtomicBoolean();
    private final Set<Process> processes = new HashSet<>();
    private final StringBuilder output = new StringBuilder();
    private volatile Process process;
    private volatile Path ssidFile;
    private volatile boolean running;
    private volatile boolean terminated;
    private volatile String tool = "";
    private volatile String command = "";
    private volatile String error;
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
        if (!used.compareAndSet(false, true)) throw new IllegalStateException("This beacon flood has already been used");
        try {
            return launchMdk4(ssid, channel, rate);
        } catch (IOException missing) {
            if (terminated) throw new CancellationException("Stopped by request");
            if (!missingProgram(missing, "mdk4")) {
                fail(missing);
                throw missing;
            }
            try {
                return launchMdk3(ssid, channel, rate);
            } catch (IOException fallbackFailure) {
                fail(fallbackFailure);
                throw fallbackFailure;
            }
        }
    }

    public Status status() {
        return new Status(running, tool, command, outputText(), error);
    }

    public synchronized void terminate() {
        terminated = true;
        for (Process current : processes) forceStop(current);
        processes.clear();
        running = false;
        deleteSsidFile();
    }

    private Status launchMdk4(String ssid, int channel, int rate) throws IOException {
        tool = "mdk4";
        var args = List.of("sudo", "mdk4", monitorInterface, "b", "-n", ssid,
                "-c", Integer.toString(channel), "-s", Integer.toString(rate));
        command = String.join(" ", args);
        return started(starter.start(new ProcessBuilder(args).redirectErrorStream(true)));
    }

    private Status launchMdk3(String ssid, int channel, int rate) throws IOException {
        Path file = Files.createTempFile("ewave-beacon-", ".txt");
        Files.writeString(file, ssid + System.lineSeparator(), StandardCharsets.UTF_8);
        ssidFile = file;
        tool = "mdk3";
        var args = List.of("sudo", "mdk3", monitorInterface, "b", "-f", file.toString(),
                "-c", Integer.toString(channel), "-s", Integer.toString(rate));
        command = String.join(" ", args);
        return started(starter.start(new ProcessBuilder(args).redirectErrorStream(true)));
    }

    private Status started(Process started) throws IOException {
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
        Thread.ofVirtual().name("ewave-beacon-output").start(() -> drain(started));
        Thread.ofVirtual().name("ewave-beacon-watch").start(() -> watch(started));
        return status();
    }

    private void watch(Process source) {
        try {
            source.waitFor();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        } finally {
            synchronized (this) {
                if (process == source) {
                    process = null;
                    running = false;
                    processes.remove(source);
                }
                deleteSsidFile();
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
        running = false;
        append("\nCould not start beacon flood: " + error + "\n");
        deleteSsidFile();
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
        if (ssidFile == null) return;
        try { Files.deleteIfExists(ssidFile); }
        catch (IOException ignored) { /* A stale temporary wordlist is harmless. */ }
        ssidFile = null;
    }

    private static boolean missingProgram(IOException failure, String name) {
        String message = Objects.toString(failure.getMessage(), "").toLowerCase(Locale.ROOT);
        return message.contains("no such file") || message.contains("error=2")
                || message.contains("cannot run program \"" + name + "\"");
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
