package ewave.active;

import ewave.model.AttackResult;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

/** Bounded channel tuning and aireplay-ng execution. Output is drained independently of waitFor. */
public final class FrameInjector {
    private static final Pattern MAC = Pattern.compile("(?i)(?:[0-9a-f]{2}:){5}[0-9a-f]{2}");
    private static final Pattern INTERFACE = Pattern.compile("[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,14}");
    private static final int OUTPUT_LIMIT = 1_048_576;
    @FunctionalInterface public interface ProcessStarter {
        Process start(ProcessBuilder builder) throws IOException;
    }
    public record Status(boolean running, String command, String output, AttackResult result) {}

    private final String monitorInterface;
    private final ProcessStarter starter;
    private final AtomicBoolean used = new AtomicBoolean();
    private final StringBuilder output = new StringBuilder();
    private volatile Process process;
    private volatile boolean terminated;
    private volatile boolean running;
    private volatile String command = "";
    private volatile AttackResult result;
    private volatile IOException readFailure;
    private boolean truncated;

    public FrameInjector(String monitorInterface) { this(monitorInterface, ProcessBuilder::start); }

    /** Process creation boundary for embedding and hardware-free tests. */
    public FrameInjector(String monitorInterface, ProcessStarter starter) {
        if (monitorInterface == null || !INTERFACE.matcher(monitorInterface).matches())
            throw new IllegalArgumentException("interface must be a Linux interface name (1–15 letters, digits, _, . or -)");
        this.monitorInterface = monitorInterface;
        this.starter = Objects.requireNonNull(starter);
    }

    public AttackResult sendDeauthFrames(String apBssid, String clientMac, int count) {
        return sendDeauthFrames(apBssid, clientMac, count, 0);
    }

    /** Tune to the cached AP frequency before injecting; zero preserves the embedding API's current channel. */
    public AttackResult sendDeauthFrames(String apBssid, String clientMac, int count, int frequencyMhz) {
        if (apBssid == null || !MAC.matcher(apBssid).matches())
            throw new IllegalArgumentException("apBssid must be a MAC address");
        if (clientMac != null && !MAC.matcher(clientMac).matches())
            throw new IllegalArgumentException("clientMac must be a MAC address or null for broadcast");
        if (count < 0) throw new IllegalArgumentException("count must be a nonnegative integer");
        if (frequencyMhz != 0 && (frequencyMhz < 2300 || frequencyMhz > 7125))
            throw new IllegalArgumentException("AP frequency must be in 2300–7125 MHz");
        if (!used.compareAndSet(false, true)) throw new IllegalStateException("This injector has already been used");
        var args = new ArrayList<>(List.of("sudo", "aireplay-ng", "--ignore-negative-one", "--deauth", Integer.toString(count), "-a", apBssid));
        if (clientMac != null) args.addAll(List.of("-c", clientMac));
        args.add(monitorInterface);
        command = String.join(" ", args);
        var tuneArgs = List.of("sudo", "iw", "dev", monitorInterface, "set", "freq", Integer.toString(frequencyMhz));
        if (frequencyMhz != 0) command = String.join(" ", tuneArgs) + "\n" + command;
        long started = System.nanoTime();
        boolean success = false;
        Thread reader = null;
        running = true;
        try {
            if (frequencyMhz != 0) {
                synchronized (this) {
                    if (!terminated) process = starter.start(new ProcessBuilder(tuneArgs).redirectErrorStream(true));
                }
                if (process != null) {
                    reader = startReader();
                    process.getOutputStream().close();
                    if (!process.waitFor(5, TimeUnit.SECONDS)) throw new IOException("Channel tuning timed out; injection skipped");
                    reader.join(1_000);
                    if (terminated || reader.isAlive() || readFailure != null || process.exitValue() != 0)
                        throw new IOException("Channel tuning failed; injection skipped");
                    process = null;
                    reader = null;
                    append("Tuned " + monitorInterface + " to " + frequencyMhz + " MHz.\n");
                }
            }
            synchronized (this) {
                if (!terminated) process = starter.start(new ProcessBuilder(args).redirectErrorStream(true));
            }
            if (process != null) {
                reader = startReader();
                process.getOutputStream().close();
                boolean finished = process.waitFor(30, TimeUnit.SECONDS);
                if (!finished) {
                    killProcess();
                    append(count == 0 ? "\n30-second test window completed.\n" : "\nTimed out after 30 seconds.\n");
                }
                reader.join(1_000);
                success = !terminated && readFailure == null && (finished ? process.exitValue() == 0 : count == 0);
            }
        } catch (IOException failure) {
            append("\nCould not run injection: " + failure.getMessage() + "\n");
        } catch (InterruptedException interrupted) {
            append("\nInjection interrupted.\n");
            Thread.currentThread().interrupt();
        } finally {
            killProcess();
            if (terminated) append("\nStopped by request.\n");
            if (reader != null && reader.isAlive()) {
                success = false;
                append("\nProcess output did not close after termination.\n");
                try { process.getInputStream().close(); } catch (IOException ignored) { }
                reader.interrupt();
            }
            if (readFailure != null) append("\nCould not read process output: " + readFailure.getMessage() + "\n");
            synchronized (this) {
                result = new AttackResult(success && !terminated && readFailure == null, "deauth", command, outputText(),
                        TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started), Instant.now());
                running = false;
            }
        }
        return result;
    }

    private Thread startReader() {
        Process source = process;
        return Thread.ofVirtual().name("ewave-injection-output").start(() -> readOutput(source));
    }

    private void readOutput(Process source) {
        try (var input = new InputStreamReader(source.getInputStream(), StandardCharsets.UTF_8)) {
            char[] buffer = new char[4096];
            int size;
            while ((size = input.read(buffer)) != -1) append(new String(buffer, 0, size));
        } catch (IOException failure) { readFailure = failure; }
    }

    private synchronized void append(String value) {
        if (result != null) return;
        int remaining = Math.max(0, OUTPUT_LIMIT - output.length());
        if (remaining > 0) output.append(value, 0, Math.min(remaining, value.length()));
        if (value.length() > remaining && !truncated) {
            output.append("\n[Output truncated at 1 MiB]\n");
            truncated = true;
        }
    }

    private synchronized String outputText() { return output.toString(); }

    public synchronized Status status() { return new Status(running, command, outputText(), result); }

    /** Also cancels a run reserved by the server before process creation. */
    public synchronized void terminate() {
        terminated = true;
        killProcess();
    }

    private void killProcess() {
        Process current = process;
        if (current == null) return;
        try { current.descendants().toList().reversed().forEach(ProcessHandle::destroyForcibly); }
        catch (UnsupportedOperationException ignored) { /* Embedded Process may lack handles. */ }
        if (current.isAlive()) current.destroyForcibly();
    }
}
