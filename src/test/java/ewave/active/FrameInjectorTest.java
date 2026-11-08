package ewave.active;

import ewave.fixtures.StreamingCaptureProcess;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(8)
class FrameInjectorTest {
    private static final String AP = "02:11:22:33:44:55", CLIENT = "02:11:22:33:44:66";

    @Test void tunesToTheSelectedFrequencyBeforeInjecting() {
        for (int frequency : new int[]{2417, 5745, 5975}) {
            var commands = new ArrayList<List<String>>();
            var injector = new FrameInjector("wlo1", builder -> {
                commands.add(List.copyOf(builder.command()));
                return new FiniteProcess(builder.command().get(1).equals("iw") ? "" : "frames\n", 0, false);
            });
            var result = injector.sendDeauthFrames(AP, CLIENT, 10, frequency);
            assertTrue(result.success());
            assertEquals(List.of("sudo", "iw", "dev", "wlo1", "set", "freq", Integer.toString(frequency)), commands.get(0));
            assertEquals("aireplay-ng", commands.get(1).get(1));
            assertEquals(2, commands.size());
            assertTrue(result.command().startsWith(String.join(" ", commands.get(0)) + "\n"));
        }
    }

    @Test void tuningFailureOrTimeoutNeverLaunchesInjection() {
        for (boolean timeout : new boolean[]{false, true}) {
            var commands = new ArrayList<List<String>>();
            var process = new FiniteProcess("Operation not permitted\n", 1, timeout);
            var injector = new FrameInjector("wlo1", builder -> { commands.add(builder.command()); return process; });
            var result = injector.sendDeauthFrames(AP, CLIENT, 10, 2417);
            assertFalse(result.success());
            assertEquals(1, commands.size());
            assertEquals("iw", commands.getFirst().get(1));
            assertEquals(5, process.requestedTimeout);
            assertTrue(result.output().contains("injection skipped"));
            if (timeout) assertTrue(process.killed);
        }
    }

    @Test void stopDuringTuningDoesNotLaunchInjection() throws Exception {
        var process = new StreamingCaptureProcess();
        var started = new CountDownLatch(1);
        var commands = new ArrayList<List<String>>();
        var injector = new FrameInjector("wlo1", builder -> {
            commands.add(builder.command()); started.countDown(); return process;
        });
        var task = CompletableFuture.supplyAsync(() -> injector.sendDeauthFrames(AP, CLIENT, 10, 2417));
        assertTrue(started.await(2, TimeUnit.SECONDS));
        injector.terminate();
        assertFalse(task.get(3, TimeUnit.SECONDS).success());
        assertEquals(1, commands.size());
        assertFalse(process.isAlive());
    }

    @Test void buildsDirectedAndBroadcastCommandsAndCapturesOutputAndExitStatus() {
        for (String client : new String[]{CLIENT, null}) {
            var command = new AtomicReference<ProcessBuilder>();
            var injector = new FrameInjector("wlo1", builder -> {
                command.set(builder);
                return new FiniteProcess("sent frames\n", client == null ? 1 : 0, false);
            });
            var result = injector.sendDeauthFrames(AP, client, 10);
            assertEquals(client != null, result.success());
            assertEquals("deauth", result.attackType());
            assertEquals("sent frames\n", result.output());
            assertTrue(result.durationMs() >= 0);
            assertNotNull(result.timestamp());
            assertTrue(command.get().redirectErrorStream());
            assertEquals(client == null
                    ? List.of("sudo", "aireplay-ng", "--ignore-negative-one", "--deauth", "10", "-a", AP, "wlo1")
                    : List.of("sudo", "aireplay-ng", "--ignore-negative-one", "--deauth", "10", "-a", AP, "-c", CLIENT, "wlo1"), command.get().command());
            assertEquals(String.join(" ", command.get().command()), result.command());
            assertEquals(result, injector.status().result());
            assertFalse(injector.status().running());
        }
    }

    @Test void timeoutKillsProcessAndZeroCountCompletesItsScheduledWindow() {
        for (int count : new int[]{0, 10}) {
            var process = new FiniteProcess("frames\n", 0, true);
            var result = new FrameInjector("wlo1", builder -> process).sendDeauthFrames(AP, null, count);
            assertEquals(30, process.requestedTimeout);
            assertEquals(count == 0, result.success());
            assertTrue(process.killed);
            assertTrue(result.output().contains(count == 0 ? "test window completed" : "Timed out"));
        }
    }

    @Test void drainsLargeOutputWhileWaitingAndBoundsRetainedText() throws Exception {
        var process = new StreamingCaptureProcess();
        var injector = new FrameInjector("wlo1", builder -> process);
        var task = CompletableFuture.supplyAsync(() -> injector.sendDeauthFrames(AP, CLIENT, 10));
        process.write("x".repeat(2_000_000).getBytes(StandardCharsets.UTF_8));
        process.finish();
        var result = task.get(3, TimeUnit.SECONDS);
        assertTrue(result.success());
        assertTrue(result.output().endsWith("[Output truncated at 1 MiB]\n"));
        assertTrue(result.output().length() < 1_049_000);
    }

    @Test void stopIsResponsiveAndCanCancelBeforeProcessCreation() throws Exception {
        var process = new StreamingCaptureProcess();
        var started = new CountDownLatch(1);
        var injector = new FrameInjector("wlo1", builder -> { started.countDown(); return process; });
        var task = CompletableFuture.supplyAsync(() -> injector.sendDeauthFrames(AP, CLIENT, 0));
        assertTrue(started.await(2, TimeUnit.SECONDS));
        process.write("live output\n".getBytes(StandardCharsets.UTF_8));
        injector.terminate();
        var result = task.get(3, TimeUnit.SECONDS);
        assertFalse(result.success());
        assertFalse(process.isAlive());
        assertTrue(result.output().contains("Stopped by request"));
        assertTrue(result.output().contains("live output"));
        var cancelled = new FrameInjector("wlo1", builder -> { fail("must not launch"); return process; });
        cancelled.terminate();
        assertFalse(cancelled.sendDeauthFrames(AP, null, 10).success());
    }

    @Test void handlesLaunchFailureAndRejectsInvalidArgumentsWithoutLaunching() {
        var missing = new FrameInjector("wlo1", builder -> { throw new IOException("missing executable"); });
        var result = missing.sendDeauthFrames(AP, null, 10);
        assertFalse(result.success());
        assertTrue(result.output().contains("missing executable"));
        var injector = new FrameInjector("wlo1", builder -> { fail("must not launch"); return null; });
        assertThrows(IllegalArgumentException.class, () -> injector.sendDeauthFrames("-a", null, 1));
        assertThrows(IllegalArgumentException.class, () -> injector.sendDeauthFrames(AP, "bad", 1));
        assertThrows(IllegalArgumentException.class, () -> injector.sendDeauthFrames(AP, null, -1));
        for (String name : new String[]{"--help", "wlan0;id", "a b", "", "1234567890123456"})
            assertThrows(IllegalArgumentException.class, () -> new FrameInjector(name), name);
    }

    @Test void interruptedWaitKillsTheProcessAndPreservesInterruptFlag() {
        var process = new FiniteProcess("", 0, false) {
            @Override public boolean waitFor(long timeout, TimeUnit unit) throws InterruptedException {
                throw new InterruptedException("test");
            }
            @Override public boolean isAlive() { return !killed; }
        };
        try {
            var result = new FrameInjector("wlo1", builder -> process).sendDeauthFrames(AP, null, 10);
            assertFalse(result.success());
            assertTrue(process.killed);
            assertTrue(Thread.currentThread().isInterrupted());
        } finally { Thread.interrupted(); }
    }

    @Test void readFailureMakesAnOtherwiseSuccessfulProcessFail() {
        var process = new FiniteProcess("", 0, false) {
            @Override public InputStream getInputStream() {
                return new InputStream() {
                    @Override public int read() throws IOException { throw new IOException("simulated read failure"); }
                };
            }
        };
        var result = new FrameInjector("wlo1", builder -> process).sendDeauthFrames(AP, null, 10);
        assertFalse(result.success());
        assertTrue(result.output().contains("simulated read failure"));
    }

    private static class FiniteProcess extends Process {
        private final InputStream output;
        private final int exitCode;
        private final boolean timesOut;
        volatile boolean killed;
        long requestedTimeout;
        FiniteProcess(String output, int exitCode, boolean timesOut) {
            this.output = new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8));
            this.exitCode = exitCode; this.timesOut = timesOut;
        }
        @Override public InputStream getInputStream() { return output; }
        @Override public InputStream getErrorStream() { return InputStream.nullInputStream(); }
        @Override public OutputStream getOutputStream() { return OutputStream.nullOutputStream(); }
        @Override public int waitFor() { return exitCode; }
        @Override public boolean waitFor(long timeout, TimeUnit unit) throws InterruptedException {
            requestedTimeout = unit.toSeconds(timeout); return !timesOut;
        }
        @Override public int exitValue() { return exitCode; }
        @Override public boolean isAlive() { return timesOut && !killed; }
        @Override public void destroy() { killed = true; }
        @Override public Process destroyForcibly() { destroy(); return this; }
    }
}
