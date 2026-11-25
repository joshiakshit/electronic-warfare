package ewave.active;

import ewave.fixtures.StreamingCaptureProcess;
import ewave.fixtures.CompletedProcess;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.CountDownLatch;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(15)
class BeaconFloodTest {
    @Test void startsMdk4AndStopsTheProcess() throws Exception {
        var process = new StreamingCaptureProcess();
        var commands = new CopyOnWriteArrayList<List<String>>();
        var flood = new BeaconFlood("wlo1", builder -> {
            commands.add(List.copyOf(builder.command()));
            return process;
        });
        var status = flood.start("ewave-lab", 6, 120);
        assertTrue(status.running());
        assertEquals("mdk4", status.tool());
        assertEquals(List.of("sudo", "mdk4", "wlo1", "b", "-n", "ewave-lab", "-c", "6", "-s", "120"), commands.getFirst());
        flood.terminate();
        assertFalse(flood.status().running());
        assertFalse(process.isAlive());
    }

    @Test void fallsBackToMdk3WithATemporarySsidFile() throws Exception {
        var process = new StreamingCaptureProcess();
        var commands = new CopyOnWriteArrayList<List<String>>();
        var flood = new BeaconFlood("wlo1", builder -> {
            var command = List.copyOf(builder.command());
            commands.add(command);
            if (command.get(1).equals("mdk4"))
                throw new IOException("Cannot run program \"mdk4\": error=2, No such file or directory");
            return process;
        });
        var status = flood.start("ewave-lab", 11, 50);
        assertTrue(status.running());
        assertEquals("mdk3", status.tool());
        var command = commands.get(1);
        assertEquals("sudo", command.getFirst());
        assertEquals("mdk3", command.get(1));
        assertEquals("b", command.get(3));
        Path ssid = Path.of(command.get(command.indexOf("-f") + 1));
        assertTrue(Files.isRegularFile(ssid));
        assertEquals("ewave-lab" + System.lineSeparator(), Files.readString(ssid));
        flood.terminate();
        assertFalse(Files.exists(ssid));
    }

    @Test void fallsBackWhenSudoReportsMdk4MissingAfterSuccessfulProcessCreation() throws Exception {
        var fallback = new StreamingCaptureProcess();
        var commands = new CopyOnWriteArrayList<List<String>>();
        var flood = new BeaconFlood("wlo1", builder -> {
            var command = List.copyOf(builder.command());
            commands.add(command);
            if (command.get(1).equals("mdk4"))
                return new CompletedProcess("sudo: mdk4: command not found\n", 1);
            Path ssidFile = Path.of(command.get(command.indexOf("-f") + 1));
            assertEquals("ewave-lab" + System.lineSeparator(), Files.readString(ssidFile));
            return fallback;
        });
        try {
            flood.start("ewave-lab", 11, 50);
            await(() -> commands.size() == 2 && flood.status().tool().equals("mdk3"));
            assertTrue(flood.status().running());
            assertNull(flood.status().error());
            assertTrue(flood.status().output().contains("sudo: mdk4: command not found"));
            var command = commands.get(1);
            assertEquals(List.of("sudo", "mdk3", "wlo1", "b", "-f"), command.subList(0, 5));
            assertEquals(List.of("-c", "11", "-s", "50"), command.subList(6, 10));
            assertEquals(String.join(" ", command), flood.status().command());
        } finally {
            flood.terminate();
        }
        assertFalse(fallback.isAlive());
        assertFalse(Files.exists(Path.of(commands.get(1).get(5))));
    }

    @ParameterizedTest
    @ValueSource(strings = {"sudo: a password is required\n", "sudo: user is not in the sudoers file\n",
            "mdk4: failed to open interface wlo1\n", "mdk4: invalid option -- n\n"})
    void doesNotFallBackForPermissionInterfaceOrArgumentFailures(String diagnostic) throws Exception {
        var commands = new CopyOnWriteArrayList<List<String>>();
        var flood = new BeaconFlood("wlo1", builder -> {
            commands.add(List.copyOf(builder.command()));
            return new CompletedProcess(diagnostic, 1);
        });
        try {
            flood.start("lab", 6, 100);
            await(() -> !flood.status().running());
            assertEquals(1, commands.size());
            assertEquals("mdk4", flood.status().tool());
            assertEquals("mdk4 exited with code 1", flood.status().error());
            assertTrue(flood.status().output().contains(diagnostic));
        } finally {
            flood.terminate();
        }
    }

    @Test void keepsRunningDuringFallbackAndStopsAProcessCreatedAfterCancellation() throws Exception {
        var creatingFallback = new CountDownLatch(1);
        var proceed = new CountDownLatch(1);
        var fallback = new StreamingCaptureProcess();
        var files = new CopyOnWriteArrayList<Path>();
        var flood = new BeaconFlood("wlo1", builder -> {
            if (builder.command().get(1).equals("mdk4"))
                return new CompletedProcess("sudo: mdk4: command not found\n", 1);
            files.add(Path.of(builder.command().get(5)));
            creatingFallback.countDown();
            try {
                if (!proceed.await(3, TimeUnit.SECONDS)) throw new IOException("Timed out waiting for cancellation");
            } catch (InterruptedException stopped) {
                throw new IOException(stopped);
            }
            return fallback;
        });
        try {
            flood.start("lab", 6, 100);
            assertTrue(creatingFallback.await(3, TimeUnit.SECONDS));
            assertTrue(flood.status().running(), "The operation slot must remain held while fallback starts");
            assertTrue(Files.exists(files.getFirst()));
            flood.terminate();
            assertFalse(flood.status().running());
            assertFalse(Files.exists(files.getFirst()));
        } finally {
            flood.terminate();
            proceed.countDown();
        }
        await(() -> !fallback.isAlive());
        assertFalse(flood.status().running());
    }

    @Test void reportsFallbackFailureAndDeletesTheSsidFile() throws Exception {
        var files = new CopyOnWriteArrayList<Path>();
        var flood = new BeaconFlood("wlo1", builder -> {
            if (builder.command().get(1).equals("mdk4"))
                return new CompletedProcess("sudo: mdk4: command not found\n", 1);
            files.add(Path.of(builder.command().get(5)));
            throw new IOException("mdk3 launch failed");
        });
        try {
            flood.start("lab", 6, 100);
            await(() -> !flood.status().running());
            assertEquals("mdk3 launch failed", flood.status().error());
            assertEquals(1, files.size());
            assertFalse(Files.exists(files.getFirst()));
        } finally {
            flood.terminate();
        }
    }

    @Test void stopsAfterMdk3ExitsWithoutRetryingAgain() throws Exception {
        var commands = new CopyOnWriteArrayList<List<String>>();
        var flood = new BeaconFlood("wlo1", builder -> {
            var command = List.copyOf(builder.command());
            commands.add(command);
            return new CompletedProcess("sudo: " + command.get(1) + ": command not found\n", 1);
        });
        try {
            flood.start("lab", 6, 100);
            await(() -> !flood.status().running());
            assertEquals(2, commands.size());
            assertEquals("mdk3", flood.status().tool());
            assertEquals("mdk3 exited with code 1", flood.status().error());
            assertTrue(flood.status().output().contains("sudo: mdk3: command not found"));
            assertFalse(Files.exists(Path.of(commands.get(1).get(5))));
        } finally {
            flood.terminate();
        }
    }

    @Test void cancellationPreventsFallbackAfterTheMissingCommandDiagnostic() throws Exception {
        var process = new StreamingCaptureProcess("", 1);
        var commands = new CopyOnWriteArrayList<List<String>>();
        var flood = new BeaconFlood("wlo1", builder -> {
            commands.add(List.copyOf(builder.command()));
            return process;
        });
        try {
            flood.start("lab", 6, 100);
            process.write("sudo: mdk4: command not found\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            await(() -> flood.status().output().contains("command not found"));
            flood.terminate();
            assertFalse(flood.status().running());
            assertFalse(process.isAlive());
            assertEquals(1, commands.size());
        } finally {
            flood.terminate();
        }
    }

    @Test void missingSudoDoesNotTriggerMdk3Fallback() {
        var commands = new CopyOnWriteArrayList<List<String>>();
        var flood = new BeaconFlood("wlo1", builder -> {
            commands.add(List.copyOf(builder.command()));
            throw new IOException("Cannot run program \"sudo\": error=2, No such file or directory");
        });
        assertThrows(IOException.class, () -> flood.start("lab", 6, 100));
        assertEquals(1, commands.size());
    }

    private static void await(BooleanSupplier condition) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
        while (!condition.getAsBoolean() && System.nanoTime() < deadline) Thread.sleep(10);
        assertTrue(condition.getAsBoolean());
    }

    @Test void rejectsInvalidSettingsBeforeLaunching() {
        var commands = new CopyOnWriteArrayList<List<String>>();
        var flood = new BeaconFlood("wlo1", builder -> {
            commands.add(List.copyOf(builder.command()));
            return new StreamingCaptureProcess();
        });
        for (String ssid : new String[]{null, "", " ", "x".repeat(33), "two\nlines"})
            assertThrows(IllegalArgumentException.class, () -> flood.start(ssid, 6, 100));
        assertThrows(IllegalArgumentException.class, () -> flood.start("lab", 0, 100));
        assertThrows(IllegalArgumentException.class, () -> flood.start("lab", 234, 100));
        assertThrows(IllegalArgumentException.class, () -> flood.start("lab", 6, 0));
        assertThrows(IllegalArgumentException.class, () -> flood.start("lab", 6, 10_001));
        assertThrows(IllegalArgumentException.class, () -> new BeaconFlood("a b"));
        assertTrue(commands.isEmpty());
    }

    @Test void reportsLaunchFailuresAndRejectsReuse() throws Exception {
        var flood = new BeaconFlood("wlo1", builder -> {
            throw new IOException("Permission denied");
        });
        var failure = assertThrows(IOException.class, () -> flood.start("lab", 6, 100));
        assertEquals("Permission denied", failure.getMessage());
        assertFalse(flood.status().running());
        assertEquals("Permission denied", flood.status().error());

        var running = new BeaconFlood("wlo1", builder -> new StreamingCaptureProcess());
        running.start("lab", 6, 100);
        assertThrows(IllegalStateException.class, () -> running.start("lab", 6, 100));
        running.terminate();
    }

    @Test void marksStoppedWhenTheToolExits() throws Exception {
        var flood = new BeaconFlood("wlo1", builder -> new ewave.fixtures.CompletedProcess("exited\n", 0));
        flood.start("lab", 6, 100);
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
        while (flood.status().running() && System.nanoTime() < deadline) Thread.sleep(10);
        assertFalse(flood.status().running());
        assertNull(flood.status().error());
        assertTrue(flood.status().output().contains("exited"));

        var failed = new BeaconFlood("wlo1", builder -> new ewave.fixtures.CompletedProcess("failed\n", 2));
        failed.start("lab", 6, 100);
        deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
        while (failed.status().running() && System.nanoTime() < deadline) Thread.sleep(10);
        assertFalse(failed.status().running());
        assertEquals("mdk4 exited with code 2", failed.status().error());
    }

    @Test void supportsMultiSsidListInPrivateWorkspaceAndCleansUpOnTerminate() throws Exception {
        var commands = new CopyOnWriteArrayList<List<String>>();
        var capturedSsidList = new java.util.concurrent.atomic.AtomicReference<String>();
        var process = new StreamingCaptureProcess();
        var flood = new BeaconFlood("wlo1", builder -> {
            var cmd = List.copyOf(builder.command());
            commands.add(cmd);
            int idx = cmd.indexOf("-f");
            if (idx >= 0 && idx + 1 < cmd.size()) {
                capturedSsidList.set(java.nio.file.Files.readString(java.nio.file.Path.of(cmd.get(idx + 1))));
            }
            return process;
        });

        assertThrows(IllegalArgumentException.class, () -> flood.start(List.of(), 6, 100));
        var tooMany = java.util.Collections.nCopies(51, "lab");
        assertThrows(IllegalArgumentException.class, () -> flood.start(tooMany, 6, 100));

        var status = flood.start(List.of("lab-1", "lab-2"), 6, 100);
        assertTrue(status.running());
        assertEquals(2, status.ssidCount());
        assertTrue(status.command().contains("-f "));
        assertEquals("lab-1\nlab-2", capturedSsidList.get().trim());

        var cmd = commands.getFirst();
        java.nio.file.Path ssidPath = java.nio.file.Path.of(cmd.get(cmd.indexOf("-f") + 1));
        assertTrue(java.nio.file.Files.exists(ssidPath));

        flood.terminate();
        assertFalse(java.nio.file.Files.exists(ssidPath));
        assertFalse(java.nio.file.Files.exists(ssidPath.getParent()));
    }
}
