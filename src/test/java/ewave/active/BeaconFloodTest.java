package ewave.active;

import ewave.fixtures.StreamingCaptureProcess;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

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
        assertTrue(flood.status().output().contains("exited"));
    }
}
