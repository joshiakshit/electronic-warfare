package ewave.active;

import ewave.fixtures.CompletedProcess;
import ewave.fixtures.StreamingCaptureProcess;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(15)
class PmkidCaptureTest {
    @TempDir Path directory;

    @Test void runsCaptureConversionAndVerificationAndReturnsTheCrackedKey() throws Exception {
        var commands = new CopyOnWriteArrayList<List<String>>();
        Path words = Files.writeString(directory.resolve("words.txt"), "lab password\n");
        var capture = new PmkidCapture("wlo1", directory.resolve("captures").toString(),
                starter(commands, true, true));

        var result = capture.run(words.toString(), 5);

        assertTrue(result.captured());
        assertTrue(result.vulnerable());
        assertEquals("lab password", result.psk());
        assertTrue(result.pcapngPath().endsWith(".pcapng"));
        assertTrue(result.hashPath().endsWith(".22000"));
        assertNotNull(result.timestamp());
        assertEquals(3, commands.size());
        assertEquals(List.of("sudo", "hcxdumptool", "-i", "wlo1", "-w", result.pcapngPath(), "--tot=1"),
                commands.get(0));
        assertEquals(List.of("hcxpcapngtool", "-o", result.hashPath(), result.pcapngPath()), commands.get(1));
        assertEquals(List.of("aircrack-ng", "-I",
                "4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*f4747f87f9f4*hashcat-essid",
                "-e", "hashcat-essid", "-w", words.toString()), commands.get(2));
        assertEquals(result.command(), String.join(" ", commands.get(2)));
        assertTrue(result.output().contains("KEY FOUND!"));
        assertFalse(capture.status().running());
    }

    @Test void reportsAnExhaustedWordlistAndSkipsVerificationWithoutHashes() throws Exception {
        Path words = Files.writeString(directory.resolve("words.txt"), "lab password\n");
        var commands = new CopyOnWriteArrayList<List<String>>();
        var miss = new PmkidCapture("wlo1", directory.resolve("captures").toString(),
                starter(commands, true, false)).run(words.toString(), 1);
        assertTrue(miss.captured());
        assertFalse(miss.vulnerable());
        assertNull(miss.psk());

        commands.clear();
        var empty = new PmkidCapture("wlo1", directory.resolve("captures").toString(),
                starter(commands, false, true)).run(words.toString(), 1);
        assertFalse(empty.captured());
        assertFalse(empty.vulnerable());
        assertEquals(2, commands.size());
        assertEquals("hcxpcapngtool", commands.get(1).getFirst());
    }

    @Test void explainsEapolOnlyHashesWithoutLaunchingAircrack() throws Exception {
        Path words = Files.writeString(directory.resolve("words.txt"), "word\n");
        var commands = new CopyOnWriteArrayList<List<String>>();
        var capture = new PmkidCapture("wlo1", directory.toString(), builder -> {
            var command = List.copyOf(builder.command());
            commands.add(command);
            if (command.get(1).equals("hcxdumptool")) {
                Files.write(Path.of(command.get(command.indexOf("-w") + 1)), new byte[]{0x0a, 0x0d, 0x0d, 0x0a});
                return new CompletedProcess("", 0);
            }
            Files.writeString(Path.of(command.get(command.indexOf("-o") + 1)),
                    "WPA*02*024022795224bffca545276c3762686f*6466b38ec3fc*225edc49b7aa*"
                            + "54502d4c494e4b5f484153484341545f54455354*00*00*a2\n");
            return new CompletedProcess("converted\n", 0);
        });
        var result = capture.run(words.toString(), 1);
        assertFalse(result.captured());
        assertFalse(result.vulnerable());
        assertNull(result.psk());
        assertEquals(2, commands.size());
        assertTrue(result.output().contains("No PMKID hash found"));
    }

    @Test void validatesArgumentsBeforeLaunchingAnything() throws Exception {
        Path words = Files.writeString(directory.resolve("words.txt"), "word\n");
        var commands = new CopyOnWriteArrayList<List<String>>();
        var capture = new PmkidCapture("wlo1", directory.toString(), starter(commands, true, true));
        assertThrows(IllegalArgumentException.class, () -> capture.run(words.toString(), 0));
        assertThrows(IllegalArgumentException.class, () -> capture.run(words.toString(), 301));
        assertThrows(IOException.class, () -> capture.run(directory.resolve("missing").toString(), 1));
        assertThrows(IllegalArgumentException.class, () -> new PmkidCapture("--help"));
        assertTrue(commands.isEmpty());
        assertFalse(capture.status().running());
    }

    @Test void terminateStopsARunningCapture() throws Exception {
        Path words = Files.writeString(directory.resolve("words.txt"), "word\n");
        var process = new StreamingCaptureProcess();
        var launched = new CountDownLatch(1);
        var capture = new PmkidCapture("wlo1", directory.toString(), builder -> {
            launched.countDown();
            return process;
        });
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            var future = executor.submit(() -> capture.run(words.toString(), 5));
            assertTrue(launched.await(3, TimeUnit.SECONDS));
            assertTrue(capture.status().running());
            capture.terminate();
            var failure = assertThrows(ExecutionException.class, () -> future.get(5, TimeUnit.SECONDS));
            assertInstanceOf(java.util.concurrent.CancellationException.class, failure.getCause());
        }
        assertFalse(process.isAlive());
        assertFalse(capture.status().running());
    }

    @Test void convertsLowLevelFailuresIntoDiagnostics() throws Exception {
        Path words = Files.writeString(directory.resolve("words.txt"), "word\n");
        var capture = new PmkidCapture("wlo1", directory.toString(), builder -> {
            throw new IOException("hcxdumptool not found");
        });
        var failure = assertThrows(IOException.class, () -> capture.run(words.toString(), 1));
        assertTrue(failure.getMessage().contains("hcxdumptool not found"));
        assertFalse(capture.status().running());

        var slow = new PmkidCapture("wlo1", directory.toString(), builder -> {
            var command = builder.command();
            if (command.get(1).equals("hcxdumptool"))
                Files.write(Path.of(command.get(command.indexOf("-w") + 1)), new byte[]{0x0a, 0x0d, 0x0d, 0x0a});
            return new NeverFinishes();
        });
        assertThrows(TimeoutException.class, () -> slow.run(words.toString(), 1));
    }

    private static final class NeverFinishes extends Process {
        @Override public java.io.InputStream getInputStream() { return java.io.InputStream.nullInputStream(); }
        @Override public java.io.OutputStream getOutputStream() { return java.io.OutputStream.nullOutputStream(); }
        @Override public java.io.InputStream getErrorStream() { return java.io.InputStream.nullInputStream(); }
        @Override public int waitFor() { return -1; }
        @Override public boolean waitFor(long timeout, TimeUnit unit) { return false; }
        @Override public int exitValue() { throw new IllegalThreadStateException(); }
        @Override public void destroy() { }
    }

    private static PmkidCapture.ProcessStarter starter(List<List<String>> commands, boolean hashes, boolean found) {
        return builder -> {
            var command = List.copyOf(builder.command());
            commands.add(command);
            if (command.get(1).equals("hcxdumptool")) {
                Files.write(Path.of(command.get(command.indexOf("-w") + 1)), new byte[]{0x0a, 0x0d, 0x0d, 0x0a});
                return new CompletedProcess("capture\n", 0);
            }
            if (command.getFirst().equals("hcxpcapngtool")) {
                if (hashes) Files.writeString(Path.of(command.get(command.indexOf("-o") + 1)),
                        "WPA*01*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*f4747f87f9f4*"
                                + "686173686361742d6573736964***\n");
                return new CompletedProcess("converted\n", 0);
            }
            if (command.getFirst().equals("aircrack-ng"))
                return new CompletedProcess(found ? "KEY FOUND! [ lab password ]\n" : "KEY NOT FOUND\n", found ? 0 : 1);
            throw new IOException("Unexpected command: " + command);
        };
    }
}
