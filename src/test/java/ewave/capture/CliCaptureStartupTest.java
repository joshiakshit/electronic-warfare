package ewave.capture;

import ewave.Ewave;
import ewave.fixtures.CompletedProcess;
import ewave.fixtures.StreamingCaptureProcess;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(10)
class CliCaptureStartupTest {
    @ParameterizedTest
    @CsvSource({
            "--freq 2437, 2437, 6",
            "--freq 5180, 5180, 0",
            "--freq 5955, 5955, 0",
            "--channel 6 --band 2.4, 2437, 6",
            "--channel 14, 2484, 14",
            "--channel 36, 5180, 0",
            "--channel 1 --band 6, 5955, 0"
    })
    void tunesTheRequestedFrequencyBeforeStartingCapture(String flags, int frequency, int channel) throws Exception {
        var commands = new CopyOnWriteArrayList<List<String>>();
        var receiver = new StreamingCaptureProcess();
        try (var bridge = new PacketBridge(builder -> {
            commands.add(List.copyOf(builder.command()));
            return builder.command().getFirst().equals("tcpdump") ? receiver : new CompletedProcess("", 0);
        }, Map.of())) {
            Ewave.startCapture(Ewave.parseConfig(("--iface lab0mon " + flags).split(" ")), bridge);
            assertEquals(2, commands.size());
            assertEquals(List.of("sudo", "iw", "dev", "lab0mon", "set", "freq", Integer.toString(frequency)),
                    commands.getFirst());
            assertEquals("tcpdump", commands.get(1).getFirst());
            assertTrue(commands.get(1).contains("lab0mon"));
            assertTrue(bridge.isRunning());
            assertEquals("watch", bridge.getCaptureStatus().get("captureMode"));
            assertEquals(false, bridge.getCaptureStatus().get("scannerAttached"));
            assertEquals(channel == 0 ? null : channel, bridge.getCaptureStatus().get("channel"));
            assertEquals(frequency, bridge.getCaptureStatus().get("frequencyMhz"));
        }
    }

    @Test void waitsForSuccessfulTuningBeforeStartingCapture() throws Exception {
        var tuning = new StreamingCaptureProcess();
        var receiver = new StreamingCaptureProcess();
        var tuneStarted = new CountDownLatch(1);
        var commands = new CopyOnWriteArrayList<List<String>>();
        try (var bridge = new PacketBridge(builder -> {
            commands.add(List.copyOf(builder.command()));
            if (builder.command().getFirst().equals("tcpdump")) return receiver;
            tuneStarted.countDown();
            return tuning;
        }, Map.of()); var executor = Executors.newSingleThreadExecutor()) {
            var starting = executor.submit(() -> {
                Ewave.startCapture(Ewave.parseConfig("--iface", "lab0mon", "--freq", "2437"), bridge);
                return null;
            });
            try {
                assertTrue(tuneStarted.await(1, TimeUnit.SECONDS));
                assertFalse(starting.isDone());
                assertEquals(1, commands.size(), "Capture must wait for tuning to finish");
            } finally {
                tuning.finish();
            }
            starting.get(3, TimeUnit.SECONDS);
            assertTrue(bridge.isRunning());
            assertEquals(6, bridge.getCaptureStatus().get("channel"));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"exit", "timeout", "launch"})
    void tuningFailureAbortsStartupWithoutReportingTheRequestedChannel(String failure) throws Exception {
        var commands = new CopyOnWriteArrayList<List<String>>();
        var timedOut = new StreamingCaptureProcess() {
            @Override public boolean waitFor(long timeout, TimeUnit unit) {
                assertEquals(2, timeout);
                assertEquals(TimeUnit.SECONDS, unit);
                return false;
            }
        };
        try (var bridge = new PacketBridge(builder -> {
            commands.add(List.copyOf(builder.command()));
            if (failure.equals("launch")) throw new IOException("iw unavailable");
            return failure.equals("timeout") ? timedOut : new CompletedProcess("", 1);
        }, Map.of())) {
            var error = assertThrows(IOException.class, () -> Ewave.startCapture(
                    Ewave.parseConfig("--iface", "lab0mon", "--channel", "11", "--band", "2.4"), bridge));
            assertTrue(error.getMessage().contains(failure.equals("launch") ? "iw unavailable" : "Could not tune"));
            assertEquals(List.of(List.of("sudo", "iw", "dev", "lab0mon", "set", "freq", "2462")), commands);
            assertFalse(bridge.isRunning());
            assertNull(bridge.getCaptureStatus().get("channel"));
            assertEquals("idle", bridge.getCaptureStatus().get("captureMode"));
            assertNull(bridge.getPassiveWifi());
            if (failure.equals("timeout")) assertFalse(timedOut.isAlive());
        } finally {
            timedOut.destroy();
        }
    }

    @Test void doesNotRetuneAnExistingCaptureWhenCliStartupIsRejected() throws Exception {
        var commands = new CopyOnWriteArrayList<List<String>>();
        var receiver = new StreamingCaptureProcess();
        try (var bridge = new PacketBridge(builder -> {
            commands.add(List.copyOf(builder.command()));
            return receiver;
        }, Map.of())) {
            Ewave.startCapture(Ewave.parseConfig("--iface", "lab0mon"), bridge);
            assertThrows(IllegalStateException.class, () -> Ewave.startCapture(
                    Ewave.parseConfig("--iface", "lab0mon", "--freq", "2437"), bridge));
            assertEquals(1, commands.size());
            assertEquals("tcpdump", commands.getFirst().getFirst());
            assertTrue(bridge.isRunning());
            assertNull(bridge.getCaptureStatus().get("channel"));
        }
    }
}
