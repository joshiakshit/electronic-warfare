package ewave.active;

import ewave.fixtures.CompletedProcess;
import ewave.fixtures.StreamingCaptureProcess;
import ewave.model.HandshakeResult.Outcome;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.HexFormat;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(10)
class HandshakeAnalyzerTest {
    private static final String AP = "02:11:22:33:44:55", CLIENT = "02:11:22:33:44:66";
    private static final String OTHER = "02:11:22:33:44:77";
    private static final byte[] HEADER = HexFormat.of().parseHex("d4c3b2a1020004000000000000000000000004007f000000");
    private static final HandshakeAnalyzer.Timing FAST = new HandshakeAnalyzer.Timing(Duration.ofMillis(200),
            Duration.ofMillis(350), Duration.ofMillis(5), Duration.ofMillis(40));
    @TempDir Path directory;

    private HandshakeAnalyzer analyzer(String client, HandshakeAnalyzer.ProcessStarter starter) {
        return new HandshakeAnalyzer("wlo1", AP, client, 6, 2437, directory.toString(), starter, FAST);
    }

    @Test void tunesMeasuredFrequencyAndPromptsOnlyAfterMatchingBeacon() throws Exception {
        var commands = new ArrayList<List<String>>();
        var fixture = new PassiveFixture();
        var timing = new HandshakeAnalyzer.Timing(Duration.ofSeconds(2), Duration.ofSeconds(3), FAST.poll(), FAST.verify());
        var analyzer = new HandshakeAnalyzer("wlo1", AP, null, 5, 5975, directory.toString(), builder -> {
            commands.add(List.copyOf(builder.command()));
            return fixture.start(builder);
        }, timing);
        var pending = captureAsync(analyzer);
        try {
            assertTrue(fixture.started.await(1, TimeUnit.SECONDS));
            fixture.row(beacon(OTHER, 5975, 5));
            fixture.row(beacon(AP, 5955, 1));
            fixture.row(beacon(AP, 5975, 1));
            assertTrue(analyzer.status().stage().startsWith("Waiting for target AP beacon"));
            fixture.row(beacon(AP, 5975, 5));
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(1);
            while (!analyzer.status().stage().startsWith("Ready —") && System.nanoTime() < deadline) Thread.sleep(5);
            assertEquals("Ready — reconnect your device now", analyzer.status().stage());
            fixture.recorder.write(new byte[]{1, 2, 3}); // Stop while the next record header is incomplete.
            for (int i = 1; i <= 4; i++) fixture.row(message(AP, CLIENT, 5975, i, i < 3 ? 1 : 2, "a"));
            var result = pending.get(3, TimeUnit.SECONDS);
            assertTrue(result.handshakeDetected());
            assertEquals(Outcome.COMPLETE, result.outcome());
            assertEquals(List.of(1, 2, 3, 4), result.messages());
            assertEquals(CLIENT, result.clientMac());
            assertEquals(AP, result.apBssid());
            assertEquals(5975, result.frequencyMhz());
            assertArrayEquals(HEADER, Files.readAllBytes(Path.of(result.capFilePath())));
            assertEquals(List.of("sudo", "iw", "dev", "wlo1", "set", "freq", "5975"), commands.getFirst());
            assertEquals(List.of("sudo", "tcpdump", "-i", "wlo1", "-s", "0", "-U", "-w", "-"), commands.getLast());
            assertEquals(3, commands.size());
            assertFalse(fixture.recorder.isAlive());
            assertFalse(fixture.decoder.isAlive());
        } finally { analyzer.terminate(); }
    }

    @Test void retainsRecordingsForPartialExchangeAndStaleApChannel() throws Exception {
        for (boolean beaconSeen : new boolean[]{true, false}) {
            var fixture = new PassiveFixture();
            var analyzer = analyzer(CLIENT, fixture::start);
            var pending = captureAsync(analyzer);
            try {
                assertTrue(fixture.started.await(1, TimeUnit.SECONDS));
                fixture.row(beacon(AP, 2437, beaconSeen ? 6 : 2));
                if (beaconSeen) {
                    fixture.row(message(AP, OTHER, 2437, 1, 7, "other"));
                    fixture.row(message(AP, CLIENT, 2437, 2, 1, "b"));
                    fixture.row(message(AP, CLIENT, 2437, 3, 2, "a"));
                }
                var result = pending.get(3, TimeUnit.SECONDS);
                assertFalse(result.handshakeDetected());
                assertEquals(beaconSeen ? Outcome.PARTIAL : Outcome.TARGET_NOT_SEEN, result.outcome());
                assertEquals(beaconSeen ? List.of(2, 3) : List.of(), result.messages());
                assertArrayEquals(HEADER, Files.readAllBytes(Path.of(result.capFilePath())));
            } finally { analyzer.terminate(); }
        }
    }

    @Test void rejectsMixedStationsReplayMismatchesAndExchangesAcrossAssociations() {
        var tracker = new HandshakePackets(AP, CLIENT, 2437, 6);
        tracker.accept(message(AP, CLIENT, 2437, 1, 1, "a"));
        tracker.accept(message(AP, OTHER, 2437, 2, 1, "b"));
        tracker.accept(message(AP, CLIENT, 2437, 3, 2, "a"));
        tracker.accept(message(AP, CLIENT, 2437, 4, 2, ""));
        assertFalse(tracker.observation().complete());
        tracker.accept(message(AP, CLIENT, 2437, 1, 5, "c"));
        tracker.accept(message(AP, CLIENT, 2437, 2, 5, "d"));
        tracker.accept(row("0x0002", "2437", AP, CLIENT, AP, "", "", "", "", "", "", ""));
        tracker.accept(message(AP, CLIENT, 2437, 3, 6, "c"));
        tracker.accept(message(AP, CLIENT, 2437, 4, 6, ""));
        assertFalse(tracker.observation().complete());
        tracker.accept(message(AP, CLIENT, 2437, 1, 7, "e"));
        tracker.accept(message(AP, CLIENT, 2437, 2, 7, "f"));
        tracker.accept(message(AP, CLIENT, 2437, 3, 8, "e"));
        tracker.accept(message(AP, CLIENT, 2437, 4, 9, ""));
        assertFalse(tracker.observation().complete());
        tracker.accept(message(AP, CLIENT, 2437, 4, 8, ""));
        assertTrue(tracker.observation().complete());
    }

    @Test void reportsMissingCaptureToolsAndReleasesBothProcessesOnCancellation() throws Exception {
        var missing = analyzer(null, builder -> {
            if (builder.command().contains("iw")) return new CompletedProcess("", 0);
            throw new IOException("tshark missing");
        });
        assertTrue(assertThrows(IOException.class, missing::capture).getMessage().contains("tshark missing"));
        var fixture = new PassiveFixture();
        var analyzer = analyzer(null, fixture::start);
        var pending = captureAsync(analyzer);
        assertTrue(fixture.started.await(1, TimeUnit.SECONDS));
        analyzer.terminate();
        var error = assertThrows(java.util.concurrent.ExecutionException.class, () -> pending.get(3, TimeUnit.SECONDS));
        assertInstanceOf(CancellationException.class, error.getCause());
        assertFalse(fixture.recorder.isAlive());
        assertFalse(fixture.decoder.isAlive());
    }

    private static FutureTask<ewave.model.HandshakeResult> captureAsync(HandshakeAnalyzer analyzer) {
        var task = new FutureTask<>(analyzer::capture);
        Thread.startVirtualThread(task);
        return task;
    }

    private static String beacon(String ap, int frequency, int channel) {
        return row("0x0008", String.valueOf(frequency), ap, ap, "ff:ff:ff:ff:ff:ff",
                String.valueOf(channel), "", "", "", "", "", "");
    }

    private static String message(String ap, String client, int frequency, int message, int replay, String nonce) {
        boolean fromAp = message == 1 || message == 3;
        return row("0x0028", String.valueOf(frequency), ap, fromAp ? ap : client, fromAp ? client : ap,
                "", "", "", String.valueOf(message), String.valueOf(replay), nonce, "True");
    }

    private static String row(String... fields) { return String.join("\t", fields); }

    private static final class PassiveFixture {
        final StreamingCaptureProcess recorder;
        final CountDownLatch started = new CountDownLatch(1);
        StreamingCaptureProcess decoder;

        PassiveFixture() throws IOException { recorder = new StreamingCaptureProcess(); }

        Process start(ProcessBuilder builder) throws IOException {
            var command = builder.command();
            if (command.contains("iw")) return new CompletedProcess("", 0);
            if (command.getFirst().equals("tshark")) {
                Path cap = Path.of(command.get(command.indexOf("-w") + 1));
                decoder = new StreamingCaptureProcess() {
                    @Override public OutputStream getOutputStream() {
                        try {
                            return new FilterOutputStream(Files.newOutputStream(cap)) {
                                @Override public void close() throws IOException {
                                    super.close();
                                    finish();
                                }
                            };
                        } catch (IOException failure) {
                            throw new java.io.UncheckedIOException(failure);
                        }
                    }
                };
                return decoder;
            }
            assertTrue(command.contains("tcpdump"));
            recorder.write(HEADER);
            started.countDown();
            return recorder;
        }

        void row(String row) throws IOException { decoder.write((row + "\n").getBytes(StandardCharsets.UTF_8)); }
    }

    @Test void verifiesKeysPreservingSpacesAndFullOutputAndAcceptsDictionaryMissExitOne() throws Exception {
        Path cap = Files.writeString(directory.resolve("capture with spaces.cap"), "pcap");
        Path words = Files.writeString(directory.resolve("-words.txt"), "wordlist");
        for (boolean found : new boolean[]{false, true}) {
            String output = found ? "\u001B[2J\nKEY FOUND! [  pass [ word ]  ]\n" : "stats ".repeat(180_000) + "\nKEY NOT FOUND\n";
            var verifier = analyzer(null, builder -> {
                assertEquals(List.of("aircrack-ng", cap.toString(), "-w", words.toString()), builder.command());
                assertTrue(builder.redirectErrorStream());
                return new CompletedProcess(output, found ? 0 : 1);
            });
            var result = verifier.verifyPsk(cap.toString(), words.toString());
            assertEquals(found, result.vulnerable());
            assertEquals(found ? " pass [ word ] " : null, result.psk());
            assertEquals(output, result.fullOutput());
            assertNotNull(result.timestamp());
        }
    }

    @Test void verificationErrorsAndTimeoutsNeverBecomeDictionaryMisses() throws Exception {
        Path cap = Files.writeString(directory.resolve("capture.cap"), "pcap");
        Path words = Files.writeString(directory.resolve("words.txt"), "wordlist");
        for (String output : new String[]{"No valid WPA handshakes found.", "", "KEY FOUND! [bad]"}) {
            var verifier = analyzer(null, builder -> new CompletedProcess(output, 1));
            assertThrows(IOException.class, () -> verifier.verifyPsk(cap.toString(), words.toString()));
        }
        var stuck = new StreamingCaptureProcess();
        assertThrows(TimeoutException.class, () -> analyzer(null, builder -> stuck).verifyPsk(cap.toString(), words.toString()));
        assertFalse(stuck.isAlive());
        var readFailure = new Process() {
            @Override public InputStream getInputStream() {
                return new InputStream() {
                    @Override public int read() throws IOException { throw new IOException("simulated read failure"); }
                };
            }
            @Override public InputStream getErrorStream() { return InputStream.nullInputStream(); }
            @Override public OutputStream getOutputStream() { return OutputStream.nullOutputStream(); }
            @Override public int waitFor() { return 0; }
            @Override public int exitValue() { return 0; }
            @Override public void destroy() { }
        };
        assertTrue(assertThrows(IOException.class,
                () -> analyzer(null, builder -> readFailure).verifyPsk(cap.toString(), words.toString()))
                .getMessage().contains("simulated read failure"));
    }

    @Test void rejectsInvalidTargetsInterfacesAndFilesBeforeLaunching() throws Exception {
        HandshakeAnalyzer.ProcessStarter never = builder -> { fail("must not launch"); return null; };
        for (String monitor : new String[]{"--help", "a b", "wlan0;id", "", "1234567890123456"})
            assertThrows(IllegalArgumentException.class, () -> new HandshakeAnalyzer(monitor, AP, null, 1));
        assertThrows(IllegalArgumentException.class, () -> new HandshakeAnalyzer("wlo1", "--help", null, 6,
                directory.toString(), never).capture());
        assertThrows(IllegalArgumentException.class, () -> analyzer("bad", never).capture());
        assertThrows(IllegalArgumentException.class, () -> new HandshakeAnalyzer("wlo1", AP, null, 234,
                directory.toString(), never).capture());
        Path cap = Files.writeString(directory.resolve("capture.cap"), "pcap");
        var verifier = analyzer(null, never);
        assertEquals(HandshakeAnalyzer.WORDLIST_MISSING, assertThrows(IOException.class,
                () -> verifier.verifyPsk(cap.toString(), directory.resolve("missing").toString())).getMessage());
        assertThrows(IOException.class, () -> verifier.verifyPsk(directory.toString(), cap.toString()));
        var cancelled = analyzer(null, never);
        cancelled.terminate();
        assertThrows(CancellationException.class, cancelled::capture);
    }
}
