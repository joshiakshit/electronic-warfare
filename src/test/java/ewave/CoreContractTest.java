package ewave.core;

import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class CoreContractTest {
    private AdaptiveScanner scanner() { return new AdaptiveScanner(AdaptiveScanner.Config.defaults(3,128,71)); }

    @Test void invalidAndDuplicateFeedbackDoesNotMutateTheModel() {
        var scanner = scanner();
        scanner.observe(0,4,true);
        var before = scanner.snapshot(5);
        assertThrows(IllegalArgumentException.class,() -> scanner.observe(0,4,false));
        assertThrows(IllegalArgumentException.class,() -> scanner.observe(1,3,false));
        assertThrows(IllegalArgumentException.class,() -> scanner.observe(3,5,false));
        assertThrows(IllegalArgumentException.class,() -> scanner.observe(1,-1,false));
        assertArrayEquals(before.scores(),scanner.snapshot(5).scores());
        scanner.observe(1,5,false,false);
        assertEquals(0,scanner.snapshot(6).counts()[1]);
        assertEquals(1,scanner.snapshot(6).scores()[1]);
        assertThrows(IllegalArgumentException.class,() -> scanner.observe(1,5,true));
        // Top-K feedback can share a tick across distinct bands.
        scanner.observe(2,5,true);
        assertEquals(1,scanner.snapshot(6).counts()[2]);
    }

    @Test void snapshotsAndDecisionsAreDefensiveAndResetIsComplete() {
        var scanner = scanner();
        var initial = scanner.choose(0,3);
        int[] original = initial.bands();
        initial.bands()[0] = 999;
        initial.snapshot().scores()[0] = 999;
        initial.snapshot().counts()[0] = 999;
        assertArrayEquals(original,initial.bands());
        assertEquals(1,initial.snapshot().scores()[0]);
        for (int t = 0; t < 800; t++) scanner.observe(0,t,t % 20 == 5);
        assertEquals(20,scanner.snapshot(801).periods()[0]);
        var fingerprint = scanner.snapshot(801, 10).fingerprints().getFirst();
        assertEquals(200, fingerprint.fittedPeriodMs());
        assertEquals("802.11 AP (long interval)", fingerprint.deviceHint());
        assertTrue(fingerprint.fitConfidence() > .9 && fingerprint.fitConfidence() <= 1);
        for (int t = 800; t < 1200; t++) scanner.observe(0,t,false);
        var broken = scanner.snapshot(1200, 10);
        assertEquals("PERIOD_BROKEN", broken.anomalies().get(1).reason());
        assertEquals("Transient / mobile", broken.fingerprints().getFirst().deviceHint());
        assertEquals(0, broken.fingerprints().getFirst().fitConfidence());
        scanner.reset();
        assertArrayEquals(initial.snapshot().scores(),scanner.snapshot(0).scores());
        assertArrayEquals(new long[3],scanner.snapshot(0).counts());
        assertArrayEquals(new int[3],scanner.snapshot(0).periods());
        assertEquals(0,scanner.snapshot(0).coupledPeriod());
        assertTrue(scanner.snapshot(0).anomalies().isEmpty());
        assertArrayEquals(original,scanner.choose(0,3).bands());
    }

    @Test void flagsDeviationsAgainstThePrecedingSixtyValidObservations() {
        var scanner = scanner();
        scanner.observe(0, 0, true);
        for (int tick = 1; tick <= 60; tick++) scanner.observe(0, tick, false);
        scanner.observe(0, 61, true);
        var start = scanner.snapshot(62).anomalies().get(1);
        assertEquals("NEW_ACTIVITY", start.reason());
        assertEquals(1000, start.deviation());
        assertEquals(50, start.durationMillis(start.detectedAt().plusMillis(50)));

        scanner.observe(0, 62, false, false);
        scanner.observe(0, 63, true);
        var ongoing = scanner.snapshot(64).anomalies().get(1);
        assertEquals(start.detectedAt(), ongoing.detectedAt());
        assertEquals(start.reason(), ongoing.reason());
        double mean = 1.0 / 60;
        assertEquals((1 - mean) / (Math.sqrt(mean * (1 - mean)) + .001), ongoing.deviation(), 1e-12);

        scanner.observe(0, 64, false);
        assertTrue(scanner.snapshot(65).anomalies().isEmpty());
        scanner.observe(0, 65, true);
        assertEquals("UNUSUAL_BURST", scanner.snapshot(66).anomalies().get(1).reason());
    }

    @Test void selectionRejectsInvalidRequestsAndUsesDeterministicNearTies() {
        var a = scanner(); var b = scanner();
        for (int i = 0; i < 100; i++) {
            int[] chosen = a.choose(0,3).bands();
            assertArrayEquals(chosen,b.choose(0,3).bands());
            assertEquals(3,Arrays.stream(chosen).distinct().count());
        }
        assertThrows(IllegalArgumentException.class,() -> a.choose(0,0));
        assertThrows(IllegalArgumentException.class,() -> a.choose(0,4));
        a.observe(0,10,true);
        assertThrows(IllegalArgumentException.class,() -> a.choose(10,1));
        assertThrows(IllegalArgumentException.class,() -> a.snapshot(Long.MAX_VALUE));
        assertThrows(IllegalArgumentException.class,() -> AdaptiveScanner.Config.defaults(0,128,0));
        assertThrows(IllegalArgumentException.class,() -> AdaptiveScanner.Config.defaults(1,0,0));
        assertThrows(IllegalArgumentException.class,() -> new AdaptiveScanner.Config(1,128,48,6,1,4,200,.1,.2,.3,.03,1,0));
        assertThrows(IllegalArgumentException.class,() -> new AdaptiveScanner.Config(1,128,48,6,1,Double.NaN,200,.9,.01,.3,.03,1,0));
    }

    @Test void explicitPriorityWeightsExposeActualSelectionScores() {
        var scanner = scanner();
        double[] weights = {0,.5,2};
        var decision = scanner.choose(0,1,weights);
        assertEquals(2,decision.bands()[0]);
        assertArrayEquals(new double[]{.1,.5,2},decision.snapshot().scores());
        weights[2] = 99;
        assertEquals(2,decision.snapshot().scores()[2]);
        assertThrows(IllegalArgumentException.class,() -> scanner.choose(0,1,new double[]{1}));
        assertThrows(IllegalArgumentException.class,() -> scanner.choose(0,1,new double[]{1,Double.NaN,1}));
    }

    @Test void ringBufferEvictsOldSamplesWithoutGrowingAndHugeTimeGapsAreSafe() {
        var history = new PeriodFit.History(10);
        for (int i = 0; i < 100; i++) history.append(i,i%2==0);
        assertEquals(10,history.recent().size());
        assertEquals(90,history.recent().getFirst().tick());
        var samples = new ArrayList<PeriodFit.Sample>();
        for (int i = 0; i < 20; i++) samples.add(new PeriodFit.Sample(i * 1_000_000_000L,i%3==0));
        assertDoesNotThrow(() -> PeriodFit.autocorrelationCandidates(samples,280));
    }

    @Test void fixtureHashesAreFrozen() throws Exception {
        String manifest;
        try (var stream = getClass().getResourceAsStream("/reference/manifest.json")) {
            manifest = new String(Objects.requireNonNull(stream).readAllBytes(),java.nio.charset.StandardCharsets.UTF_8);
        }
        var matcher = Pattern.compile("\"file\": \"([^\"]+)\",\\s*\"sha256\": \"([^\"]+)\"").matcher(manifest);
        int count = 0;
        while (matcher.find()) {
            try (var stream = getClass().getResourceAsStream("/reference/"+matcher.group(1))) {
                String actual = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Objects.requireNonNull(stream).readAllBytes()));
                assertEquals(matcher.group(2),actual,matcher.group(1)); count++;
            }
        }
        assertEquals(6,count);
    }

    @Test void cliStreamsValidReplayAndReportsMalformedUnavailableAndMissingInput() throws IOException {
        Path input = Files.createTempFile("ewave-replay-",".csv");
        try {
            var stdout = new ByteArrayOutputStream(); var stderr = new ByteArrayOutputStream();
            var out = new PrintStream(stdout); var err = new PrintStream(stderr);
            Files.writeString(input,"tick,band,detection,valid\n0,0,1,1\n2,1,0,0\n");
            String[] args = {"replay","3","128","71",input.toString()};
            assertEquals(0,Main.run(args,out,err));
            String firstRun = stdout.toString(); stdout.reset();
            assertEquals(0,Main.run(args,out,err));
            assertEquals(firstRun,stdout.toString());
            assertEquals(3,firstRun.lines().count());
            assertTrue(stderr.toString().isEmpty());
            Files.writeString(input,"0,0,yes,1\n");
            assertEquals(2,Main.run(args,out,err));
            assertTrue(stderr.toString().contains("Line 1"));
            Files.writeString(input,"x".repeat(257));
            assertEquals(2,Main.run(args,out,err));
            Files.writeString(input,"0,0,1,1\n0,0,0,1\n");
            assertEquals(2,Main.run(args,out,err));
            Files.delete(input);
            assertEquals(1,Main.run(args,out,err));
            assertEquals(0,Main.run(new String[]{"--help"},out,err));
        } finally { Files.deleteIfExists(input); }
    }
}
