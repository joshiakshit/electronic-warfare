package ewave.capture;

import ewave.core.AdaptiveScanner;
import ewave.decoder.Dot11FrameDecoder;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SniperSweepPlannerTest {
    @Test void listensForABeaconIntervalAndAmortizesSlowRetunesWithACap() {
        var planner = new SniperSweepPlanner(List.of(channel(2412, false)));
        planner.tuneFinished(ms(100), 2412, true, ms(10));
        assertEquals(0, planner.finishDwell(ms(219)));
        assertEquals(2412, planner.finishDwell(ms(220)));
        assertEquals(0, planner.finishDwell(ms(230)));

        planner.tuneFinished(ms(400), 2412, true, ms(160));
        assertEquals(0, planner.finishDwell(ms(719)));
        assertEquals(2412, planner.finishDwell(ms(720)));

        planner.tuneFinished(ms(2000), 2412, true, ms(1000));
        assertEquals(0, planner.finishDwell(ms(2399)));
        assertEquals(2412, planner.finishDwell(ms(2400)));
    }

    @Test void promotesNewHintsWithinThePassAndRestartsAfterEveryFrequencyWasAttempted() {
        var planner = new SniperSweepPlanner(List.of(channel(2412, false), channel(5180, false), channel(5955, false)));
        var scanner = scanner(new double[]{0.1, 0.8, 0.2}, Map.of());
        assertEquals(5180, planner.nextFrequency(scanner, Set.of(), 0));
        planner.tuneFinished(0, 5180, false, 0);
        assertEquals(5955, planner.nextFrequency(scanner, Set.of(5180, 5955, 9999), 0));
        visit(planner, 5955);
        assertEquals(2412, planner.nextFrequency(scanner, Set.of(5180, 5955), 0));
        visit(planner, 2412);
        assertEquals(5955, planner.nextFrequency(scanner, Set.of(5955), 0));
    }

    @Test void ranksSameBandWithNonDfsPreferenceAndRevisitsOriginBeforeOtherBands() {
        var planner = new SniperSweepPlanner(List.of(channel(2412, false), channel(5180, false),
                channel(5260, true), channel(5500, true), channel(5955, false)));
        var scores = scanner(new double[]{8, 0.1, 0.7, 0.9, 0}, Map.of());
        var hints = Set.of(5955, 5500);
        for (int expected : List.of(5955, 5180, 5260, 5500, 2412)) {
            assertEquals(expected, planner.nextFrequency(scores, hints, 5500));
            visit(planner, expected);
        }
    }

    @Test void boostsPreferredChannelsAndActiveAnomaliesWithinTheirTier() {
        var two = new SniperSweepPlanner(List.of(channel(2417, false), channel(2437, false), channel(2462, false)));
        var six = new SniperSweepPlanner(List.of(channel(5955, false), channel(5975, false), channel(6055, false)));
        var scores = scanner(new double[]{0.6, 0.3, 0.1}, Map.of(3,
                new AdaptiveScanner.AnomalyFlag(3, 1, Instant.EPOCH, "PHASE_SHIFT")));
        assertEquals(2462, two.nextFrequency(scores, Set.of(), 2412));
        assertEquals(6055, six.nextFrequency(scores, Set.of(), 6135));
        for (String reason : List.of("NEW_ACTIVITY", "UNUSUAL_BURST", "PHASE_SHIFT")) {
            var anomalies = Map.of(3, new AdaptiveScanner.AnomalyFlag(3, 1, Instant.EPOCH, reason));
            assertEquals(6055, six.nextFrequency(scanner(new double[]{0.6, 0.3, 0.1}, anomalies), Set.of(), 0));
        }
    }

    @Test void anAnomalyOnTheFirstScannerSlotBoostsTheFirstFrequency() {
        var planner = new SniperSweepPlanner(List.of(channel(2412, false), channel(2437, false), channel(2462, false)));
        double[] scores = {0.1, 0.6, 0.4};
        assertEquals(2437, planner.nextFrequency(scanner(scores, Map.of()), Set.of(), 0));
        var flag = new AdaptiveScanner.AnomalyFlag(1, 3.2, Instant.EPOCH, "NEW_ACTIVITY");
        assertEquals(2412, planner.nextFrequency(scanner(scores, Map.of(1, flag)), Set.of(), 0));
    }

    private static RadioStatus.Channel channel(int freq, boolean radar) {
        return new RadioStatus.Channel(Dot11FrameDecoder.channel(freq), freq, false, radar);
    }

    private static AdaptiveScanner.Snapshot scanner(double[] scores, Map<Integer, AdaptiveScanner.AnomalyFlag> anomalies) {
        int count = scores.length;
        return new AdaptiveScanner.Snapshot(0, new double[count], new double[count], scores,
                new int[count], new long[count], 0, new int[0], anomalies, List.of());
    }

    private static long ms(long value) { return TimeUnit.MILLISECONDS.toNanos(value); }

    private static void visit(SniperSweepPlanner planner, int frequency) {
        planner.tuneFinished(0, frequency, true, 0);
        assertEquals(frequency, planner.finishDwell(ms(120)));
    }
}
