package ewave.capture;

import ewave.core.AdaptiveScanner;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/** One receive-only pass at a time. The bridge owns the planner and serializes changes. */
final class SniperSweepPlanner {
    private static final long MIN_DWELL = TimeUnit.MILLISECONDS.toNanos(120);
    private static final long MAX_RETUNE_COST = TimeUnit.MILLISECONDS.toNanos(200);

    private final List<RadioStatus.Channel> channels;
    private final Set<Integer> visited = new HashSet<>();
    private int listeningFrequency;
    private long listenUntil;

    SniperSweepPlanner(List<RadioStatus.Channel> channels) {
        this.channels = List.copyOf(channels);
    }

    int nextFrequency(AdaptiveScanner.Snapshot scanner, Set<Integer> hints, int lostFromFrequency) {
        if (visited.size() == channels.size()) visited.clear();
        double[] scores = scanner == null ? new double[0] : scanner.scores();
        int bestFrequency = 0;
        int bestTier = Integer.MAX_VALUE;
        double bestScore = Double.NEGATIVE_INFINITY;
        for (int slot = 0; slot < channels.size(); slot++) {
            var channel = channels.get(slot);
            int frequency = channel.frequencyMhz();
            if (visited.contains(frequency)) continue;
            int tier = tier(frequency, hints, lostFromFrequency);
            double score = slot < scores.length && Double.isFinite(scores[slot]) ? scores[slot] : 0;
            if (scanner != null) score += anomalyBonus(scanner.anomalies().get(slot + 1));
            if (tier == 1 && preferred(channel)) score += 1;
            if (frequency == lostFromFrequency) score = Double.NEGATIVE_INFINITY;
            if (tier < bestTier || (tier == bestTier && score > bestScore)) {
                bestFrequency = frequency;
                bestTier = tier;
                bestScore = score;
            }
        }
        return bestFrequency;
    }

    void tuneFinished(long now, int frequency, boolean succeeded, long elapsed) {
        if (succeeded) {
            listeningFrequency = frequency;
            listenUntil = now + Math.max(MIN_DWELL, 2 * Math.min(elapsed, MAX_RETUNE_COST));
        } else {
            visited.add(frequency);
            listeningFrequency = 0;
        }
    }

    int listeningFrequency() { return listeningFrequency; }

    int finishDwell(long now) {
        if (listeningFrequency == 0 || now - listenUntil < 0) return 0;
        int frequency = listeningFrequency;
        visited.add(frequency);
        listeningFrequency = 0;
        return frequency;
    }

    void reset() {
        visited.clear();
        listeningFrequency = 0;
    }

    private static int tier(int frequency, Set<Integer> hints, int lostFromFrequency) {
        // Reserve the previous frequency for the end of its band, even if an RNR lists it.
        if (frequency != lostFromFrequency && hints.contains(frequency)) return 0;
        if (lostFromFrequency != 0 && band(frequency).equals(band(lostFromFrequency))) return 1;
        return 2;
    }

    private static double anomalyBonus(AdaptiveScanner.AnomalyFlag flag) {
        if (flag == null) return 0;
        return switch (flag.reason()) {
            case "NEW_ACTIVITY", "UNUSUAL_BURST", "PHASE_SHIFT" -> 1;
            default -> 0;
        };
    }

    private static boolean preferred(RadioStatus.Channel channel) {
        int frequency = channel.frequencyMhz();
        return switch (band(frequency)) {
            case "2.4 GHz" -> frequency == 2412 || frequency == 2437 || frequency == 2462;
            case "5 GHz" -> !Boolean.TRUE.equals(channel.radarDetection());
            default -> frequency >= 5975 && (channel.channel() - 5) % 16 == 0;
        };
    }

    static String band(int frequency) {
        if (frequency >= 5935) return "6 GHz";
        if (frequency >= 4900) return "5 GHz";
        return "2.4 GHz";
    }
}
