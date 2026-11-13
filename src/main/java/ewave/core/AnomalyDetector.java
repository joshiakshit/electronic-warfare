package ewave.core;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;

/** A binary occupancy baseline over the preceding valid observations. */
final class AnomalyDetector {
    private final boolean[] history;
    private final Clock clock;
    private int cursor, size, hits;
    private AdaptiveScanner.AnomalyFlag active;

    AnomalyDetector() { this(60); }

    AnomalyDetector(int historySize) { this(historySize, Clock.systemUTC()); }

    AnomalyDetector(int historySize, Clock clock) {
        if (historySize < 10) throw new IllegalArgumentException("historySize must be >= 10");
        history = new boolean[historySize];
        this.clock = Objects.requireNonNull(clock);
    }

    void observe(int channel, boolean detection, int previousPeriod, int period) {
        double mean = size == 0 ? 0 : hits / (double) size;
        double deviation = size == 0 ? 0
                : ((detection ? 1 : 0) - mean) / (Math.sqrt(mean * (1 - mean)) + .001);
        if (size == history.length && history[cursor]) hits--;
        if (detection) hits++;
        history[cursor] = detection;
        cursor = (cursor + 1) % history.length;
        size = Math.min(size + 1, history.length);

        boolean wasBroken = active != null && active.reason().equals("PERIOD_BROKEN");
        if (period == 0 && (previousPeriod != 0 || wasBroken)) {
            Instant start = wasBroken ? active.detectedAt() : Instant.now(clock);
            active = new AdaptiveScanner.AnomalyFlag(channel, deviation, start, "PERIOD_BROKEN");
        } else if (deviation > 2.5) {
            if (active == null || wasBroken) {
                active = new AdaptiveScanner.AnomalyFlag(channel, deviation, Instant.now(clock),
                        mean == 0 ? "NEW_ACTIVITY" : "UNUSUAL_BURST");
            } else {
                active = new AdaptiveScanner.AnomalyFlag(channel, deviation, active.detectedAt(), active.reason());
            }
        } else {
            active = null;
        }
    }

    AdaptiveScanner.AnomalyFlag active() { return active; }
}
