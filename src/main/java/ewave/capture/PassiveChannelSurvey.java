package ewave.capture;

import java.util.concurrent.TimeUnit;

/** Receive-only discovery across channels 1..13. The owner serializes calls.
 * Times are monotonic. Only confirmed tune completions and frames heard during
 * that visit can extend the listening window.
 */
public final class PassiveChannelSurvey {
    private static final long MIN_LISTEN = TimeUnit.MILLISECONDS.toNanos(100);
    private static final long HIT_GRACE = TimeUnit.MILLISECONDS.toNanos(200);
    private final long busyLimit;
    private int channel;
    private int nextChannel = 1;
    private long arrived, minimum, lastHit;
    private boolean heard;

    public PassiveChannelSurvey() {
        this(1200);
    }

    /** Maximum busy dwell in milliseconds, for offline policy comparisons. */
    public PassiveChannelSurvey(int busyLimitMs) {
        if (busyLimitMs <= 0) throw new IllegalArgumentException("Expected positive busy dwell");
        busyLimit = TimeUnit.MILLISECONDS.toNanos(busyLimitMs);
    }

    public int channel(long now) {
        if (channel != 0) {
            long dwell = now - arrived;
            if (dwell < minimum || heard && now - lastHit < HIT_GRACE && dwell < busyLimit) {
                return channel;
            }
        }
        return nextChannel;
    }

    public void frame(long now, int observedChannel) {
        if (channel == observedChannel) {
            heard = true;
            lastHit = now;
        }
    }

    public void tuneFinished(long now, int requested, boolean succeeded, long elapsed) {
        nextChannel = requested % 13 + 1;
        channel = succeeded ? requested : 0;
        arrived = now;
        heard = false;
        // Amortize a slow command, while bounding its impact on coverage.
        minimum = Math.max(MIN_LISTEN, 2 * Math.min(elapsed, TimeUnit.MILLISECONDS.toNanos(250)));
    }
}
