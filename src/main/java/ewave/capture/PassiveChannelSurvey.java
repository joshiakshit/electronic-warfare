package ewave.capture;

import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;

/** Receive-only discovery across an ordered set of channel identifiers. The owner serializes calls.
 * Times are monotonic. Only confirmed tune completions and frames heard during
 * that visit can extend the listening window.
 */
public final class PassiveChannelSurvey {
    private static final long MIN_LISTEN = TimeUnit.MILLISECONDS.toNanos(100);
    private static final long HIT_GRACE = TimeUnit.MILLISECONDS.toNanos(200);
    private final long busyLimit;
    private final List<Integer> channels;
    private int channel;
    private int nextIndex;
    private int attempted;
    private int lastAttempted;
    private long arrived, minimum, lastHit;
    private boolean heard;

    public PassiveChannelSurvey() {
        this(1200);
    }

    /** Maximum busy dwell in milliseconds, for offline policy comparisons. */
    public PassiveChannelSurvey(int busyLimitMs) {
        this(IntStream.rangeClosed(1, 13).boxed().toList(), busyLimitMs);
    }

    PassiveChannelSurvey(List<Integer> frequenciesMhz, int busyLimitMs) {
        if (busyLimitMs <= 0) throw new IllegalArgumentException("Expected positive busy dwell");
        channels = List.copyOf(frequenciesMhz);
        busyLimit = TimeUnit.MILLISECONDS.toNanos(busyLimitMs);
    }

    public int channel(long now) {
        if (channel != 0 && !dwellFinished(now)) return channel;
        return channels.isEmpty() ? 0 : channels.get(nextIndex);
    }

    boolean dwellFinished(long now) {
        long dwell = now - arrived;
        return channel != 0 && dwell >= minimum && (!heard || now - lastHit >= HIT_GRACE || dwell >= busyLimit);
    }

    int listeningChannel() { return channel; }

    boolean bootstrapComplete() { return attempted == channels.size(); }

    int lastAttempted() { return lastAttempted; }

    boolean failedTuneCoolingDown(long now) {
        return channel == 0 && lastAttempted != 0 && now - arrived < MIN_LISTEN;
    }

    void interruptListening() {
        channel = 0;
        lastAttempted = 0;
    }

    void listenOnConfirmedChannel(long now, int confirmed) {
        if (channel != confirmed || dwellFinished(now)) tuneFinished(now, confirmed, true, 0);
    }

    public void frame(long now, int observedChannel) {
        if (channel == observedChannel) {
            heard = true;
            lastHit = now;
        }
    }

    public void tuneFinished(long now, int requested, boolean succeeded, long elapsed) {
        int index = channels.indexOf(requested);
        if (index < 0) return;
        if (!bootstrapComplete()) attempted++;
        lastAttempted = requested;
        nextIndex = (index + 1) % channels.size();
        channel = succeeded ? requested : 0;
        arrived = now;
        heard = false;
        // Amortize a slow command, while bounding its impact on coverage.
        minimum = Math.max(MIN_LISTEN, 2 * Math.min(elapsed, TimeUnit.MILLISECONDS.toNanos(250)));
    }

    public void reset() {
        interruptListening();
        nextIndex = 0;
        attempted = 0;
        arrived = 0;
        minimum = 0;
        lastHit = 0;
        heard = false;
    }
}
