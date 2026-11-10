package ewave.core;

import java.util.ArrayList;
import java.util.List;

/** A scripted RF fixture evaluated by the production adaptive scanner. */
public final class ScannerDemo {
    private static final int CHANNELS = 13;
    private static final int TICK_MS = 100;
    private static final int DURATION_MS = 12_000;
    private static final int FIXED_CHANNEL = 6;
    private static final int RETUNE_MS = 25;
    private static final int FRAME_INTERVAL_MS = 50;
    private static final List<Burst> BURSTS = List.of(
            new Burst(6, 1_000, 3_000),
            new Burst(11, 4_000, 6_500),
            new Burst(1, 7_500, 10_000)
    );

    private ScannerDemo() {}

    public record Burst(int channel, int startMs, int endMs) {}
    public record Detection(Integer delayMs, int capturedFrames, int missedFrames) {}
    public record Run(List<Long> dwellMs, int channelsVisited, int retunes, Integer meanRetuneMs,
                      int capturedFrames, int missedFrames, List<Detection> detections) {}
    public record Comparison(int durationMs, int tickMs, int fixedChannel, int simulatedRetuneMs,
                             int frameIntervalMs, List<Burst> bursts, Run adaptive, Run fixed) {}

    public static Comparison compare() {
        return new Comparison(DURATION_MS, TICK_MS, FIXED_CHANNEL, RETUNE_MS, FRAME_INTERVAL_MS,
                BURSTS, run(new AdaptiveScanner(AdaptiveScanner.Config.defaults(CHANNELS, 2048, 42))), run(null));
    }

    private static Run run(AdaptiveScanner scanner) {
        long[] dwell = new long[CHANNELS];
        Integer[] delays = new Integer[BURSTS.size()];
        int[] captured = new int[BURSTS.size()];
        int[] missed = new int[BURSTS.size()];
        int tuned = FIXED_CHANNEL;
        int retunes = 0;
        for (int start = 0; start < DURATION_MS; start += TICK_MS) {
            int tick = start / TICK_MS;
            int chosen = scanner == null || tick == 0 ? FIXED_CHANNEL : scanner.choose(tick, 1).bands()[0] + 1;
            boolean changed = chosen != tuned;
            if (changed) retunes++;
            tuned = chosen;
            int listeningFrom = start + (changed ? RETUNE_MS : 0);
            int end = start + TICK_MS;
            dwell[tuned - 1] += end - listeningFrom;

            boolean detected = false;
            for (int i = 0; i < BURSTS.size(); i++) {
                Burst burst = BURSTS.get(i);
                for (int frame = burst.startMs(); frame < burst.endMs(); frame += FRAME_INTERVAL_MS) {
                    if (frame < start || frame >= end) continue;
                    if (tuned == burst.channel() && frame >= listeningFrom) {
                        detected = true;
                        captured[i]++;
                        if (delays[i] == null) delays[i] = frame - burst.startMs();
                    } else {
                        missed[i]++;
                    }
                }
            }
            if (scanner != null) {
                // A partial window can contain a hit but cannot establish silence.
                scanner.observe(tuned - 1, tick, detected, detected || !changed);
            }
        }
        List<Long> channelDwell = new ArrayList<>();
        for (long duration : dwell) channelDwell.add(duration);
        var detections = new ArrayList<Detection>();
        int totalCaptured = 0, totalMissed = 0;
        for (int i = 0; i < BURSTS.size(); i++) {
            detections.add(new Detection(delays[i], captured[i], missed[i]));
            totalCaptured += captured[i];
            totalMissed += missed[i];
        }
        int visited = (int) channelDwell.stream().filter(duration -> duration > 0).count();
        return new Run(List.copyOf(channelDwell), visited, retunes, retunes == 0 ? null : RETUNE_MS,
                totalCaptured, totalMissed, List.copyOf(detections));
    }
}
