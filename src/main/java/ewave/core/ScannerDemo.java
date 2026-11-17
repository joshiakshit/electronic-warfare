package ewave.core;

import ewave.capture.PassiveChannelSurvey;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import static java.util.concurrent.TimeUnit.MILLISECONDS;

/** A scripted RF fixture evaluated by the production adaptive scanner. */
public final class ScannerDemo {
    private static final int CHANNELS = 13;
    private static final int TICK_MS = 100;
    private static final int DURATION_MS = 12_000;
    private static final int FIXED_CHANNEL = 6;
    private static final int RETUNE_MS = 25;
    private static final int FRAME_INTERVAL_MS = 50;
    static final List<Burst> BURSTS = List.of(
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
                             int frameIntervalMs, List<Burst> bursts, Run adaptive, Run fixed, Run roundRobin) {}

    public static Comparison compare() {
        return new Comparison(DURATION_MS, TICK_MS, FIXED_CHANNEL, RETUNE_MS, FRAME_INTERVAL_MS,
                BURSTS, simulate(BURSTS, RETUNE_MS, adaptive(new PassiveChannelSurvey())),
                simulate(BURSTS, RETUNE_MS, fixed()), simulate(BURSTS, RETUNE_MS, roundRobin()));
    }

    // Receiver callbacks have no access to the fixture or missed transmissions.
    interface Receiver {
        int choose(int startMs, int current);
        default void arrived(int timeMs, int channel, int costMs) {}
        default void frame(int timeMs, int channel) {}
        default void window(int tick, int channel, boolean hit, boolean full, boolean listeningAtEnd) {}
    }

    static Receiver fixed() { return (now, current) -> FIXED_CHANNEL; }
    static Receiver roundRobin() { return (now, current) -> current % CHANNELS + 1; }

    static Receiver adaptive(PassiveChannelSurvey survey) {
        return new Receiver() {
            public int choose(int startMs, int current) {
                return survey.channel(MILLISECONDS.toNanos(startMs));
            }
            public void arrived(int timeMs, int channel, int costMs) {
                survey.tuneFinished(MILLISECONDS.toNanos(timeMs), channel, true, MILLISECONDS.toNanos(costMs));
            }
            public void frame(int timeMs, int channel) {
                survey.frame(MILLISECONDS.toNanos(timeMs), channel);
            }
        };
    }

    private record Transmission(int time, int burstIndex) {}

    static Run simulate(List<Burst> bursts, int cost, Receiver receiver) {
        return simulate(bursts, cost, receiver, true);
    }

    static Run simulate(List<Burst> bursts, int cost, Receiver receiver, boolean alreadyTuned) {
        if (cost < 0) throw new IllegalArgumentException("Negative tune cost");
        var frames = new ArrayList<Transmission>();
        for (int i = 0; i < bursts.size(); i++) {
            Burst b = bursts.get(i);
            for (int t = b.startMs(); t < b.endMs(); t += FRAME_INTERVAL_MS) {
                frames.add(new Transmission(t, i));
            }
        }
        frames.sort(Comparator.comparingInt(Transmission::time));
        int nextFrame = 0;
        long[] dwell = new long[CHANNELS];
        Integer[] delays = new Integer[bursts.size()];
        int[] captured = new int[bursts.size()];
        int[] missed = new int[bursts.size()];
        int tuned = alreadyTuned ? FIXED_CHANNEL : 0;
        int retunes = 0, readyAt = 0;
        if (alreadyTuned) receiver.arrived(0, tuned, 0);
        for (int start = 0; start < DURATION_MS; start += TICK_MS) {
            int end = start + TICK_MS;
            if (start != 0 && readyAt == start) receiver.arrived(start, tuned, cost);
            if (start != 0 && start >= readyAt) {
                int chosen = receiver.choose(start, tuned);
                if (chosen != tuned) {
                    retunes++;
                    tuned = chosen;
                    readyAt = start + cost;
                    if (cost == 0) receiver.arrived(start, tuned, cost);
                }
            }
            if (readyAt > start && readyAt < end) {
                receiver.arrived(readyAt, tuned, cost);
            }
            if (tuned != 0) dwell[tuned - 1] += Math.max(0, end - Math.max(start, readyAt));
            boolean detected = false;
            while (nextFrame < frames.size() && frames.get(nextFrame).time() < end) {
                Transmission frame = frames.get(nextFrame++);
                int i = frame.burstIndex();
                Burst burst = bursts.get(i);
                if (tuned == burst.channel() && frame.time() >= readyAt) {
                    detected = true;
                    captured[i]++;
                    receiver.frame(frame.time(), tuned);
                    if (delays[i] == null) delays[i] = frame.time() - burst.startMs();
                } else {
                    missed[i]++;
                }
            }
            if (tuned != 0) receiver.window(start / TICK_MS, tuned, detected, readyAt <= start, readyAt < end);
        }
        List<Long> channelDwell = new ArrayList<>();
        for (long duration : dwell) channelDwell.add(duration);
        var detections = new ArrayList<Detection>();
        int totalCaptured = 0, totalMissed = 0;
        for (int i = 0; i < bursts.size(); i++) {
            detections.add(new Detection(delays[i], captured[i], missed[i]));
            totalCaptured += captured[i];
            totalMissed += missed[i];
        }
        int visited = (int) channelDwell.stream().filter(duration -> duration > 0).count();
        return new Run(List.copyOf(channelDwell), visited, retunes, retunes == 0 ? null : cost,
                totalCaptured, totalMissed, List.copyOf(detections));
    }
}
