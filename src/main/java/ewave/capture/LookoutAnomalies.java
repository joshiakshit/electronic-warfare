package ewave.capture;

import ewave.core.AdaptiveScanner.AnomalyFlag;
import ewave.decoder.Dot11Frame;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** Session-local receive evidence. The capture lock serializes all calls. */
final class LookoutAnomalies {
    private static final long FLOOD_WINDOW = TimeUnit.SECONDS.toNanos(1);
    private static final long HOLD_WINDOW = TimeUnit.SECONDS.toNanos(15);
    private static final int HISTORY_LIMIT = 32;
    private static final int BEACON_THRESHOLD_WITH_FLAG = 40;
    private static final int BEACON_THRESHOLD_STANDALONE = 50;

    private final List<RadioStatus.Channel> channels;
    private final FrameCounts[] counts;
    private final Episode[] held;
    private final ArrayDeque<Episode> recent = new ArrayDeque<>();

    LookoutAnomalies(List<RadioStatus.Channel> channels) {
        this.channels = channels;
        counts = new FrameCounts[channels.size()];
        Arrays.setAll(counts, ignored -> new FrameCounts());
        held = new Episode[channels.size()];
    }

    boolean observeFrame(int slot, Dot11Frame frame, long now) {
        var frames = counts[slot];
        if (frame.management() && (frame.subtype() == 10 || frame.subtype() == 12)) {
            frames.deauthDisassoc.add(now);
            return frames.deauthDisassoc.reached(now);
        } else if (frame.management() && frame.subtype() == 8) {
            frames.beacons.add(now);
            return frames.beacons.reached(now);
        } else if (frame.type() == 2) {
            frames.data.add(now);
        }
        return false;
    }

    void update(int slot, AnomalyFlag flag, long now, Instant wallTime) {
        var flood = counts[slot].floodAt(now, flag != null);
        var episode = held[slot];
        if (flag == null && flood != FloodType.DEAUTH_FLOOD && flood != FloodType.BEACON_FLOOD) {
            if (episode != null) {
                episode.activeNow = false;
                if (!episode.visibleAt(now)) held[slot] = null;
            }
            return;
        }
        if (episode == null || !episode.activeNow) {
            episode = new Episode(channels.get(slot), flag == null ? wallTime : flag.detectedAt());
            held[slot] = episode;
            recent.addFirst(episode);
            if (recent.size() > HISTORY_LIMIT) recent.removeLast();
        }
        episode.update(flag, flood, now, wallTime);
    }

    PacketBridge.HeldAnomaly onChannel(int slot, long now) {
        var episode = held[slot];
        return episode != null && episode.visibleAt(now) ? episode.snapshot() : null;
    }

    List<PacketBridge.HeldAnomaly> recent(long now) {
        return recent.stream().filter(episode -> episode.visibleAt(now)).map(Episode::snapshot).toList();
    }

    private enum FloodType { DEAUTH_FLOOD, BEACON_FLOOD, DATA_BURST }

    private static final class FrameCounts {
        final ThresholdWindow deauthDisassoc = new ThresholdWindow(8);
        final ThresholdWindow beacons = new ThresholdWindow(BEACON_THRESHOLD_STANDALONE);
        final ThresholdWindow data = new ThresholdWindow(30);

        FloodType floodAt(long now, boolean scannerFlag) {
            if (deauthDisassoc.reached(now)) return FloodType.DEAUTH_FLOOD;
            int beaconThreshold = scannerFlag ? BEACON_THRESHOLD_WITH_FLAG : BEACON_THRESHOLD_STANDALONE;
            if (beacons.reached(now, beaconThreshold)) return FloodType.BEACON_FLOOD;
            return data.reached(now) ? FloodType.DATA_BURST : null;
        }
    }

    // Retain enough timestamps for the highest threshold checked against this window.
    private static final class ThresholdWindow {
        final long[] arrivals;
        int cursor, size;

        ThresholdWindow(int threshold) { arrivals = new long[threshold]; }

        void add(long now) {
            arrivals[cursor] = now;
            cursor = (cursor + 1) % arrivals.length;
            if (size < arrivals.length) size++;
        }

        boolean reached(long now) {
            return reached(now, arrivals.length);
        }

        boolean reached(long now, int threshold) {
            int oldest = Math.floorMod(cursor - threshold, arrivals.length);
            return size >= threshold && now - arrivals[oldest] < FLOOD_WINDOW;
        }
    }

    private static final class Episode {
        final RadioStatus.Channel channel;
        final Instant detectedAt;
        Instant lastActiveAt;
        long lastActiveNanos;
        String reason;
        double deviation;
        FloodType currentFlood, lastFlood;
        boolean activeNow;

        Episode(RadioStatus.Channel channel, Instant detectedAt) {
            this.channel = channel;
            this.detectedAt = detectedAt;
        }

        void update(AnomalyFlag flag, FloodType observedFlood, long now, Instant wallTime) {
            if (flag != null) {
                reason = flag.reason();
                deviation = flag.deviation();
            } else {
                reason = observedFlood.name();
                deviation = 0;
            }
            currentFlood = observedFlood;
            if (observedFlood != null) lastFlood = observedFlood;
            lastActiveNanos = now;
            lastActiveAt = wallTime.isBefore(detectedAt) ? detectedAt : wallTime;
            activeNow = true;
        }

        boolean visibleAt(long now) {
            return activeNow || now - lastActiveNanos < HOLD_WINDOW;
        }

        PacketBridge.HeldAnomaly snapshot() {
            var flood = activeNow ? currentFlood : lastFlood;
            return new PacketBridge.HeldAnomaly(channel.channel(), channel.frequencyMhz(), deviation,
                    detectedAt, lastActiveAt, reason, flood == null ? null : flood.name(), activeNow);
        }
    }
}
