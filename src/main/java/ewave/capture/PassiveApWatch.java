package ewave.capture;

import ewave.decoder.Dot11Frame;
import ewave.decoder.Dot11FrameDecoder;

import java.util.UUID;

/** Records one channel move for a single observed 2.4 GHz access point. */
final class PassiveApWatch {
    private final UUID id = UUID.randomUUID();
    private final String apId;
    private final String bssid;
    private final long startedAt;
    private final boolean adaptive;
    private final long[] firstTune = new long[14];
    private PacketBridge.ApWatchEvent lastHeard;
    private PacketBridge.ApWatchEvent tuned;
    private PacketBridge.ApWatchEvent heardAgain;
    private Long endedAt;

    PassiveApWatch(String apId, String bssid, boolean adaptive, long startedAt) {
        this.apId = apId;
        this.bssid = bssid;
        this.adaptive = adaptive;
        this.startedAt = startedAt;
    }

    UUID id() { return id; }
    boolean active() { return endedAt == null; }

    void observe(Dot11Frame frame) {
        if (!active() || !frame.apAdvertisement() || !bssid.equals(frame.addr2())
                || !bssid.equals(frame.addr3()) || (frame.capability() & 1) == 0) return;
        long at = frame.timestamp();
        if (at < startedAt || lastHeard != null && at <= lastHeard.timestamp()) return;
        int channel = Dot11FrameDecoder.channel(frame.frequencyMhz());
        Integer frequency = PacketBridge.channelFrequencyMhz(channel);
        if (frequency == null || frequency != frame.frequencyMhz()) return;

        // An adjacent-channel copy of a beacon must not look like an AP move.
        byte[] primary = frame.ies().first(3);
        if (primary.length == 1 && Byte.toUnsignedInt(primary[0]) != channel) return;
        byte[] ht = frame.ies().first(61);
        if (primary.length == 0 && ht.length >= 22 && Byte.toUnsignedInt(ht[0]) != channel) return;

        if (lastHeard == null || lastHeard.channel() == channel) {
            lastHeard = new PacketBridge.ApWatchEvent(channel, at);
            for (int ch = 1; ch < firstTune.length; ch++) {
                if (firstTune[ch] <= at) firstTune[ch] = 0;
            }
            return;
        }

        long confirmation = firstTune[channel];
        if (confirmation > lastHeard.timestamp() && confirmation <= at)
            tuned = new PacketBridge.ApWatchEvent(channel, confirmation);
        heardAgain = new PacketBridge.ApWatchEvent(channel, at);
        endedAt = at;
    }

    void tuneConfirmed(int channel, long at) {
        if (active() && lastHeard != null && channel != lastHeard.channel()
                && at > lastHeard.timestamp() && firstTune[channel] == 0) firstTune[channel] = at;
    }

    void stop(long at) {
        if (active()) endedAt = Math.max(at, lastHeard == null ? startedAt : lastHeard.timestamp());
    }

    PacketBridge.ApWatchRun snapshot() {
        return new PacketBridge.ApWatchRun(id, apId, adaptive, startedAt, endedAt, lastHeard, tuned, heardAgain);
    }
}
