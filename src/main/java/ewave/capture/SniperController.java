package ewave.capture;

import ewave.decoder.Dot11Frame;
import ewave.decoder.Dot11FrameDecoder;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

/** State machine for finding, locking onto, and following a target access point across channels. */
public final class SniperController {
    private static final int ALL_TWO_FOUR_CHANNELS_MASK = 0x3FFE; // bits 1..13
    private static final long MIN_SILENCE_NANOS = TimeUnit.MILLISECONDS.toNanos(3000);
    private static final long TU_NANOS = 1_024_000L; // 1 TU = 1024 microseconds
    private static final int SILENCE_BEACON_MULTIPLIER = 20;

    public enum State { IDLE, SEARCHING, SELECTING, LOCKED, LOST_SEARCHING }

    public record Candidate(String apId, String ssid, int channel, int frequencyMhz, Double rssi,
                            int beaconIntervalTu, long lastSeenAt) {}

    public record ChannelMove(int fromChannel, int fromFrequencyMhz, int toChannel, int toFrequencyMhz,
                              long lostAtMs, Long tunedAtMs, long rediscoveredAtMs) {}

    public record Snapshot(UUID id, State state, String targetSsid, String lockedApId, String lockedSsid,
                           Integer lockedChannel, Integer lockedFrequencyMhz, boolean initialSweepComplete,
                           int channelsSwept, List<Candidate> candidates,
                           PacketBridge.ApWatchEvent lastHeard, PacketBridge.ApWatchEvent tuned,
                           PacketBridge.ApWatchEvent heardAgain, List<ChannelMove> moves,
                           long startedAt, Long endedAt, boolean opsPaused) {}

    private static final class CandidateEntry {
        final String apId;
        final String bssid;
        String ssid;
        int channel;
        int frequencyMhz;
        Double rssi;
        int beaconIntervalTu;
        long lastSeenAt;

        CandidateEntry(String apId, String bssid, String ssid, int channel, int frequencyMhz,
                       Double rssi, int beaconIntervalTu, long lastSeenAt) {
            this.apId = apId;
            this.bssid = bssid;
            this.ssid = ssid;
            this.channel = channel;
            this.frequencyMhz = frequencyMhz;
            this.rssi = rssi;
            this.beaconIntervalTu = beaconIntervalTu > 0 ? beaconIntervalTu : 100;
            this.lastSeenAt = lastSeenAt;
        }

        Candidate toRecord() {
            return new Candidate(apId, ssid, channel, frequencyMhz, rssi, beaconIntervalTu, lastSeenAt);
        }
    }

    private final LongSupplier nanoClock;
    private final LongSupplier wallClock;

    private UUID id;
    private State state = State.IDLE;
    private byte[] targetSsidBytes;
    private String targetSsid;
    private String lockedBssid;
    private String lockedApId;
    private String lockedSsid;
    private Integer lockedChannel;
    private Integer lockedFrequencyMhz;
    private int lockedBeaconTu = 100;
    private int sweptMask;
    private boolean initialSweepComplete;
    private final Map<String, CandidateEntry> candidates = new LinkedHashMap<>();
    private final List<ChannelMove> moves = new ArrayList<>();
    private final long[] firstTune = new long[14];
    private PacketBridge.ApWatchEvent lastHeard;
    private PacketBridge.ApWatchEvent tuned;
    private PacketBridge.ApWatchEvent heardAgain;
    private long startedAt;
    private Long endedAt;
    private long lastHeardMonoNanos;
    private boolean opsPaused;
    private long opsPauseStartedNanos;
    private long lostAtMs;
    private int lostFromChannel;
    private int lostFromFreq;

    public SniperController() {
        this(System::nanoTime, System::currentTimeMillis);
    }

    SniperController(LongSupplier nanoClock, LongSupplier wallClock) {
        this.nanoClock = Objects.requireNonNull(nanoClock);
        this.wallClock = Objects.requireNonNull(wallClock);
    }

    public synchronized Snapshot startBySsid(byte[] ssidBytes, String displaySsid) {
        if (ssidBytes == null || ssidBytes.length == 0 || ssidBytes.length > 32) {
            throw new IllegalArgumentException("Enter a network name of 1–32 Wi-Fi bytes");
        }
        reset(State.SEARCHING);
        this.targetSsidBytes = ssidBytes.clone();
        this.targetSsid = displaySsid;
        return snapshot();
    }

    public synchronized Snapshot startByAp(String apId, String bssid, byte[] ssidBytes, String ssid,
                                           int channel, int frequencyMhz, int beaconIntervalTu, long lastSeenAt) {
        Objects.requireNonNull(apId, "apId");
        Objects.requireNonNull(bssid, "bssid");
        reset(channel > 0 && frequencyMhz > 0 ? State.LOCKED : State.SEARCHING);
        this.targetSsidBytes = ssidBytes == null ? null : ssidBytes.clone();
        this.targetSsid = ssid;
        this.lockedBssid = bssid;
        this.lockedApId = apId;
        this.lockedSsid = ssid;
        if (state == State.LOCKED) {
            this.lockedChannel = channel;
            this.lockedFrequencyMhz = frequencyMhz;
            this.lockedBeaconTu = beaconIntervalTu > 0 ? beaconIntervalTu : 100;
            this.lastHeard = new PacketBridge.ApWatchEvent(channel, lastSeenAt > 0 ? lastSeenAt : startedAt);
            this.lastHeardMonoNanos = nanoClock.getAsLong();
            if (opsPaused) opsPauseStartedNanos = this.lastHeardMonoNanos;
        }
        return snapshot();
    }

    public synchronized Snapshot selectCandidate(String apId) {
        if (state != State.SEARCHING && state != State.SELECTING) {
            throw new IllegalStateException("Sniper is not awaiting candidate selection.");
        }
        if (apId == null || apId.isBlank()) throw new IllegalArgumentException("Choose a matching access point.");
        CandidateEntry chosen = candidates.values().stream()
                .filter(entry -> entry.apId.equals(apId)).findFirst().orElse(null);
        if (chosen == null) throw new IllegalArgumentException("Selected AP is not among the search candidates.");
        lockCandidate(chosen);
        return snapshot();
    }

    public synchronized Snapshot cancel() {
        if (state != State.IDLE) {
            state = State.IDLE;
            endedAt = wallClock.getAsLong();
            sweptMask = 0;
            Arrays.fill(firstTune, 0);
        }
        return snapshot();
    }

    public synchronized void setOpsPaused(boolean paused) {
        if (paused == opsPaused) return;
        long nowMono = nanoClock.getAsLong();
        if (paused) {
            opsPaused = true;
            opsPauseStartedNanos = nowMono;
        } else {
            long pausedDuration = Math.max(0L, nowMono - opsPauseStartedNanos);
            lastHeardMonoNanos += pausedDuration;
            opsPaused = false;
        }
    }

    public synchronized void tuneConfirmed(int channel, int frequencyMhz, long atWallMs) {
        if (state == State.LOST_SEARCHING && channel >= 1 && channel < firstTune.length
                && frequencyMhz != lostFromFreq && firstTune[channel] == 0) {
            firstTune[channel] = atWallMs;
        }
    }

    public synchronized void sweepChannelFinished(int channel) {
        if (state != State.SEARCHING || channel < 1 || channel > 13) return;
        sweptMask |= (1 << channel);
        if ((sweptMask & ALL_TWO_FOUR_CHANNELS_MASK) == ALL_TWO_FOUR_CHANNELS_MASK) {
            initialSweepComplete = true;
        }
        if (initialSweepComplete) {
            evaluateSearchCandidates();
        }
    }

    public synchronized void observeFrame(Dot11Frame frame, String apId, String bssid,
                                          byte[] ssidBytes, String ssidName) {
        if (state == State.IDLE || state == State.SELECTING) return;
        if (!frame.apAdvertisement() || bssid == null || (frame.capability() & 1) == 0) return;
        int freq = frame.frequencyMhz();
        int channel = Dot11FrameDecoder.channel(freq);
        if (channel <= 0 || freq <= 0) return;

        // Ignore adjacent-channel bleed where advertised primary channel differs from receiver frequency.
        byte[] primary = frame.ies().first(3);
        if (primary.length == 1 && Byte.toUnsignedInt(primary[0]) != channel) return;
        byte[] ht = frame.ies().first(61);
        if (primary.length == 0 && ht.length >= 22 && Byte.toUnsignedInt(ht[0]) != channel) return;

        switch (state) {
            case SEARCHING -> {
                if (lockedBssid != null) {
                    if (lockedBssid.equalsIgnoreCase(bssid)) {
                        var entry = new CandidateEntry(apId, bssid, ssidName, channel, freq,
                                Double.isFinite(frame.rssi()) ? frame.rssi() : null,
                                frame.beaconIntervalTu(), frame.timestamp());
                        candidates.put(bssid, entry);
                        lockCandidate(entry);
                    }
                    return;
                }
                if (targetSsidBytes != null && Arrays.equals(targetSsidBytes, ssidBytes)) {
                    CandidateEntry existing = candidates.get(bssid);
                    Double rssi = Double.isFinite(frame.rssi()) ? Double.valueOf(frame.rssi())
                            : (existing == null ? null : existing.rssi);
                    int tu = frame.beaconIntervalTu() > 0 ? frame.beaconIntervalTu()
                            : (existing == null ? 100 : existing.beaconIntervalTu);
                    candidates.put(bssid, new CandidateEntry(apId, bssid,
                            ssidName != null ? ssidName : (existing == null ? null : existing.ssid),
                            channel, freq, rssi, tu, frame.timestamp()));
                }
            }
            case LOCKED -> {
                if (!lockedBssid.equalsIgnoreCase(bssid)) return;
                long nowMono = nanoClock.getAsLong();
                long prevLastHeardAt = lastHeard != null ? lastHeard.timestamp() : frame.timestamp();
                if (opsPaused) opsPauseStartedNanos = nowMono;
                lastHeardMonoNanos = nowMono;
                lastHeard = new PacketBridge.ApWatchEvent(channel, frame.timestamp());
                if (frame.beaconIntervalTu() > 0) lockedBeaconTu = frame.beaconIntervalTu();
                if (ssidName != null) lockedSsid = ssidName;
                if (lockedFrequencyMhz != null && freq != lockedFrequencyMhz) {
                    int prevCh = lockedChannel;
                    int prevFreq = lockedFrequencyMhz;
                    lockedChannel = channel;
                    lockedFrequencyMhz = freq;
                    this.tuned = null;
                    this.heardAgain = new PacketBridge.ApWatchEvent(channel, frame.timestamp());
                    moves.add(new ChannelMove(prevCh, prevFreq, channel, freq,
                            prevLastHeardAt, null, frame.timestamp()));
                }
            }
            case LOST_SEARCHING -> {
                if (!lockedBssid.equalsIgnoreCase(bssid)) return;
                if (lastHeard != null && frame.timestamp() < lastHeard.timestamp()) return;
                state = State.LOCKED;
                lockedChannel = channel;
                lockedFrequencyMhz = freq;
                if (frame.beaconIntervalTu() > 0) lockedBeaconTu = frame.beaconIntervalTu();
                if (ssidName != null) lockedSsid = ssidName;
                long nowMono = nanoClock.getAsLong();
                if (opsPaused) opsPauseStartedNanos = nowMono;
                lastHeardMonoNanos = nowMono;
                lastHeard = new PacketBridge.ApWatchEvent(channel, frame.timestamp());
                if (freq != lostFromFreq) {
                    long confirmation = channel >= 1 && channel < firstTune.length ? firstTune[channel] : 0;
                    PacketBridge.ApWatchEvent tuneEvent = confirmation > lostAtMs && confirmation <= frame.timestamp()
                            ? new PacketBridge.ApWatchEvent(channel, confirmation) : null;
                    this.tuned = tuneEvent;
                    this.heardAgain = new PacketBridge.ApWatchEvent(channel, frame.timestamp());
                    moves.add(new ChannelMove(lostFromChannel, lostFromFreq, channel, freq, lostAtMs,
                            tuneEvent == null ? null : tuneEvent.timestamp(), frame.timestamp()));
                }
            }
            default -> { }
        }
    }

    public synchronized boolean tick() {
        if (state != State.LOCKED || opsPaused) return false;
        long thresholdNanos = silenceThresholdNanos(lockedBeaconTu);
        if (nanoClock.getAsLong() - lastHeardMonoNanos > thresholdNanos) {
            state = State.LOST_SEARCHING;
            lostAtMs = wallClock.getAsLong();
            lostFromChannel = lockedChannel == null ? 0 : lockedChannel;
            lostFromFreq = lockedFrequencyMhz == null ? 0 : lockedFrequencyMhz;
            Arrays.fill(firstTune, 0);
            return true;
        }
        return false;
    }

    static long silenceThresholdNanos(int beaconIntervalTu) {
        long tu = Math.max(100, beaconIntervalTu);
        return Math.max(MIN_SILENCE_NANOS, tu * TU_NANOS * SILENCE_BEACON_MULTIPLIER);
    }

    public synchronized Integer desiredFrequencyMhz() {
        return state == State.LOCKED ? lockedFrequencyMhz : null;
    }

    public synchronized boolean needsSweep() {
        return state == State.SEARCHING || state == State.LOST_SEARCHING;
    }

    public synchronized State state() { return state; }

    public synchronized Snapshot snapshot() {
        var candidateList = candidates.values().stream().map(CandidateEntry::toRecord).toList();
        return new Snapshot(id, state, targetSsid, lockedApId, lockedSsid, lockedChannel, lockedFrequencyMhz,
                initialSweepComplete, Integer.bitCount(sweptMask & ALL_TWO_FOUR_CHANNELS_MASK),
                candidateList, lastHeard, tuned, heardAgain, List.copyOf(moves), startedAt, endedAt, opsPaused);
    }

    private void reset(State initialState) {
        this.id = UUID.randomUUID();
        this.state = initialState;
        this.targetSsidBytes = null;
        this.targetSsid = null;
        this.lockedBssid = null;
        this.lockedApId = null;
        this.lockedSsid = null;
        this.lockedChannel = null;
        this.lockedFrequencyMhz = null;
        this.lockedBeaconTu = 100;
        this.sweptMask = 0;
        this.initialSweepComplete = false;
        this.candidates.clear();
        this.moves.clear();
        Arrays.fill(this.firstTune, 0);
        this.lastHeard = null;
        this.tuned = null;
        this.heardAgain = null;
        this.startedAt = wallClock.getAsLong();
        this.endedAt = null;
        this.lastHeardMonoNanos = nanoClock.getAsLong();
        this.lostAtMs = 0;
        this.lostFromChannel = 0;
        this.lostFromFreq = 0;
    }

    private void evaluateSearchCandidates() {
        if (candidates.size() == 1) {
            lockCandidate(candidates.values().iterator().next());
        } else if (candidates.size() > 1) {
            state = State.SELECTING;
        }
    }

    private void lockCandidate(CandidateEntry entry) {
        this.state = State.LOCKED;
        this.lockedBssid = entry.bssid;
        this.lockedApId = entry.apId;
        this.lockedSsid = entry.ssid;
        this.lockedChannel = entry.channel;
        this.lockedFrequencyMhz = entry.frequencyMhz;
        this.lockedBeaconTu = entry.beaconIntervalTu;
        this.lastHeard = new PacketBridge.ApWatchEvent(entry.channel, entry.lastSeenAt);
        this.lastHeardMonoNanos = nanoClock.getAsLong();
        if (opsPaused) this.opsPauseStartedNanos = this.lastHeardMonoNanos;
    }
}
