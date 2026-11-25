package ewave.capture;

import ewave.decoder.Dot11ChannelSwitchDecoder;
import ewave.decoder.Dot11Frame;
import ewave.decoder.Dot11FrameDecoder;
import ewave.decoder.Dot11InformationElements;
import ewave.decoder.IeSignature;
import ewave.decoder.SecurityDecoder;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;
import java.util.function.UnaryOperator;

/** State machine for finding, locking onto, and following a target access point across channels. */
public final class SniperController {
    private static final long MIN_SILENCE_NANOS = TimeUnit.MILLISECONDS.toNanos(3000);
    private static final long MIN_SWITCH_VERIFY_NANOS = TimeUnit.MILLISECONDS.toNanos(600);
    private static final long RECENT_HEARD_NANOS = TimeUnit.MILLISECONDS.toNanos(1500);
    private static final long MAX_CLOCK_DRIFT_US = 5_000_000L;
    private static final long TU_NANOS = 1_024_000L;
    private static final int SILENCE_BEACON_MULTIPLIER = 20;
    private static final int MAX_AFFILIATED_LINKS = 256;

    public enum State { IDLE, SEARCHING, SELECTING, LOCKED, LOST_SEARCHING }
    public enum MoveTrigger { CSA, SILENCE_SWEEP, HEURISTIC_BSSID_ROTATION, AFFILIATED_LINK_SWITCH, OBSERVED }

    public record Candidate(String apId, String ssid, int channel, int frequencyMhz, Double rssi,
                            int beaconIntervalTu, long lastSeenAt) {}

    public record ChannelMove(int fromChannel, int fromFrequencyMhz, int toChannel, int toFrequencyMhz,
                              long lostAtMs, Long tunedAtMs, long rediscoveredAtMs, MoveTrigger trigger) {
        public ChannelMove(int fromChannel, int fromFrequencyMhz, int toChannel, int toFrequencyMhz,
                           long lostAtMs, Long tunedAtMs, long rediscoveredAtMs) {
            this(fromChannel, fromFrequencyMhz, toChannel, toFrequencyMhz,
                    lostAtMs, tunedAtMs, rediscoveredAtMs, MoveTrigger.SILENCE_SWEEP);
        }
    }

    public record PendingChannelSwitch(int channel, int frequencyMhz, long scheduledAtMs, Long tunedAtMs) {}

    public record AffiliatedLink(Integer linkId, String apId, int channel, int frequencyMhz, String band,
                                 boolean supported) {}

    public record Snapshot(UUID id, State state, String targetSsid, String lockedApId, String lockedSsid,
                           Integer lockedChannel, Integer lockedFrequencyMhz, boolean initialSweepComplete,
                           int channelsSwept, int sweepChannelCount, int unavailableSweepChannels, List<Candidate> candidates,
                           PacketBridge.ApWatchEvent lastHeard, PacketBridge.ApWatchEvent tuned,
                           PacketBridge.ApWatchEvent heardAgain, List<ChannelMove> moves,
                           long startedAt, Long endedAt, boolean opsPaused, Integer activeSweepChannel,
                           Integer activeSweepFrequencyMhz, PendingChannelSwitch pendingChannelSwitch,
                           long decoyFramesIgnored, long spoofWarnings, String mldId,
                           List<AffiliatedLink> affiliatedLinks, boolean bssidRotated,
                           Integer pendingAffiliatedLinkFrequencyMhz) {}

    private record CandidateEntry(String bssid, Candidate view, Dot11Frame frame) {}

    private record LinkEvidence(Integer linkId, String bssid, int frequencyMhz) {}

    private static final class PendingTune {
        final int frequency;
        final String bssid;
        final long scheduledAtNanos;
        final long scheduledAtMs;
        final MoveTrigger trigger;
        Long tunedAtMs;
        long verifyByNanos;

        PendingTune(int frequency, String bssid, long scheduledAtNanos, long scheduledAtMs, MoveTrigger trigger) {
            this.frequency = frequency;
            this.bssid = bssid;
            this.scheduledAtNanos = scheduledAtNanos;
            this.scheduledAtMs = scheduledAtMs;
            this.trigger = trigger;
        }
    }

    private final LongSupplier nanoClock;
    private final LongSupplier wallClock;
    private final UnaryOperator<String> addressTokenizer;
    private UUID id;
    private State state = State.IDLE;
    private byte[] targetSsidBytes;
    private Integer targetShortSsid;
    private String targetSsid;
    private String lockedBssid;
    private String lockedApId;
    private String lockedSsid;
    private Integer lockedChannel;
    private Integer lockedFrequencyMhz;
    private int lockedBeaconTu = 100;
    private boolean lockedProtected;
    private Long lastBeaconTsf;
    private long lastBeaconAt;
    private String lockedCapabilityCohort;
    private Integer lockedLinkId;
    private String mldMac;
    private final Map<String, LinkEvidence> links = new LinkedHashMap<>();
    private final Set<Integer> rnrHints = new HashSet<>();
    private PendingTune pendingTune;
    private Long returnGraceUntilNanos;
    private long decoyFramesIgnored;
    private long spoofWarnings;
    private boolean bssidRotated;
    private Set<Integer> sweepFrequencies = Set.copyOf(
            RadioStatus.FALLBACK_CHANNELS.stream().map(RadioStatus.Channel::frequencyMhz).toList());
    private final Set<Integer> swept = new HashSet<>();
    private final Set<Integer> unavailable = new HashSet<>();
    private final Set<Integer> lostPass = new HashSet<>();
    private boolean lostPassCompleteCoverage = true;
    private boolean lostPassHeardOriginal;
    private Integer activeSweepFrequency;
    private boolean initialSweepComplete;
    private final Map<String, CandidateEntry> candidates = new LinkedHashMap<>();
    private final List<ChannelMove> moves = new ArrayList<>();
    private final Map<Integer, Long> firstTune = new HashMap<>();
    private PacketBridge.ApWatchEvent lastHeard;
    private PacketBridge.ApWatchEvent tuned;
    private PacketBridge.ApWatchEvent heardAgain;
    private long startedAt;
    private Long endedAt;
    private long lastHeardMonoNanos;
    private boolean opsPaused;
    private long opsPauseStartedNanos;
    private long lostAtMs;
    private int lostFromFreq;

    public SniperController() {
        this(System::nanoTime, System::currentTimeMillis);
    }

    SniperController(UnaryOperator<String> addressTokenizer) {
        this(System::nanoTime, System::currentTimeMillis, addressTokenizer);
    }

    SniperController(LongSupplier nanoClock, LongSupplier wallClock) {
        this(nanoClock, wallClock, UnaryOperator.identity());
    }

    SniperController(LongSupplier nanoClock, LongSupplier wallClock, UnaryOperator<String> addressTokenizer) {
        this.nanoClock = Objects.requireNonNull(nanoClock);
        this.wallClock = Objects.requireNonNull(wallClock);
        this.addressTokenizer = Objects.requireNonNull(addressTokenizer);
    }

    synchronized void useSweepChannels(List<RadioStatus.Channel> channels) {
        sweepFrequencies = Set.copyOf(channels.stream().map(RadioStatus.Channel::frequencyMhz).toList());
    }

    public synchronized Snapshot startBySsid(byte[] ssidBytes, String displaySsid) {
        if (ssidBytes == null || ssidBytes.length == 0 || ssidBytes.length > 32) {
            throw new IllegalArgumentException("Enter a network name of 1–32 Wi-Fi bytes");
        }
        reset(State.SEARCHING);
        initialSweepComplete = sweepFrequencies.isEmpty();
        setTargetSsidBytes(ssidBytes);
        targetSsid = displaySsid;
        return snapshot();
    }

    public synchronized Snapshot startByAp(String apId, String bssid, byte[] ssidBytes, String ssid,
                                           int channel, int frequencyMhz, int beaconIntervalTu, long lastSeenAt) {
        return startByAp(apId, bssid, ssidBytes, ssid, channel, frequencyMhz, beaconIntervalTu, lastSeenAt, null);
    }

    synchronized Snapshot startByAp(String apId, String bssid, byte[] ssidBytes, String ssid,
                                     int channel, int frequencyMhz, int beaconIntervalTu, long lastSeenAt,
                                     Dot11Frame advertisement) {
        Objects.requireNonNull(apId, "apId");
        Objects.requireNonNull(bssid, "bssid");
        reset(channel > 0 && frequencyMhz > 0 ? State.LOCKED : State.SEARCHING);
        setTargetSsidBytes(ssidBytes);
        targetSsid = ssid;
        lockedBssid = bssid;
        lockedApId = apId;
        lockedSsid = ssid;
        if (state == State.LOCKED) {
            lockedChannel = channel;
            lockedFrequencyMhz = frequencyMhz;
            lockedBeaconTu = beaconIntervalTu > 0 ? beaconIntervalTu : 100;
            refreshLastHeard(lastSeenAt > 0 ? lastSeenAt : startedAt);
            if (advertisement != null) rememberAdvertisement(advertisement, ssid);
        }
        return snapshot();
    }

    public synchronized Snapshot selectCandidate(String apId) {
        if (state != State.SEARCHING && state != State.SELECTING) {
            throw new IllegalStateException("Sniper is not awaiting candidate selection.");
        }
        if (apId == null || apId.isBlank()) throw new IllegalArgumentException("Choose a matching access point.");
        CandidateEntry chosen = candidates.values().stream()
                .filter(entry -> entry.view.apId().equals(apId)).findFirst().orElse(null);
        if (chosen == null) throw new IllegalArgumentException("Selected AP is not among the search candidates.");
        if (state == State.SELECTING && lostFromFreq != 0) rotateBssid(chosen);
        else lockCandidate(chosen);
        return snapshot();
    }

    synchronized void switchAffiliatedLink(int frequency) {
        if (state != State.LOCKED || opsPaused) {
            throw new IllegalStateException("Lock onto an AP while passive capture owns the receiver.");
        }
        if (!sweepFrequencies.contains(frequency) || frequency == lockedFrequencyMhz) {
            throw new IllegalArgumentException("Choose a different supported affiliated frequency.");
        }
        var matches = links.values().stream().filter(link -> link.frequencyMhz == frequency).toList();
        if (matches.size() != 1) {
            throw new IllegalArgumentException("Choose a frequency with one advertised affiliated link.");
        }
        if (pendingTune != null && (pendingTune.tunedAtMs != null
                || pendingTune.trigger == MoveTrigger.AFFILIATED_LINK_SWITCH)) {
            throw new IllegalStateException("Sniper is verifying a channel change.");
        }
        pendingTune = new PendingTune(frequency, matches.getFirst().bssid, nanoClock.getAsLong(),
                wallClock.getAsLong(), MoveTrigger.AFFILIATED_LINK_SWITCH);
    }

    public synchronized Snapshot cancel() {
        if (state != State.IDLE) {
            state = State.IDLE;
            endedAt = wallClock.getAsLong();
            swept.clear();
            unavailable.clear();
            firstTune.clear();
            activeSweepFrequency = null;
            pendingTune = null;
        }
        return snapshot();
    }

    public synchronized void setOpsPaused(boolean paused) {
        if (paused == opsPaused) return;
        long nowMono = nanoClock.getAsLong();
        if (paused) {
            opsPaused = true;
            opsPauseStartedNanos = nowMono;
            receiverInterrupted();
        } else {
            long pausedDuration = Math.max(0L, nowMono - opsPauseStartedNanos);
            lastHeardMonoNanos += pausedDuration;
            if (returnGraceUntilNanos != null) returnGraceUntilNanos += pausedDuration;
            opsPaused = false;
        }
    }

    synchronized void receiverInterrupted() {
        activeSweepFrequency = null;
        if (pendingTune != null) pendingTune.tunedAtMs = null;
        resetLostPass();
    }

    public synchronized void tuneConfirmed(int channel, int frequencyMhz, long atWallMs) {
        if (opsPaused) return;
        if (state == State.LOST_SEARCHING && channel > 0 && frequencyMhz != lostFromFreq) {
            firstTune.putIfAbsent(frequencyMhz, atWallMs);
        }
        if (pendingTune != null && pendingTune.frequency == frequencyMhz && pendingTune.tunedAtMs == null
                && nanoClock.getAsLong() - pendingTune.scheduledAtNanos >= 0) {
            pendingTune.tunedAtMs = atWallMs;
            pendingTune.verifyByNanos = nanoClock.getAsLong() + verificationWindow();
        }
    }

    synchronized void tuneFailed(int frequency) {
        if (pendingTune != null && pendingTune.frequency == frequency) returnToLockedFrequency();
    }

    synchronized UUID runId() { return id; }

    synchronized int lostSweepOrigin() { return state == State.LOST_SEARCHING ? lostFromFreq : 0; }

    synchronized Set<Integer> prioritySweepFrequencies() {
        var frequencies = new HashSet<>(rnrHints);
        for (LinkEvidence link : links.values()) frequencies.add(link.frequencyMhz);
        return frequencies;
    }

    synchronized void setActiveSweepFrequency(Integer frequency) {
        activeSweepFrequency = needsSweep() && !opsPaused ? frequency : null;
    }

    public synchronized void sweepChannelFinished(int channel) {
        Integer frequency = PacketBridge.channelFrequencyMhz(channel);
        if (frequency != null) sweepFrequencyFinished(frequency, true);
    }

    synchronized void sweepFrequencyFinished(int frequency, boolean listened) {
        if (!sweepFrequencies.contains(frequency)) return;
        if (state == State.LOST_SEARCHING) {
            if (!lostPass.add(frequency)) return;
            lostPassCompleteCoverage &= listened;
            if (lostPass.size() == sweepFrequencies.size()) {
                boolean canRotate = lostPassCompleteCoverage && !lostPassHeardOriginal;
                if (canRotate && candidates.size() == 1) {
                    rotateBssid(candidates.values().iterator().next());
                } else if (canRotate && candidates.size() > 1) {
                    state = State.SELECTING;
                    activeSweepFrequency = null;
                } else {
                    resetLostPass();
                }
            }
            return;
        }
        if (state != State.SEARCHING) return;
        if (listened) {
            swept.add(frequency);
            unavailable.remove(frequency);
        } else if (!swept.contains(frequency)) {
            unavailable.add(frequency);
        }
        if (swept.size() + unavailable.size() == sweepFrequencies.size()) initialSweepComplete = true;
        if (initialSweepComplete) evaluateSearchCandidates();
    }

    private void resetLostPass() {
        if (state != State.LOST_SEARCHING) return;
        lostPass.clear();
        lostPassCompleteCoverage = true;
        lostPassHeardOriginal = false;
        candidates.clear();
    }

    public synchronized void observeFrame(Dot11Frame frame, String apId, String bssid,
                                          byte[] ssidBytes, String ssidName) {
        if (state == State.IDLE || state == State.SELECTING || opsPaused) return;
        if (!frame.apAdvertisement() || bssid == null || (frame.capability() & 1) == 0) return;
        int frequency = frame.frequencyMhz();
        int channel = Dot11FrameDecoder.channel(frequency);
        if (channel <= 0 || frame.ies() == null) return;

        // Reject adjacent-channel bleed before treating the receiver frequency as the AP's channel.
        byte[] primary = frame.ies().first(3);
        if (primary.length == 1 && Byte.toUnsignedInt(primary[0]) != channel) return;
        byte[] ht = frame.ies().first(61);
        if (primary.length == 0 && ht.length >= 22 && Byte.toUnsignedInt(ht[0]) != channel) return;

        boolean sameBssid = bssid.equalsIgnoreCase(lockedBssid);
        boolean sameSsid = targetSsidBytes != null && Arrays.equals(targetSsidBytes, ssidBytes);
        switch (state) {
            case SEARCHING -> {
                rememberSweepHints(frame, sameBssid || sameSsid, bssid);
                if (lockedBssid != null ? sameBssid : sameSsid) {
                    var entry = recordCandidate(frame, apId, bssid, ssidName, channel);
                    if (lockedBssid != null) lockCandidate(entry);
                    else if (initialSweepComplete) evaluateSearchCandidates();
                }
            }
            case LOCKED -> {
                if (observePendingDestination(frame, apId, bssid, ssidName, channel)) return;
                if (sameBssid) observeLockedAdvertisement(frame, ssidName, channel);
            }
            case LOST_SEARCHING -> {
                if (sameBssid) {
                    if (rejectDowngrade(frame) || olderThanLastHeard(frame)) return;
                    reacquire(frame, ssidName, channel);
                } else {
                    rememberSweepHints(frame, sameSsid, bssid);
                    if (sweepFrequencies.contains(frequency) && rotationCandidate(frame, bssid)) {
                        recordCandidate(frame, apId, bssid, ssidName, channel);
                    }
                }
            }
            default -> { }
        }
    }

    public synchronized void observeTransmitterActivity(Dot11Frame frame) {
        if ((state != State.LOCKED && state != State.LOST_SEARCHING) || opsPaused
                || !lockedBssid.equalsIgnoreCase(frame.addr2()) || olderThanLastHeard(frame)) return;
        boolean apData = frame.type() == 2 && frame.ds() == 2;
        boolean apManagement = frame.management() && !frame.apAdvertisement()
                && lockedBssid.equalsIgnoreCase(frame.addr3());
        if (!apData && !apManagement) return;

        int frequency = frame.frequencyMhz();
        if (state == State.LOCKED && frequency == lockedFrequencyMhz) {
            refreshLastHeard(frame.timestamp());
        } else if (state == State.LOST_SEARCHING && sweepFrequencies.contains(frequency) && frame.timestamp() >= lostAtMs) {
            lostPassHeardOriginal = true;
        }
    }

    private void observeLockedAdvertisement(Dot11Frame frame, String ssid, int channel) {
        if (rejectDowngrade(frame) || olderThanLastHeard(frame)) return;
        int frequency = frame.frequencyMhz();
        if (frequency != lockedFrequencyMhz) {
            if (pendingTune != null && pendingTune.frequency == frequency) return;
            if (nanoClock.getAsLong() - lastHeardMonoNanos <= RECENT_HEARD_NANOS && !plausibleTsf(frame)) {
                decoyFramesIgnored++;
                return;
            }
            if (pendingTune != null && pendingTune.tunedAtMs != null) return;
            recordMove(channel, frequency, lastHeard.timestamp(), null, frame.timestamp(), MoveTrigger.OBSERVED);
            pendingTune = null;
        } else if (pendingTune == null || pendingTune.tunedAtMs == null) {
            var announcement = Dot11ChannelSwitchDecoder.decodeChannelSwitch(frame.ies(), frequency);
            if (announcement != null && announcement.frequencyMhz() != frequency
                    && sweepFrequencies.contains(announcement.frequencyMhz())
                    && (pendingTune == null || pendingTune.trigger == MoveTrigger.CSA)) {
                scheduleCsa(announcement, frame.beaconIntervalTu());
            }
        }
        refreshLastHeard(frame.timestamp());
        rememberAdvertisement(frame, ssid);
    }

    private void scheduleCsa(Dot11ChannelSwitchDecoder.ChannelSwitch announcement, int beaconIntervalTu) {
        int interval = beaconIntervalTu > 0 ? beaconIntervalTu : lockedBeaconTu;
        long delay = Math.max(0, announcement.switchCount() - 1) * (long) interval * TU_NANOS;
        long due = nanoClock.getAsLong() + delay;
        // Repeated announcements can advance a countdown, but must not push it further out.
        if (pendingTune != null && pendingTune.frequency == announcement.frequencyMhz()
                && due - pendingTune.scheduledAtNanos >= 0) return;
        pendingTune = new PendingTune(announcement.frequencyMhz(), lockedBssid, due,
                wallClock.getAsLong() + TimeUnit.NANOSECONDS.toMillis(delay), MoveTrigger.CSA);
    }

    private boolean observePendingDestination(Dot11Frame frame, String apId, String bssid, String ssid, int channel) {
        var change = pendingTune;
        if (change == null || change.frequency != frame.frequencyMhz() || !change.bssid.equalsIgnoreCase(bssid)) {
            return false;
        }
        if (rejectDowngrade(frame)) return true;
        if (change.tunedAtMs == null || frame.timestamp() < change.tunedAtMs) return true;
        if (nanoClock.getAsLong() - change.verifyByNanos >= 0) return true;
        var mlo = Dot11ChannelSwitchDecoder.decodeBasicMultiLink(frame.ies());
        if (change.trigger == MoveTrigger.AFFILIATED_LINK_SWITCH
                && mlo != null && mldMac != null && !mldMac.equals(mlo.mldMac())) {
            decoyFramesIgnored++;
            return true;
        }
        pendingTune = null;
        if (change.trigger == MoveTrigger.AFFILIATED_LINK_SWITCH) {
            links.put(lockedBssid, new LinkEvidence(lockedLinkId, lockedBssid, lockedFrequencyMhz));
            lockedBssid = bssid;
            lockedApId = apId;
            lastBeaconTsf = null;
            lockedCapabilityCohort = null;
        }
        recordMove(channel, change.frequency, change.scheduledAtMs, change.tunedAtMs, frame.timestamp(), change.trigger);
        refreshLastHeard(frame.timestamp());
        rememberAdvertisement(frame, ssid);
        return true;
    }

    private void reacquire(Dot11Frame frame, String ssid, int channel) {
        int frequency = frame.frequencyMhz();
        state = State.LOCKED;
        activeSweepFrequency = null;
        candidates.clear();
        if (frequency != lostFromFreq) {
            recordMove(channel, frequency, lostAtMs, confirmedBefore(frequency, frame.timestamp()),
                    frame.timestamp(), MoveTrigger.SILENCE_SWEEP);
        }
        refreshLastHeard(frame.timestamp());
        rememberAdvertisement(frame, ssid);
    }

    private boolean rejectDowngrade(Dot11Frame frame) {
        if (!lockedProtected || advertisesProtection(frame)) return false;
        decoyFramesIgnored++;
        return true;
    }

    private boolean plausibleTsf(Dot11Frame frame) {
        Long tsf = frame.beaconTsf();
        if (tsf == null || lastBeaconTsf == null || Long.compareUnsigned(tsf, lastBeaconTsf) <= 0) return false;
        long advance = tsf - lastBeaconTsf;
        long elapsed = TimeUnit.MILLISECONDS.toMicros(frame.timestamp() - lastBeaconAt);
        return advance > 0 && elapsed >= 0 && advance >= elapsed - MAX_CLOCK_DRIFT_US
                && advance - MAX_CLOCK_DRIFT_US <= elapsed;
    }

    private static boolean advertisesProtection(Dot11Frame frame) {
        return (frame.capability() & 0x0010) != 0 || !SecurityDecoder.decode(frame.ies()).profiles().isEmpty();
    }

    private boolean olderThanLastHeard(Dot11Frame frame) {
        return lastHeard != null && frame.timestamp() < lastHeard.timestamp();
    }

    private void refreshLastHeard(long timestamp) {
        lastHeard = new PacketBridge.ApWatchEvent(lockedChannel, timestamp);
        lastHeardMonoNanos = nanoClock.getAsLong();
        if (opsPaused) opsPauseStartedNanos = lastHeardMonoNanos;
        returnGraceUntilNanos = null;
    }

    private void rememberAdvertisement(Dot11Frame frame, String ssid) {
        lockedProtected |= advertisesProtection(frame);
        lastBeaconTsf = frame.beaconTsf();
        lastBeaconAt = frame.timestamp();
        String cohort = IeSignature.bandInvariantCohortOf(frame.ies());
        if (cohort != null) lockedCapabilityCohort = cohort;
        if (frame.beaconIntervalTu() > 0) lockedBeaconTu = frame.beaconIntervalTu();
        if (ssid != null) lockedSsid = ssid;
        byte[] bytes = frame.ies().first(0);
        if (targetSsidBytes == null && !Dot11InformationElements.hidden(bytes)) setTargetSsidBytes(bytes);

        var mlo = Dot11ChannelSwitchDecoder.decodeBasicMultiLink(frame.ies());
        if (mlo != null) {
            if (mldMac != null && !mldMac.equals(mlo.mldMac())) links.clear();
            mldMac = mlo.mldMac();
            lockedLinkId = mlo.linkId();
        } else {
            var knownLink = links.get(lockedBssid);
            if (knownLink != null) lockedLinkId = knownLink.linkId;
        }
        links.remove(lockedBssid);
        rememberSweepHints(frame, true, lockedBssid);
    }

    private void rememberSweepHints(Dot11Frame frame, boolean targetReporter, String reporterBssid) {
        if (!frame.ies().has(201)) return;
        boolean lockedReporter = state == State.LOCKED && reporterBssid.equalsIgnoreCase(lockedBssid);
        boolean hasMld = lockedReporter ? mldMac != null
                : targetReporter && Dot11ChannelSwitchDecoder.decodeBasicMultiLink(frame.ies()) != null;
        for (var neighbor : Dot11ChannelSwitchDecoder.decodeReducedNeighborReport(frame.ies())) {
            boolean coLocatedLink = targetReporter && neighbor.sameSsid() && neighbor.coLocated();
            boolean matchingMld = hasMld && Integer.valueOf(0).equals(neighbor.mldId());
            boolean affiliate = matchingMld || coLocatedLink;
            boolean named = targetShortSsid != null && targetShortSsid.equals(neighbor.shortSsid());
            if ((named || targetReporter && neighbor.sameSsid() || affiliate
                    || lockedBssid != null && lockedBssid.equalsIgnoreCase(neighbor.bssid()))
                    && sweepFrequencies.contains(neighbor.frequencyMhz())) {
                rnrHints.add(neighbor.frequencyMhz());
            }
            if (affiliate && lockedReporter
                    && neighbor.bssid() != null && !lockedBssid.equalsIgnoreCase(neighbor.bssid())) {
                if (links.size() < MAX_AFFILIATED_LINKS || links.containsKey(neighbor.bssid())) {
                    links.put(neighbor.bssid(), new LinkEvidence(neighbor.linkId(), neighbor.bssid(), neighbor.frequencyMhz()));
                }
            }
        }
    }

    private boolean rotationCandidate(Dot11Frame frame, String bssid) {
        if (!locallyAdministered(lockedBssid) || !locallyAdministered(bssid) || targetSsidBytes == null
                || !Arrays.equals(targetSsidBytes, frame.ies().first(0)) || olderThanLastHeard(frame)
                || lockedProtected && !advertisesProtection(frame)) return false;
        String cohort = IeSignature.bandInvariantCohortOf(frame.ies());
        return cohort == null || lockedCapabilityCohort == null || lockedCapabilityCohort.equals(cohort);
    }

    private static boolean locallyAdministered(String bssid) {
        return bssid != null && bssid.length() >= 2 && (Character.digit(bssid.charAt(1), 16) & 0x03) == 2;
    }

    private CandidateEntry recordCandidate(Dot11Frame frame, String apId, String bssid, String ssid, int channel) {
        String key = bssid.toLowerCase(Locale.ROOT);
        CandidateEntry existing = candidates.get(key);
        Candidate previous = existing == null ? null : existing.view;
        Double rssi = Double.isFinite(frame.rssi()) ? Double.valueOf(frame.rssi()) : previous == null ? null : previous.rssi();
        int tu = frame.beaconIntervalTu() > 0 ? frame.beaconIntervalTu() : previous == null ? 100 : previous.beaconIntervalTu();
        String name = ssid != null || previous == null ? ssid : previous.ssid();
        var entry = new CandidateEntry(bssid, new Candidate(apId, name, channel, frame.frequencyMhz(),
                rssi, tu, frame.timestamp()), frame);
        if (previous != null && previous.lastSeenAt() > frame.timestamp()) return existing;
        candidates.put(key, entry);
        return entry;
    }

    private void rotateBssid(CandidateEntry entry) {
        var candidate = entry.view;
        recordMove(candidate.channel(), candidate.frequencyMhz(), lostAtMs,
                confirmedBefore(candidate.frequencyMhz(), candidate.lastSeenAt()), candidate.lastSeenAt(),
                MoveTrigger.HEURISTIC_BSSID_ROTATION);
        bssidRotated = true;
        links.clear();
        rnrHints.clear();
        mldMac = null;
        lockedLinkId = null;
        lockedCapabilityCohort = null;
        lockCandidate(entry);
    }

    private Long confirmedBefore(int frequency, long timestamp) {
        Long confirmation = firstTune.get(frequency);
        return confirmation != null && confirmation > lostAtMs && confirmation <= timestamp ? confirmation : null;
    }

    private void recordMove(int channel, int frequency, long lostAt, Long tunedAt, long rediscoveredAt, MoveTrigger trigger) {
        moves.add(new ChannelMove(lockedChannel, lockedFrequencyMhz, channel, frequency,
                lostAt, tunedAt, rediscoveredAt, trigger));
        lockedChannel = channel;
        lockedFrequencyMhz = frequency;
        tuned = tunedAt == null ? null : new PacketBridge.ApWatchEvent(channel, tunedAt);
        heardAgain = new PacketBridge.ApWatchEvent(channel, rediscoveredAt);
    }

    public synchronized boolean tick() {
        if (state != State.LOCKED || opsPaused) return false;
        long now = nanoClock.getAsLong();
        if (pendingTune != null) {
            if (pendingTune.tunedAtMs != null) {
                if (now - pendingTune.verifyByNanos >= 0) {
                    if (pendingTune.trigger == MoveTrigger.CSA) spoofWarnings++;
                    returnToLockedFrequency();
                }
                return false;
            }
            if (now - pendingTune.scheduledAtNanos >= 0) return false;
        }
        if (returnGraceUntilNanos != null && now - returnGraceUntilNanos < 0) return false;
        if (now - lastHeardMonoNanos <= silenceThresholdNanos(lockedBeaconTu)) return false;

        state = State.LOST_SEARCHING;
        lostAtMs = wallClock.getAsLong();
        lostFromFreq = lockedFrequencyMhz;
        if (pendingTune != null) rnrHints.add(pendingTune.frequency);
        pendingTune = null;
        returnGraceUntilNanos = null;
        firstTune.clear();
        resetLostPass();
        return true;
    }

    private long verificationWindow() {
        return Math.max(MIN_SWITCH_VERIFY_NANOS, 5L * lockedBeaconTu * TU_NANOS);
    }

    private void returnToLockedFrequency() {
        pendingTune = null;
        returnGraceUntilNanos = nanoClock.getAsLong() + verificationWindow();
    }

    static long silenceThresholdNanos(int beaconIntervalTu) {
        long tu = Math.max(100, beaconIntervalTu);
        return Math.max(MIN_SILENCE_NANOS, tu * TU_NANOS * SILENCE_BEACON_MULTIPLIER);
    }

    public synchronized Integer desiredFrequencyMhz() {
        if (state != State.LOCKED) return null;
        if (pendingTune != null && nanoClock.getAsLong() - pendingTune.scheduledAtNanos >= 0) {
            return pendingTune.frequency;
        }
        return lockedFrequencyMhz;
    }

    public synchronized boolean needsSweep() {
        return state == State.SEARCHING || state == State.LOST_SEARCHING;
    }

    public synchronized State state() { return state; }

    public synchronized Snapshot snapshot() {
        var candidateList = candidates.values().stream().map(CandidateEntry::view).toList();
        var linkCounts = new HashMap<Integer, Integer>();
        links.values().forEach(link -> linkCounts.merge(link.frequencyMhz, 1, Integer::sum));
        var affiliatedLinks = links.values().stream().map(link -> new AffiliatedLink(link.linkId,
                addressTokenizer.apply(link.bssid), Dot11FrameDecoder.channel(link.frequencyMhz), link.frequencyMhz,
                SniperSweepPlanner.band(link.frequencyMhz), sweepFrequencies.contains(link.frequencyMhz)
                        && linkCounts.get(link.frequencyMhz) == 1)).toList();
        PendingChannelSwitch csa = pendingTune != null && pendingTune.trigger == MoveTrigger.CSA
                ? new PendingChannelSwitch(Dot11FrameDecoder.channel(pendingTune.frequency), pendingTune.frequency,
                        pendingTune.scheduledAtMs, pendingTune.tunedAtMs) : null;
        Integer pendingLink = pendingTune != null && pendingTune.trigger == MoveTrigger.AFFILIATED_LINK_SWITCH
                ? pendingTune.frequency : null;
        return new Snapshot(id, state, targetSsid, lockedApId, lockedSsid, lockedChannel, lockedFrequencyMhz,
                initialSweepComplete, swept.size(), sweepFrequencies.size(), unavailable.size(),
                candidateList, lastHeard, tuned, heardAgain, List.copyOf(moves), startedAt, endedAt, opsPaused,
                activeSweepFrequency == null ? null : Dot11FrameDecoder.channel(activeSweepFrequency),
                activeSweepFrequency, csa, decoyFramesIgnored, spoofWarnings,
                mldMac == null ? null : addressTokenizer.apply(mldMac), affiliatedLinks, bssidRotated, pendingLink);
    }

    private void reset(State initialState) {
        id = UUID.randomUUID();
        state = initialState;
        setTargetSsidBytes(null);
        targetSsid = null;
        lockedBssid = null;
        lockedApId = null;
        lockedSsid = null;
        lockedChannel = null;
        lockedFrequencyMhz = null;
        lockedBeaconTu = 100;
        lockedProtected = false;
        lastBeaconTsf = null;
        lockedCapabilityCohort = null;
        lockedLinkId = null;
        mldMac = null;
        links.clear();
        rnrHints.clear();
        pendingTune = null;
        returnGraceUntilNanos = null;
        decoyFramesIgnored = 0;
        spoofWarnings = 0;
        bssidRotated = false;
        swept.clear();
        unavailable.clear();
        lostPass.clear();
        lostPassCompleteCoverage = true;
        lostPassHeardOriginal = false;
        activeSweepFrequency = null;
        initialSweepComplete = false;
        candidates.clear();
        moves.clear();
        firstTune.clear();
        lastHeard = null;
        tuned = null;
        heardAgain = null;
        startedAt = wallClock.getAsLong();
        endedAt = null;
        lastHeardMonoNanos = nanoClock.getAsLong();
        lostAtMs = 0;
        lostFromFreq = 0;
    }

    private void setTargetSsidBytes(byte[] bytes) {
        targetSsidBytes = bytes == null ? null : bytes.clone();
        targetShortSsid = bytes == null ? null : Dot11ChannelSwitchDecoder.shortSsidCrc32(bytes);
    }

    private void evaluateSearchCandidates() {
        if (candidates.size() == 1) {
            lockCandidate(candidates.values().iterator().next());
        } else if (candidates.size() > 1) {
            state = State.SELECTING;
            activeSweepFrequency = null;
        }
    }

    private void lockCandidate(CandidateEntry entry) {
        var candidate = entry.view;
        state = State.LOCKED;
        activeSweepFrequency = null;
        lockedBssid = entry.bssid;
        lockedApId = candidate.apId();
        lockedSsid = candidate.ssid();
        lockedChannel = candidate.channel();
        lockedFrequencyMhz = candidate.frequencyMhz();
        lockedBeaconTu = candidate.beaconIntervalTu();
        refreshLastHeard(candidate.lastSeenAt());
        rememberAdvertisement(entry.frame, candidate.ssid());
    }
}
