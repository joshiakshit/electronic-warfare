package ewave.capture;

import ewave.core.AdaptiveScanner;
import ewave.decoder.Dot11ChannelSwitchDecoder;
import ewave.decoder.Dot11Frame;
import ewave.decoder.Dot11FrameDecoder;
import ewave.decoder.Dot11InformationElements;
import ewave.fixtures.CompletedProcess;
import ewave.fixtures.ProbeFrames;
import ewave.fixtures.StreamingCaptureProcess;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(15)
class SniperControllerTest {
    private static final String AP1 = "00:11:22:33:44:55";
    private static final String AP2 = "00:11:22:33:44:66";
    private static final int PCAP_HEADER_BYTES = 24;
    private static final String HOTSPOT = "02:11:22:33:44:55";
    private static final String ROTATED = "02:11:22:33:44:66";
    private static final String THIRD_AP = "02:11:22:33:44:77";
    private static final byte[] LAB_SSID = "Test AP".getBytes(StandardCharsets.UTF_8);

    @Test void followsCsaAtTheBeaconCountdownAndVerifiesTheTargetAfterTuning() {
        var clock = new Timeline();
        var sniper = clock.locked(AP1);
        clock.observe(sniper, AP1, 2412, 1, 100, ie(60, "00830503"));
        assertEquals(5975, sniper.snapshot().pendingChannelSwitch().frequencyMhz());
        assertEquals(2412, sniper.desiredFrequencyMhz());
        clock.advance(205);
        assertEquals(5975, sniper.desiredFrequencyMhz());
        assertEquals(2412, sniper.snapshot().lockedFrequencyMhz());
        clock.observe(sniper, AP1, 5975, 1, 300);
        assertTrue(sniper.snapshot().moves().isEmpty());
        sniper.tuneConfirmed(5, 5975, clock.wall.get());
        clock.advance(50);
        clock.observe(sniper, AP1, 5975, 1, 500);
        var run = sniper.snapshot();
        assertEquals(5975, run.lockedFrequencyMhz());
        assertNull(run.pendingChannelSwitch());
        assertEquals(SniperController.MoveTrigger.CSA, run.moves().getFirst().trigger());
        assertEquals(clock.wall.get() - 50, run.moves().getFirst().tunedAtMs());
    }

    @Test void rollsBackUnverifiedCsaAfterTheVerificationWindow() {
        var clock = new Timeline();
        var sniper = clock.locked(AP1);
        clock.observe(sniper, AP1, 2412, 17, 100, ie(37, "000601"));
        assertEquals(2437, sniper.desiredFrequencyMhz());
        sniper.tuneConfirmed(6, 2437, clock.wall.get());
        clock.advance(599);
        clock.observe(sniper, AP2, 2437, 17, 1000);
        clock.observe(sniper, AP1, 2437, 1, 1000);
        assertFalse(sniper.tick());
        assertEquals(2437, sniper.desiredFrequencyMhz());
        clock.advance(1);
        assertFalse(sniper.tick());
        var run = sniper.snapshot();
        assertEquals(2412, sniper.desiredFrequencyMhz());
        assertEquals(1, run.decoyFramesIgnored());
        assertEquals(1, run.spoofWarnings());
        assertNull(run.pendingChannelSwitch());
        assertTrue(run.moves().isEmpty());
    }

    @Test void keepsTheLockWithFromDsAndApManagementHeartbeats() {
        var clock = new Timeline();
        var sniper = clock.locked(AP1);
        clock.advance(2900);
        sniper.observeTransmitterActivity(clock.traffic(2, 0, 2, AP1, AP2, 2412));
        assertEquals(clock.wall.get(), sniper.snapshot().lastHeard().timestamp());
        clock.advance(2900);
        assertFalse(sniper.tick());
        sniper.observeTransmitterActivity(clock.traffic(0, 13, 0, AP1, AP1, 2412));
        assertEquals(clock.wall.get(), sniper.snapshot().lastHeard().timestamp());

        clock.advance(3001);
        sniper.observeTransmitterActivity(clock.traffic(2, 0, 1, AP1, AP1, 2412));
        sniper.observeTransmitterActivity(clock.traffic(2, 0, 2, AP2, AP1, 2412));
        sniper.observeTransmitterActivity(clock.traffic(0, 13, 0, AP1, AP2, 2412));
        sniper.observeTransmitterActivity(clock.traffic(2, 0, 2, AP1, AP1, 2437));
        assertTrue(sniper.tick());
        assertEquals(1, sniper.snapshot().lastHeard().channel());
        assertEquals(2412, sniper.snapshot().lockedFrequencyMhz());
    }

    @Test void rejectsOpenDecoysEvenAfterSilenceButAllowsAProtectedApToRestartItsTsf() {
        var clock = new Timeline();
        var sniper = clock.locked(AP1);
        clock.observe(sniper, AP1, 2412, 1, 1_100_000, ie(48, ""));
        clock.advance(100);
        clock.observe(sniper, AP1, 2412, 1, 1_200_000);
        assertEquals(1, sniper.snapshot().decoyFramesIgnored());
        assertEquals(clock.wall.get() - 100, sniper.snapshot().lastHeard().timestamp());
        clock.advance(3000);
        assertTrue(sniper.tick());
        clock.observe(sniper, AP1, 2437, 1, 10);
        assertEquals(SniperController.State.LOST_SEARCHING, sniper.state());
        clock.observe(sniper, AP1, 2437, 17, 20);
        assertEquals(SniperController.State.LOCKED, sniper.state());
        assertEquals(2, sniper.snapshot().decoyFramesIgnored());
        assertEquals(2437, sniper.desiredFrequencyMhz());
        assertEquals(SniperController.MoveTrigger.SILENCE_SWEEP, sniper.snapshot().moves().getFirst().trigger());
    }

    @Test void requiresPlausibleTsfProgressionForAnUnannouncedChangeDuringARecentLock() {
        var clock = new Timeline();
        var sniper = clock.locked(AP1);
        clock.observe(sniper, AP1, 2412, 17, 1_000_000);
        clock.advance(100);
        clock.observe(sniper, AP1, 2437, 17, 10);
        clock.observe(sniper, AP1, 2437, 17, 30_000_000);
        assertEquals(2, sniper.snapshot().decoyFramesIgnored());
        assertEquals(2412, sniper.desiredFrequencyMhz());
        clock.observe(sniper, AP1, 2437, 17, 1_100_000);
        assertEquals(2437, sniper.desiredFrequencyMhz());
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
    void onlyRotatesALocalBssidAfterAFullPassAndSurfacesAmbiguity(int matches) {
        var clock = new Timeline();
        var sniper = clock.locked(HOTSPOT);
        clock.observe(sniper, HOTSPOT, 2412, 17, 100, ie(127, "08"));
        clock.advance(3001);
        assertTrue(sniper.tick());
        sniper.sweepFrequencyFinished(2412, true);
        clock.observe(sniper, ROTATED, 2437, 17, 100, ie(127, "08"));
        sniper.sweepFrequencyFinished(2437, true);
        if (matches == 2) clock.observe(sniper, THIRD_AP, 5975, 17, 100, ie(127, "08"));
        assertEquals(SniperController.State.LOST_SEARCHING, sniper.state());
        sniper.sweepFrequencyFinished(5975, true);
        if (matches == 2) {
            assertEquals(SniperController.State.SELECTING, sniper.state());
            assertEquals(2, sniper.snapshot().candidates().size());
            assertFalse(sniper.snapshot().bssidRotated());
            sniper.selectCandidate("token-" + ROTATED);
        }
        var run = sniper.snapshot();
        assertEquals(SniperController.State.LOCKED, run.state());
        assertTrue(run.bssidRotated());
        assertEquals("token-" + ROTATED, run.lockedApId());
        assertEquals(SniperController.MoveTrigger.HEURISTIC_BSSID_ROTATION, run.moves().getFirst().trigger());
    }

    @Test void keepsAGloballyAdministeredBssidPinned() {
        var clock = new Timeline();
        var sniper = clock.locked(AP1);
        clock.advance(3001);
        assertTrue(sniper.tick());
        clock.observe(sniper, ROTATED, 2437, 1, 100);
        for (int frequency : Timeline.FREQUENCIES) sniper.sweepFrequencyFinished(frequency, true);
        assertEquals(SniperController.State.LOST_SEARCHING, sniper.state());
        assertTrue(sniper.snapshot().candidates().isEmpty());
    }

    @Test void rotationRequiresCompatibleEvidenceAndConfirmedCoverage() {
        var clock = new Timeline();
        var sniper = clock.locked(HOTSPOT);
        clock.observe(sniper, HOTSPOT, 2412, 17, 100, ie(127, "08"));
        clock.advance(3001);
        assertTrue(sniper.tick());
        clock.observe(sniper, ROTATED, 2437, 17, 100, ie(127, "10"));
        clock.observe(sniper, THIRD_AP, 2437, 1, 100, ie(127, "08"));
        assertTrue(sniper.snapshot().candidates().isEmpty());
        clock.observe(sniper, ROTATED, 2437, 17, 200, ie(127, "08"));
        sniper.sweepFrequencyFinished(2412, false);
        sniper.sweepFrequencyFinished(2437, true);
        sniper.sweepFrequencyFinished(5975, true);
        assertEquals(SniperController.State.LOST_SEARCHING, sniper.state());
        clock.observe(sniper, ROTATED, 2437, 17, 300, ie(127, "08"));
        clock.observe(sniper, HOTSPOT, 2412, 17, 25, ie(127, "08"));
        assertFalse(sniper.snapshot().bssidRotated());
        assertEquals("token-" + HOTSPOT, sniper.snapshot().lockedApId());
    }

    @Test void originalApTrafficDuringThePassPreventsHeuristicRotation() {
        var clock = new Timeline();
        var sniper = clock.locked(HOTSPOT);
        clock.advance(3001);
        assertTrue(sniper.tick());
        sniper.observeTransmitterActivity(clock.traffic(2, 0, 2, HOTSPOT, AP2, 2412));
        clock.observe(sniper, ROTATED, 2437, 1, 50);
        for (int frequency : Timeline.FREQUENCIES) sniper.sweepFrequencyFinished(frequency, true);
        assertEquals(SniperController.State.LOST_SEARCHING, sniper.state());
        assertFalse(sniper.snapshot().bssidRotated());

        clock.observe(sniper, ROTATED, 2437, 1, 100);
        for (int frequency : Timeline.FREQUENCIES) sniper.sweepFrequencyFinished(frequency, true);
        assertTrue(sniper.snapshot().bssidRotated());
    }

    @Test void learnsSupportedShortSsidHintsFromOtherAdvertisersDuringSearch() {
        var clock = new Timeline();
        var sniper = clock.controller();
        sniper.startBySsid(LAB_SSID, "Test AP");
        var report = ByteBuffer.allocate(9).order(ByteOrder.LITTLE_ENDIAN);
        report.put(new byte[]{0, 5, (byte) 131, 5, 0});
        report.putInt(Dot11ChannelSwitchDecoder.shortSsidCrc32(LAB_SSID));
        sniper.observeFrame(clock.advertisement(AP2, 2412, 1, 10,
                new Dot11InformationElements.Element(201, report.array())), "other", AP2, new byte[]{1}, "Other");
        assertEquals(Set.of(5975), sniper.prioritySweepFrequencies());
        assertEquals(SniperController.State.SEARCHING, sniper.state());
        assertTrue(sniper.snapshot().candidates().isEmpty());
    }

    private static Dot11InformationElements.Element ie(int id, String hex) {
        return new Dot11InformationElements.Element(id, HexFormat.of().parseHex(hex));
    }

    private static final class Timeline {
        static final List<Integer> FREQUENCIES = List.of(2412, 2437, 5975);
        final AtomicLong mono = new AtomicLong();
        final AtomicLong wall = new AtomicLong(100_000);

        SniperController controller() {
            var sniper = new SniperController(mono::get, wall::get);
            sniper.useSweepChannels(FREQUENCIES.stream().map(freq ->
                    new RadioStatus.Channel(Dot11FrameDecoder.channel(freq), freq, false, false)).toList());
            return sniper;
        }

        SniperController locked(String bssid) {
            var sniper = controller();
            sniper.startByAp("token-" + bssid, bssid, LAB_SSID, "Test AP", 1, 2412, 100, wall.get());
            return sniper;
        }

        void advance(long millis) {
            wall.addAndGet(millis);
            mono.addAndGet(TimeUnit.MILLISECONDS.toNanos(millis));
        }

        void observe(SniperController sniper, String bssid, int frequency, int capability, long tsf,
                     Dot11InformationElements.Element... extra) {
            sniper.observeFrame(advertisement(bssid, frequency, capability, tsf, extra),
                    "token-" + bssid, bssid, LAB_SSID, "Test AP");
        }

        Dot11Frame advertisement(String bssid, int frequency, int capability, long tsf,
                                 Dot11InformationElements.Element... extra) {
            var elements = new ArrayList<>(List.of(extra));
            elements.add(new Dot11InformationElements.Element(0, LAB_SSID));
            return new Dot11Frame(0, 8, 0, 0, -1, "ff:ff:ff:ff:ff:ff", bssid, bssid, null,
                    wall.get(), frequency, -40, null, 48, new Dot11InformationElements(elements), tsf,
                    100, capability, null, 0, 0);
        }

        Dot11Frame traffic(int type, int subtype, int ds, String transmitter, String thirdAddress, int frequency) {
            return new Dot11Frame(type, subtype, ds, 0, -1, THIRD_AP, transmitter, thirdAddress, null,
                    wall.get(), frequency, -40, null, 48, null, null, 0, 0, null, 0, 0);
        }
    }

    @Test void completesTheFrequencyPlanAndRecordsReacquisitionAcrossMatchingChannelNumbers() {
        var mono = new AtomicLong(0);
        var wall = new AtomicLong(10_000);
        var sniper = new SniperController(mono::get, wall::get);
        sniper.useSweepChannels(RadioStatus.parseChannels(RadioStatusTest.PHY_INFO).orElseThrow());
        byte[] ssid = { 'A', 'P' };
        sniper.startBySsid(ssid, "AP");
        sniper.observeFrame(beacon(AP1, ssid, 1, 5955, 100, wall.get()), "ap", AP1, ssid, "AP");
        sniper.sweepFrequencyFinished(2412, true);
        sniper.sweepFrequencyFinished(5260, false);
        assertEquals(SniperController.State.SEARCHING, sniper.state());
        assertEquals(1, sniper.snapshot().channelsSwept());
        assertEquals(1, sniper.snapshot().unavailableSweepChannels());
        sniper.sweepFrequencyFinished(5955, true);
        assertEquals(2, sniper.snapshot().channelsSwept());
        assertEquals(5955, sniper.desiredFrequencyMhz());

        mono.set(TimeUnit.SECONDS.toNanos(4));
        wall.set(14_000);
        assertTrue(sniper.tick());
        sniper.tuneConfirmed(1, 5955, 14_020);
        sniper.tuneConfirmed(1, 2412, 14_040);
        sniper.observeFrame(beacon(AP1, ssid, 1, 2412, 100, 14_042), "ap", AP1, ssid, "AP");
        var move = sniper.snapshot().moves().getFirst();
        assertEquals(5955, move.fromFrequencyMhz());
        assertEquals(2412, move.toFrequencyMhz());
        assertEquals(14_040L, move.tunedAtMs());
    }

    @Test void completesFullInitialSweepBeforeAutoLockingSoleMatchAndPromptsWhenMultipleMatch() {
        var mono = new AtomicLong(1_000_000_000L);
        var wall = new AtomicLong(10_000L);
        var sniper = new SniperController(mono::get, wall::get);

        byte[] ssid = "ewave lab".getBytes(StandardCharsets.UTF_8);
        sniper.startBySsid(ssid, "ewave lab");
        assertEquals(SniperController.State.SEARCHING, sniper.state());
        assertTrue(sniper.needsSweep());
        assertNull(sniper.desiredFrequencyMhz());

        // Hearing one matching AP on channel 1 must NOT lock before all 13 channels are swept.
        sniper.observeFrame(beacon(AP1, ssid, 1, 2412, 100, wall.get()), "ap-1", AP1, ssid, "ewave lab");
        for (int ch = 1; ch <= 12; ch++) {
            sniper.sweepChannelFinished(ch);
            assertEquals(SniperController.State.SEARCHING, sniper.state(), "Locked too early on channel " + ch);
        }
        sniper.sweepChannelFinished(13);
        var locked = sniper.snapshot();
        assertEquals(SniperController.State.LOCKED, locked.state());
        assertEquals("ap-1", locked.lockedApId());
        assertEquals(1, locked.lockedChannel());
        assertEquals(2412, locked.lockedFrequencyMhz());
        assertTrue(locked.initialSweepComplete());

        // When two BSSIDs advertise the same SSID across channels, sweep finishes and enters SELECTING.
        sniper.startBySsid(ssid, "ewave lab");
        sniper.observeFrame(beacon(AP1, ssid, 1, 2412, 100, wall.get()), "ap-1", AP1, ssid, "ewave lab");
        sniper.observeFrame(beacon(AP2, ssid, 11, 2462, 100, wall.get()), "ap-2", AP2, ssid, "ewave lab");
        for (int ch = 1; ch <= 13; ch++) sniper.sweepChannelFinished(ch);
        var selecting = sniper.snapshot();
        assertEquals(SniperController.State.SELECTING, selecting.state());
        assertFalse(sniper.needsSweep());
        assertEquals(2, selecting.candidates().size());

        var chosen = sniper.selectCandidate("ap-2");
        assertEquals(SniperController.State.LOCKED, chosen.state());
        assertEquals("ap-2", chosen.lockedApId());
        assertEquals(11, chosen.lockedChannel());
        assertEquals(2462, chosen.lockedFrequencyMhz());
    }

    @Test void convertsBeaconIntervalTuSuspendsSilenceDuringOpsAndReacquiresSameOrMovedChannel() {
        var mono = new AtomicLong(0L);
        var wall = new AtomicLong(1_000L);
        var sniper = new SniperController(mono::get, wall::get);

        // 300 TU * 20 * 1.024 ms = 6144 ms (> 3000 ms floor).
        assertEquals(TimeUnit.MICROSECONDS.toNanos(6_144_000L), SniperController.silenceThresholdNanos(300));
        assertEquals(TimeUnit.MILLISECONDS.toNanos(3_000L), SniperController.silenceThresholdNanos(100));

        byte[] ssid = "ewave lab".getBytes(StandardCharsets.UTF_8);
        sniper.startByAp("ap-1", AP1, ssid, "ewave lab", 6, 2437, 300, wall.get());
        assertEquals(SniperController.State.LOCKED, sniper.state());

        // Pausing for Ops for 20 seconds must NOT trigger silence loss.
        sniper.setOpsPaused(true);
        mono.addAndGet(TimeUnit.SECONDS.toNanos(20));
        wall.addAndGet(20_000L);
        assertFalse(sniper.tick());
        assertEquals(SniperController.State.LOCKED, sniper.state());
        sniper.setOpsPaused(false);
        assertFalse(sniper.tick());

        // After Ops resumes, silence <= 6144 ms stays LOCKED; exceeding 6144 ms enters LOST_SEARCHING.
        mono.addAndGet(TimeUnit.MILLISECONDS.toNanos(6_100));
        wall.addAndGet(6_100L);
        assertFalse(sniper.tick());
        mono.addAndGet(TimeUnit.MILLISECONDS.toNanos(100));
        wall.addAndGet(100L);
        assertTrue(sniper.tick());
        assertEquals(SniperController.State.LOST_SEARCHING, sniper.state());
        assertTrue(sniper.needsSweep());

        // Reacquiring on the ORIGINAL channel 6 resumes LOCKED WITHOUT recording a false ChannelMove.
        wall.addAndGet(200L);
        mono.addAndGet(TimeUnit.MILLISECONDS.toNanos(200));
        sniper.observeFrame(beacon(AP1, ssid, 6, 2437, 300, wall.get()), "ap-1", AP1, ssid, "ewave lab");
        assertEquals(SniperController.State.LOCKED, sniper.state());
        assertEquals(0, sniper.snapshot().moves().size());

        // Losing it again and finding it on channel 11 DOES record a ChannelMove; adjacent bleed is ignored.
        mono.addAndGet(TimeUnit.MILLISECONDS.toNanos(6_200));
        wall.addAndGet(6_200L);
        assertTrue(sniper.tick());
        assertEquals(SniperController.State.LOST_SEARCHING, sniper.state());

        // Adjacent bleed (received on 2412 while DS advertises 6) must be ignored.
        sniper.observeFrame(beacon(AP1, ssid, 6, 2412, 300, wall.get() + 50), "ap-1", AP1, ssid, "ewave lab");
        assertEquals(SniperController.State.LOST_SEARCHING, sniper.state());

        sniper.tuneConfirmed(11, 2462, wall.get() + 100);
        wall.addAndGet(150L);
        mono.addAndGet(TimeUnit.MILLISECONDS.toNanos(150));
        sniper.observeFrame(beacon(AP1, ssid, 11, 2462, 300, wall.get()), "ap-1", AP1, ssid, "ewave lab");
        var moved = sniper.snapshot();
        assertEquals(SniperController.State.LOCKED, moved.state());
        assertEquals(11, moved.lockedChannel());
        assertEquals(1, moved.moves().size());
        assertEquals(6, moved.moves().getFirst().fromChannel());
        assertEquals(11, moved.moves().getFirst().toChannel());
        assertEquals(wall.get(), moved.moves().getFirst().rediscoveredAtMs());
    }

    @Test void allowsCancellationAtEveryStage() {
        var sniper = new SniperController();
        byte[] ssid = "ewave lab".getBytes(StandardCharsets.UTF_8);

        sniper.startBySsid(ssid, "ewave lab");
        assertEquals(SniperController.State.IDLE, sniper.cancel().state());
        assertFalse(sniper.needsSweep());

        sniper.startBySsid(ssid, "ewave lab");
        sniper.observeFrame(beacon(AP1, ssid, 1, 2412, 100, 1000L), "ap-1", AP1, ssid, "ewave lab");
        sniper.observeFrame(beacon(AP2, ssid, 6, 2437, 100, 1000L), "ap-2", AP2, ssid, "ewave lab");
        for (int ch = 1; ch <= 13; ch++) sniper.sweepChannelFinished(ch);
        assertEquals(SniperController.State.SELECTING, sniper.state());
        assertEquals(SniperController.State.IDLE, sniper.cancel().state());

        sniper.startByAp("ap-1", AP1, ssid, "ewave lab", 6, 2437, 100, 1000L);
        assertEquals(SniperController.State.IDLE, sniper.cancel().state());
        assertNull(sniper.desiredFrequencyMhz());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void integratesWithPacketBridgeToSweepAndLockOnSoleSsidMatch(boolean alreadyTunedToFirstChannel) throws Exception {
        var capture = new StreamingCaptureProcess();
        try (var bridge = new PacketBridge(builder -> builder.command().getFirst().equals("tcpdump")
                ? capture : new CompletedProcess("", 0), Map.of(), new ewave.passive.DeviceProfiler(), 20)) {
            bridge.startPassive("lab0mon", false);
            if (alreadyTunedToFirstChannel) bridge.tuneChannel(2412);
            bridge.startSniperBySsid("ewave lab");
            assertEquals(SniperController.State.SEARCHING, bridge.sniperState().run().state());

            // Emit a beacon on channel 6 while sweeping; Sniper must finish sweeping 1..13 before locking 2437.
            byte[] ssid = "ewave lab".getBytes(StandardCharsets.UTF_8);
            capture.write(beaconCapture(ssid, 6));

            await(() -> bridge.sniperState().run().state() == SniperController.State.LOCKED, "initial lock");
            var locked = bridge.sniperState().run();
            assertEquals(SniperController.State.LOCKED, locked.state());
            assertTrue(locked.initialSweepComplete());
            assertEquals(13, locked.channelsSwept());
            assertEquals(6, locked.lockedChannel());
            assertEquals(2437, locked.lockedFrequencyMhz());

            bridge.stopSniper();
            assertEquals(SniperController.State.IDLE, bridge.sniperState().run().state());
        }
    }

    @Test void bridgeSweepsAndFollowsAnAccessPointAfterItChangesChannel() throws Exception {
        var capture = new StreamingCaptureProcess();
        var scanner = new AdaptiveScanner(AdaptiveScanner.Config.defaults(13, 128, 71));
        try (var bridge = new PacketBridge(builder -> builder.command().getFirst().equals("tcpdump")
                ? capture : new CompletedProcess("", 0), Map.of(), new ewave.passive.DeviceProfiler(), 20)) {
            bridge.startPassive("lab0mon", false, scanner);
            byte[] ssid = "ewave lab".getBytes(StandardCharsets.UTF_8);
            capture.write(beaconCapture(ssid, 6));
            String apId = bridge.getPassiveWifi().addressId(AP1);
            await(() -> bridge.getPassiveWifi().observedAp(apId) != null, "observation of the target AP");
            var initial = bridge.startSniperByApId(apId).run();
            assertEquals(SniperController.State.LOCKED, initial.state());
            assertEquals(6, initial.lockedChannel());

            await(() -> bridge.sniperState().run().state() == SniperController.State.LOST_SEARCHING, "loss of the target");
            await(() -> Integer.valueOf(11).equals(bridge.getChannelSnapshot().radio().lastConfirmedChannel()),
                    "the sweep to reach channel 11");
            byte[] movedBeacon = beaconCapture(ssid, 11);
            capture.write(Arrays.copyOfRange(movedBeacon, PCAP_HEADER_BYTES, movedBeacon.length));

            await(() -> bridge.sniperState().run().state() == SniperController.State.LOCKED, "reacquisition");
            var recovered = bridge.sniperState().run();
            assertEquals(initial.id(), recovered.id());
            assertEquals(apId, recovered.lockedApId());
            assertEquals(2462, recovered.lockedFrequencyMhz());
            assertEquals(1, recovered.moves().size());
            var move = recovered.moves().getFirst();
            assertEquals(6, move.fromChannel());
            assertEquals(11, move.toChannel());
            assertNotNull(move.tunedAtMs());
            assertTrue(move.tunedAtMs() <= move.rediscoveredAtMs());
            assertTrue(bridge.isRunning());
        }
    }

    private static void await(BooleanSupplier condition, String evidence) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(6);
        while (!condition.getAsBoolean() && System.nanoTime() < deadline) Thread.sleep(10);
        assertTrue(condition.getAsBoolean(), "Timed out waiting for " + evidence);
    }

    private static byte[] beaconCapture(byte[] ssid, int channel) {
        byte[] frame = ProbeFrames.radiotap(rawBeacon(AP1, ssid, channel));
        ByteBuffer.wrap(frame).order(ByteOrder.LITTLE_ENDIAN).putShort(8, PacketBridge.channelFrequencyMhz(channel).shortValue());
        byte[] pcap = ProbeFrames.pcap(ByteOrder.LITTLE_ENDIAN, false, 127, frame);
        long now = System.currentTimeMillis();
        ByteBuffer.wrap(pcap).order(ByteOrder.LITTLE_ENDIAN).position(PCAP_HEADER_BYTES)
                .putInt((int) (now / 1000)).putInt((int) (now % 1000) * 1000);
        return pcap;
    }

    private static Dot11Frame beacon(String bssid, byte[] ssid, int advertisedChannel, int rxFreqMhz,
                                     int beaconTu, long atMs) {
        var ssidIe = new Dot11InformationElements.Element(0, ssid);
        var dsIe = new Dot11InformationElements.Element(3, new byte[]{(byte) advertisedChannel});
        return new Dot11Frame(0, 8, 0, 0, -1, "ff:ff:ff:ff:ff:ff", bssid, bssid, null,
                atMs, rxFreqMhz, -40, null, 48, new Dot11InformationElements(List.of(ssidIe, dsIe)),
                0L, beaconTu, 1, null, 0, 0);
    }

    private static byte[] rawBeacon(String bssid, byte[] ssid, int dsChannel) {
        byte[] mac = java.util.HexFormat.ofDelimiter(":").parseHex(bssid);
        byte[] bcast = java.util.HexFormat.of().parseHex("ffffffffffff");
        var buf = ByteBuffer.allocate(24 + 12 + 2 + ssid.length + 3).order(ByteOrder.LITTLE_ENDIAN);
        buf.putShort((short) 0x0080).putShort((short) 0).put(bcast).put(mac).put(mac).putShort((short) 0);
        buf.putLong(0L).putShort((short) 100).putShort((short) 1);
        buf.put((byte) 0).put((byte) ssid.length).put(ssid);
        buf.put((byte) 3).put((byte) 1).put((byte) dsChannel);
        return buf.array();
    }
}
