package ewave.passive;

import ewave.decoder.Dot11Frame;
import ewave.decoder.Dot11FrameDecoder;
import ewave.decoder.IeSignature;
import ewave.fixtures.ProbeFrames;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

class ProbeCorrelationTest {
    private static final String A = "02:11:22:33:44:01";
    private static final String B = "02:11:22:33:44:02";
    private static final String C = "02:11:22:33:44:03";

    @Test void clustersASequenceAcrossWraparoundAndRemovesExpiredEvidence() throws Exception {
        var clock = new AtomicLong(1450);
        var session = new PassiveWifiSession(new DeviceProfiler(), MyNetworkProfile.EMPTY, clock::get);
        observe(session, A, "Synthetic private name", 4095, 1000);
        observe(session, B, "Synthetic private name", 0, 1100);
        observe(session, C, "Synthetic private name", 5, 1400);

        String a = session.addressId(A), b = session.addressId(B), c = session.addressId(C);
        var cluster = session.inventoryDetail(a).inferredCorrelation();
        assertNotNull(cluster);
        assertEquals(List.of(a, b, c), cluster.memberIds());
        assertEquals(List.of(new ProbeCorrelation.Evidence(a, b, 1, 100, 1, 0.90),
                new ProbeCorrelation.Evidence(b, c, 5, 300, 1, 0.75)), cluster.evidence());
        assertEquals(0.75, cluster.confidence());
        assertEquals("Probabilistic inferred correlation", cluster.inference());
        assertEquals(3, session.profilerReport().size());
        for (var row : session.profilerReport()) assertEquals(cluster.reference(), row.inferredCorrelation());
        assertEquals(cluster, session.inventoryDetail(c).inferredCorrelation());

        clock.addAndGet(TimeUnit.DAYS.toMillis(8));
        assertTrue(session.profilerReport().isEmpty());
        assertNull(session.inventoryDetail(a));
    }

    @Test void requiresABoundedNonOverlappingHandoffAndRejectsAmbiguousOrWeakEvidence() throws Exception {
        var clock = new AtomicLong(5500);
        var session = new PassiveWifiSession(new DeviceProfiler(), MyNetworkProfile.EMPTY, clock::get);
        observe(session, A, "Same name", 100, 2500);
        observe(session, B, "Same name", 101, 2580);
        observe(session, C, "Same name", 101, 2590);
        assertNull(session.inventoryDetail(session.addressId(A)).inferredCorrelation());

        var other = new PassiveWifiSession(new DeviceProfiler(), MyNetworkProfile.EMPTY, clock::get);
        observe(other, A, "First name", 100, 2500);
        assertNoMatch(other, ProbeFrames.frame("Second name", B, 101), B, 2580);
        assertNoMatch(other, ProbeFrames.frame("First name", "00:11:22:33:44:04", 101), "00:11:22:33:44:04", 2590);
        assertNoMatch(other, ProbeFrames.frame("First name", C, 101), C, 5000);

        var overlaid = new PassiveWifiSession(new DeviceProfiler(), MyNetworkProfile.EMPTY, clock::get);
        observe(overlaid, A, "Shared", 100, 2500);
        observe(overlaid, B, "Shared", 101, 2550);
        observe(overlaid, A, "Shared", 102, 2600);
        assertNull(overlaid.inventoryDetail(overlaid.addressId(A)).inferredCorrelation());
    }

    @Test void allowsTightRepeatedWildcardBurstsButSkipsRetriesAndMismatchedFingerprints() throws Exception {
        var session = new PassiveWifiSession(new DeviceProfiler(), MyNetworkProfile.EMPTY, () -> 1500);
        observe(session, A, "", 10, 1150);
        observe(session, A, "", 11, 1200);
        observe(session, B, "", 12, 1240);
        byte[] retry = ProbeFrames.frame("", B, 13);
        retry[1] = 8;
        assertNoMatch(session, retry, B, 1250);
        observe(session, B, "", 13, 1260);
        var match = session.inventoryDetail(session.addressId(A)).inferredCorrelation();
        assertNotNull(match);
        assertEquals(0.80, match.confidence());
        assertEquals(0, match.evidence().getFirst().sharedDirectedSsidCount());

        var different = new PassiveWifiSession(new DeviceProfiler(), MyNetworkProfile.EMPTY, () -> 1500);
        observe(different, A, "Lab", 10, 1150);
        byte[] changed = ProbeFrames.frame("Lab", B, 11);
        changed[31] ^= 1; // Supported rates byte.
        assertNoMatch(different, changed, B, 1200);

        var empty = new PassiveWifiSession(new DeviceProfiler(), MyNetworkProfile.EMPTY, () -> 1500);
        empty.observe(Dot11FrameDecoder.decodeAny(Arrays.copyOf(ProbeFrames.frame("Lab", A, 10), 29), 105, 1150));
        assertNoMatch(empty, Arrays.copyOf(ProbeFrames.frame("Lab", B, 11), 29), B, 1200);
    }

    @Test void correlatesProbeToAssociationAndSharedMultiSsidScanBurstsDespiteMacRotation() throws Exception {
        var clock = new AtomicLong(25_000);
        var session = new PassiveWifiSession(new DeviceProfiler(), MyNetworkProfile.EMPTY, clock::get);
        String ap = "00:11:22:33:44:99";
        byte[] beacon = beaconFrame(ap, "EWAVE-LAB");
        session.observe(Dot11FrameDecoder.decodeAny(beacon, 105, 1_000));

        // Probe request with WPS vendor tag 0050f204, followed 8s later by AssocReq from a different random MAC
        // with WMM vendor tag 0050f202 + RSNE tag 48 and a reset sequence number.
        byte[] probeWithWps = join(ProbeFrames.frame("EWAVE-LAB", A, 200),
                new byte[]{(byte) 221, 4, 0x00, 0x50, (byte) 0xf2, 0x04});
        byte[] assocWithWmmAndRsn = assocReqFrame(B, ap, "EWAVE-LAB", 3,
                new byte[]{48, 2, 1, 0, (byte) 221, 4, 0x00, 0x50, (byte) 0xf2, 0x02});
        session.observe(Dot11FrameDecoder.decodeAny(probeWithWps, 105, 2_000));
        session.observe(Dot11FrameDecoder.decodeAny(assocWithWmmAndRsn, 105, 10_000));

        var probeToAssoc = session.inventoryDetail(session.addressId(A)).inferredCorrelation();
        assertNotNull(probeToAssoc);
        assertEquals(List.of(session.addressId(A), session.addressId(B)), probeToAssoc.memberIds());
        assertEquals("PROBE_TO_ASSOC", probeToAssoc.evidence().getFirst().basis());

        // Separate scan bursts sharing >= 2 directed SSIDs match across 15s and sequence resets, while single-SSID
        // probe pairs beyond 2s stay uncorrelated.
        var pnlClock = new AtomicLong(40_000);
        var pnl = new PassiveWifiSession(new DeviceProfiler(), MyNetworkProfile.EMPTY, pnlClock::get);
        observe(pnl, A, "Lab One", 300, 1_000);
        observe(pnl, A, "Lab Two", 301, 1_050);
        observe(pnl, B, "Lab One", 5, 16_000);
        observe(pnl, B, "Lab Two", 6, 16_050);

        var pnlCluster = pnl.inventoryDetail(pnl.addressId(A)).inferredCorrelation();
        assertNotNull(pnlCluster);
        assertEquals("PNL_PROFILE", pnlCluster.evidence().getFirst().basis());
        assertEquals(2, pnlCluster.evidence().getFirst().sharedDirectedSsidCount());
        assertEquals(List.of(pnl.addressId(A), pnl.addressId(B)), pnlCluster.memberIds());
    }

    @Test void matchesTokenizedWpsUuidAcrossOverlappingLocalAddressesAndDifferentFingerprints() throws Exception {
        var clock = new AtomicLong(70_000);
        var session = new PassiveWifiSession(new DeviceProfiler(), MyNetworkProfile.EMPTY, clock::get);
        String uuid = "0123456789abcdef0123456789abcdef";
        String global = "00:11:22:33:44:04";
        session.observe(Dot11FrameDecoder.decodeAny(wpsProbe(A, uuid, 100), 105, 1_000));
        session.observe(Dot11FrameDecoder.decodeAny(wpsProbe(B, uuid, 200), 105, 65_000));
        session.observe(Dot11FrameDecoder.decodeAny(wpsProbe(C, uuid, 300), 105, 67_000));
        session.observe(Dot11FrameDecoder.decodeAny(wpsProbe(global, uuid, 500), 105, 67_000));
        session.observe(Dot11FrameDecoder.decodeAny(wpsProbe(A, "00000000000000000000000000000000", 400), 105, 68_000));
        session.observe(Dot11FrameDecoder.decodeAny(wpsProbe(B, "ffffffffffffffffffffffffffffffff", 600), 105, 68_000));
        for (int seq = 401; seq < 421; seq++) observe(session, A, "", seq, 68_000 + seq);

        var report = session.audit();
        assertEquals(1, report.distinctWpsUuids());
        assertEquals(1, report.wpsMultiAddressCount());
        assertEquals(1, report.correlatedClusterCount());
        assertEquals(100.0 * 4 / report.totalProbes(), report.wpsUuidEPct());
        String a = session.addressId(A), b = session.addressId(B), c = session.addressId(C);
        var cluster = session.inventoryDetail(a).inferredCorrelation();
        assertNotNull(cluster);
        assertEquals(List.of(a, b, c), cluster.memberIds());
        assertEquals(0.95, cluster.confidence());
        assertEquals(List.of("WPS_UUID_E", "WPS_UUID_E"), cluster.evidence().stream().map(ProbeCorrelation.Evidence::basis).toList());
        assertNull(session.inventoryDetail(session.addressId(global)).inferredCorrelation());
        var json = new com.fasterxml.jackson.databind.ObjectMapper();
        String output = json.writeValueAsString(List.of(report, cluster));
        for (String raw : List.of(uuid, A, B, C, global)) assertFalse(output.contains(raw));
        clock.addAndGet(TimeUnit.DAYS.toMillis(8));
        assertEquals(0, session.audit().correlatedClusterCount());
    }

    @Test void correlatesCrossBandProbeToAssociationWithTheSameSsidWithinFifteenSeconds() throws Exception {
        String ap = "00:11:22:33:44:99";
        String name = "Dual-band lab";
        var hex = HexFormat.of();
        byte[] ht = new byte[28];
        ht[0] = 45;
        ht[1] = 26;
        ht[5] = (byte) 0xff;
        byte[] probeBytes = join(Arrays.copyOf(ProbeFrames.frame(name, A, 200), 26 + name.length()),
                hex.parseHex("010482848b9632020204"), ht);
        byte[] vht = hex.parseHex("bf0c00000000fcff0000fcff0000");
        byte[] fiveGhzIes = join(hex.parseHex("01048c9298a4"), ht, vht);
        var probe = decodeBand(probeBytes, 2437, 2000);
        var assoc = decodeBand(assocReqFrame(B, ap, name, 3, fiveGhzIes, new byte[0]), 5180, 10_000);
        assertNotEquals(IeSignature.capabilityCohortOf(probe.ies()), IeSignature.capabilityCohortOf(assoc.ies()));
        assertNotNull(IeSignature.bandInvariantCohortOf(probe.ies()));
        assertEquals(IeSignature.bandInvariantCohortOf(probe.ies()), IeSignature.bandInvariantCohortOf(assoc.ies()));

        var session = new PassiveWifiSession(new DeviceProfiler(), MyNetworkProfile.EMPTY, () -> 20_000);
        session.observe(probe);
        session.observe(assoc);
        String from = session.addressId(A), to = session.addressId(B);
        var match = session.inventoryDetail(from).inferredCorrelation();
        assertNotNull(match);
        assertEquals(List.of(new ProbeCorrelation.Evidence(from, to, 3899, 8000, 1, 0.70, "PROBE_TO_ASSOC")), match.evidence());
        assertEquals(match, session.inventoryDetail(to).inferredCorrelation());

        for (var rejected : List.of(
                decodeBand(assocReqFrame(B, ap, "Other lab", 3, fiveGhzIes, new byte[0]), 5180, 10_000),
                decodeBand(assocReqFrame(B, ap, name, 3, fiveGhzIes, new byte[0]), 5180, 17_001))) {
            var other = new PassiveWifiSession(new DeviceProfiler(), MyNetworkProfile.EMPTY, () -> 20_000);
            other.observe(probe);
            other.observe(rejected);
            assertNull(other.inventoryDetail(other.addressId(A)).inferredCorrelation());
        }
    }

    @Test void crossBandPreferredNetworkProfilesRequireIdenticalMultiSsidSetsAndRejectAmbiguity() {
        var ids = new SessionIdentifiers();
        var crossBand = new ProbeCorrelation(ids);
        var exact = new ProbeCorrelation(ids);
        var differentNames = new ProbeCorrelation(ids);
        List<String> names = List.of("one-token", "two-token");
        for (var correlation : List.of(crossBand, exact, differentNames)) {
            correlation.observe(A, 1000, 200, "fingerprint-24", "capabilities-24", "band-cohort", names, false);
        }
        crossBand.observe(B, 10_000, 1, "fingerprint-5", "capabilities-5", "band-cohort", names, false);
        exact.observe(B, 10_000, 1, "fingerprint-24", "capabilities-24", "band-cohort", names, false);
        differentNames.observe(B, 10_000, 1, "fingerprint-5", "capabilities-5", "band-cohort", List.of("one-token"), false);

        var evidence = crossBand.snapshot().get(A).evidence().getFirst();
        assertEquals("PNL_PROFILE", evidence.basis());
        assertEquals(2, evidence.sharedDirectedSsidCount());
        assertTrue(evidence.confidence() < exact.snapshot().get(A).confidence());
        assertTrue(differentNames.snapshot().isEmpty());
        crossBand.observe(C, 10_000, 8, "fingerprint-6", "capabilities-6", "band-cohort", names, false);
        assertTrue(crossBand.snapshot().isEmpty());
    }

    private static Dot11Frame decodeBand(byte[] frame, int frequency, long time) {
        byte[] radiotap = ProbeFrames.radiotap(frame);
        ByteBuffer.wrap(radiotap).order(ByteOrder.LITTLE_ENDIAN).putShort(8, (short) frequency);
        return Dot11FrameDecoder.decodeAny(radiotap, 127, time);
    }

    private static byte[] wpsProbe(String address, String uuid, int sequence) {
        byte[] frame = ProbeFrames.frame("", address, sequence);
        frame[28] ^= (byte) sequence; // Change a supported-rates octet across transmitters.
        return join(frame, HexFormat.of().parseHex("dd180050f20410470010" + uuid));
    }

    private static byte[] beaconFrame(String ap, String ssid) {
        byte[] ssidBytes = ssid.getBytes(StandardCharsets.UTF_8);
        byte[] hdr = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN)
                .put((byte) 0x80).put((byte) 0).putShort((short) 0)
                .put(HexFormat.of().parseHex("ffffffffffff"))
                .put(HexFormat.ofDelimiter(":").parseHex(ap))
                .put(HexFormat.ofDelimiter(":").parseHex(ap))
                .putShort((short) 16).array();
        byte[] fixed = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN)
                .putLong(100L).putShort((short) 100).putShort((short) 1).array();
        return join(hdr, fixed, new byte[]{0, (byte) ssidBytes.length}, ssidBytes);
    }

    private static byte[] assocReqFrame(String client, String ap, String ssid, int seq, byte[] extraIes) {
        return assocReqFrame(client, ap, ssid, seq, HexFormat.of().parseHex("010482848b9632030c1218"), extraIes);
    }

    private static byte[] assocReqFrame(String client, String ap, String ssid, int seq, byte[] capIes, byte[] extraIes) {
        byte[] ssidBytes = ssid.getBytes(StandardCharsets.UTF_8);
        byte[] hdr = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN)
                .put((byte) 0x00).put((byte) 0).putShort((short) 0)
                .put(HexFormat.ofDelimiter(":").parseHex(ap))
                .put(HexFormat.ofDelimiter(":").parseHex(client))
                .put(HexFormat.ofDelimiter(":").parseHex(ap))
                .putShort((short) (seq << 4)).array();
        byte[] fixed = new byte[]{1, 0, 10, 0};
        return join(hdr, fixed, new byte[]{0, (byte) ssidBytes.length}, ssidBytes, capIes, extraIes);
    }

    private static byte[] join(byte[]... parts) {
        int len = Arrays.stream(parts).mapToInt(p -> p.length).sum();
        var buf = ByteBuffer.allocate(len);
        for (byte[] part : parts) buf.put(part);
        return buf.array();
    }

    private static void assertNoMatch(PassiveWifiSession session, byte[] packet, String addr, long time) {
        session.observe(Dot11FrameDecoder.decodeAny(packet, 105, time));
        assertNull(session.inventoryDetail(session.addressId(addr)).inferredCorrelation());
    }

    private static void observe(PassiveWifiSession session, String addr, String ssid, int sequence, long time) {
        session.observe(Dot11FrameDecoder.decodeAny(ProbeFrames.frame(ssid, addr, sequence), 105, time));
    }
}
