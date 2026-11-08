package ewave.passive;

import ewave.decoder.CapabilityDecoder;
import ewave.decoder.Dot11Frame;
import ewave.decoder.IeSignature;
import ewave.decoder.Dot11FrameDecoder;
import ewave.fixtures.ProbeFrames;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class PassiveWifiSessionTest {
    private static final HexFormat HEX = HexFormat.of();
    private static final String CLIENT = "02:11:22:33:44:55";
    private static final String AP = "00:aa:bb:cc:dd:ee";
    private static final String AP2 = "00:aa:bb:cc:dd:ef";
    private static final String AP3 = "00:aa:bb:cc:dd:f0";
    private static final String BROADCAST = "ff:ff:ff:ff:ff:ff";

    @Test void decodesHtVhtHeAndEhtWithBoundedIeParsing() {
        byte[] ht = new byte[26], vht = new byte[12], he = new byte[22], eht = new byte[18];
        ht[0] = (byte) 0xef;
        ht[1] = 1;
        ht[3] = ht[4] = (byte) 0xff;
        vht[0] = (byte) 0xe4;
        vht[4] = (byte) 0xf0;
        vht[5] = (byte) 0xff;
        he[0] = 35;
        he[7] = 4;
        he[18] = (byte) 0xf0;
        he[19] = (byte) 0xff;
        eht[0] = 108;
        eht[3] = 2;
        eht[12] = 3;
        byte[] probe = ProbeFrames.frame("");
        byte[][] frames = {
                join(probe, ie(45, ht)),
                join(probe, ie(45, ht), ie(191, vht)),
                join(probe, ie(255, he), ie(255, new byte[]{59, 0, 0})),
                join(probe, ie(255, he), ie(255, eht))
        };
        var generations = List.of("Wi-Fi 4", "Wi-Fi 5", "Wi-Fi 6E", "Wi-Fi 7");
        for (int i = 0; i < frames.length; i++) {
            var f = decode(frames[i], 1000);
            var c = CapabilityDecoder.decode(f.ies(), 5975);
            assertEquals(generations.get(i), c.wifiGeneration());
            assertEquals(i == 3 ? 3 : 2, c.spatialStreams());
            assertEquals(List.of(1.0, 2.0, 5.5, 11.0), c.basicRates());
        }
        assertTrue(CapabilityDecoder.decode(decode(frames[2], 1000).ies(), 5975).sixGhzCapability());
        assertEquals(320, CapabilityDecoder.decode(decode(frames[3], 1000).ies(), 5975).maxWidthMhz());
        assertNull(decode(join(probe, new byte[]{45, 26, 1}), 1000));
        assertNull(decode(join(probe, new byte[]{45}), 1000));
    }

    @Test void retainsAtMostOneSignalSamplePerSecondAndSeparatesFingerprintSources() throws Exception {
        var clock = new java.util.concurrent.atomic.AtomicLong(1_000);
        var session = new PassiveWifiSession(new DeviceProfiler(), MyNetworkProfile.EMPTY, clock::get);
        byte[] probe = ProbeFrames.frame("Fixture");
        for (int i = 0; i < 70; i++) {
            long now = clock.getAndAdd(1000);
            var packet = ProbeFrames.radiotap(probe);
            session.observe(Dot11FrameDecoder.decodeAny(packet, 127, now));
            packet[12] = -61;
            session.observe(Dot11FrameDecoder.decodeAny(packet, 127, now + 200));
        }
        byte[] association = join(header(0, 0, AP, CLIENT, AP, 1), new byte[4], Arrays.copyOfRange(probe, 24, probe.length));
        session.observe(decode(association, clock.get()));
        String id = session.addressId(CLIENT);
        var detail = session.inventoryDetail(id);
        assertEquals(64, detail.signalHistory().size());
        assertEquals(new WifiInventory.SignalSample(7_200, -61), detail.signalHistory().getFirst());
        assertEquals(new WifiInventory.SignalSample(70_200, -61), detail.signalHistory().getLast());
        assertEquals(2, detail.fingerprints().size());
        assertEquals(detail.fingerprints().getFirst().hash(), detail.fingerprints().getLast().hash());
        assertEquals(WifiInventory.FrameSource.ASSOCIATION_REQUEST, detail.fingerprints().getFirst().source());
        assertEquals(140, detail.fingerprints().getLast().observations());
        assertEquals(WifiInventory.FrameSource.PROBE_REQUEST, detail.fingerprints().getLast().source());
        clock.addAndGet(RfSettings.retentionMillis() + 1);
        assertNull(session.inventoryDetail(id));
    }

    @Test void namesAdvertisedSecuritySuitesAndKeepsUnknownSelectors() {
        var ids = new SessionIdentifiers();
        var topology = new TopologyBuilder(ids);
        byte[] rsn = HEX.parseHex("0100000fac040100000fac040300000fac02000fac0800112208c000");
        byte[] wpa = HEX.parseHex("0050f20101000050f20201000050f20201000050f202");
        observe(topology, ids, decode(join(beacon(8, AP, new byte[0], 1), ie(48, rsn), ie(221, wpa)), 1000));
        var ap = topology.snapshot().accessPoints().getFirst();
        assertEquals("RSN[000fac04;000fac04;000fac02,000fac08,00112208]+WPA[0050f202;0050f202;0050f202]", ap.security());
        assertEquals(List.of(new TopologyBuilder.AdvertisedSecurity("RSN", "CCMP-128", List.of("CCMP-128"),
                        List.of("PSK", "SAE", "0x00112208"), "Required"),
                new TopologyBuilder.AdvertisedSecurity("WPA", "TKIP", List.of("TKIP"), List.of("PSK"), null)),
                ap.advertisedSecurity());
        observe(topology, ids, decode(join(beacon(8, AP2, new byte[0], 1), ie(48, new byte[]{1, 0})), 1000));
        var malformed = topology.snapshot().accessPoints().stream().filter(point -> point.bssid().equals(ids.id("wifi", AP2)))
                .findFirst().orElseThrow();
        assertEquals("RSN", malformed.security());
        assertNull(malformed.advertisedSecurity().getFirst().groupCipher());
    }

    @Test void auditsAddressPercentagesAndUuidEPresenceAndExpiresWindow() throws Exception {
        long now = System.currentTimeMillis();
        var profiler = new DeviceProfiler();
        var session = new PassiveWifiSession(profiler);
        byte[] privateProbe = ProbeFrames.frame("NETGEAR42");
        byte[] wps = ie(221, join(HEX.parseHex("0050f20410470010"), new byte[16]));
        var directed = decode(join(privateProbe, wps), now);
        var wildcard = decode(ProbeFrames.frame(new byte[]{0, 0}), now);
        byte[] globalProbe = ProbeFrames.frame("");
        globalProbe[10] = 0;
        session.observe(directed);
        session.observe(wildcard);
        session.observe(decode(globalProbe, now));
        session.observe(decode(privateProbe, now - TimeUnit.MINUTES.toMillis(20)));
        assertTrue(directed.ies().hasWpsUuidE());
        assertFalse(decode(join(privateProbe, ie(221, HEX.parseHex("0050f20410470010"))), now).ies().hasWpsUuidE());
        assertEquals(IeSignature.of(directed.ies()), IeSignature.of(decode(join(ProbeFrames.frame("AnotherSSID"), wps), now).ies()));
        var report = session.audit();
        assertEquals(3, report.totalProbes());
        assertEquals(2, report.totalObservedAddresses());
        assertEquals(50.0, report.locallyAdministeredPct());
        assertEquals(50.0, report.directedPct());
        assertEquals(100.0 / 3, report.wpsUuidEPct());
        assertEquals(1, report.distinctDirectedSsids());
        assertEquals(1L, report.ssidExposureCounts().get("ROUTER_DEFAULT_PATTERN"));
        assertEquals(1, report.directedPerAddress().get("1"));
        assertFalse(report.toString().contains("NETGEAR42"));

        var other = new PassiveWifiSession(profiler);
        other.observe(directed);
        assertNotEquals(report.ssidTokens(), other.audit().ssidTokens());
        assertTrue(profiler.all().isEmpty());
    }

    @Test void probeDetailsRequireExplicitOptInAndStillUseSessionTokens() throws Exception {
        long now = System.currentTimeMillis();
        var probe = decode(ProbeFrames.frame("JIOFIBER fixture"), now);
        var normal = new PassiveWifiSession(new DeviceProfiler());
        normal.observe(probe);
        var anonymous = normal.audit().corpus().getFirst();
        assertNull(anonymous.name());
        assertNull(anonymous.deviceCount());
        assertTrue(anonymous.devices().isEmpty());
        assertEquals(1, anonymous.timeline().stream().mapToInt(Integer::intValue).sum());

        String previous = System.getProperty("audit.deviceDetails");
        try {
            System.setProperty("audit.deviceDetails", "true");
            var optIn = new PassiveWifiSession(new DeviceProfiler());
            optIn.observe(probe);
            var row = optIn.audit().corpus().getFirst();
            assertEquals(1, row.deviceCount());
            assertNull(row.name());
            assertEquals(optIn.inventory().getFirst().id(), row.devices().getFirst().id());
            assertNotEquals(CLIENT, row.devices().getFirst().id());
        } finally {
            if (previous == null) System.clearProperty("audit.deviceDetails");
            else System.setProperty("audit.deviceDetails", previous);
        }
    }

    @Test void scopeFiltersInventoryAndTopologyWithAnIndependentProbeAudit() throws Exception {
        String oldBssids = System.getProperty("rf.bssids");
        String oldProbes = System.getProperty("rf.neighborhoodProbes");
        try {
            System.setProperty("rf.bssids", AP.toUpperCase(java.util.Locale.ROOT));
            System.clearProperty("rf.neighborhoodProbes");
            long now = System.currentTimeMillis();
            var session = new PassiveWifiSession(new DeviceProfiler());
            assertEquals(session.addressId(AP), session.preferredApId());
            assertTrue(session.observe(decode(beacon(8, AP, new byte[0], 1), now)).inventory());
            assertFalse(session.observe(decode(beacon(8, AP2, new byte[0], 1), now)).inventory());
            assertFalse(session.observe(decode(ProbeFrames.frame("Neighbor"), now)).probe());
            assertFalse(session.observe(decode(header(8, 1, AP2, CLIENT, AP, 1), now)).inventory());
            assertFalse(session.observe(decode(join(header(8, 3, AP, CLIENT, AP2, 2), mac(AP3)), now)).inventory());
            assertEquals(List.of(session.addressId(AP)), session.inventory().stream().map(WifiInventory.Device::id).toList());
            assertEquals(List.of(session.addressId(AP)), session.topology().accessPoints().stream()
                    .map(TopologyBuilder.AccessPoint::bssid).toList());
            assertEquals(0, session.audit().totalProbes());

            for (int seq = 3; seq < 6; seq++)
                assertTrue(session.observe(decode(header(8, 1, AP, CLIENT, AP2, seq), now)).inventory());
            assertEquals(session.addressId(CLIENT), session.topology().edges().getFirst().clientId());
            var reassoc = join(header(0x20, 0, AP, CLIENT, AP, 7), new byte[4], mac(AP2), ie(0, new byte[0]));
            session.observe(decode(reassoc, now));
            assertTrue(session.topology().roams().isEmpty());

            System.setProperty("rf.neighborhoodProbes", "true");
            var auditOnly = new PassiveWifiSession(new DeviceProfiler());
            var observation = auditOnly.observe(decode(ProbeFrames.frame("Neighbor"), now));
            assertFalse(observation.inventory());
            assertTrue(observation.probe());
            assertEquals(1, auditOnly.audit().totalProbes());
            assertTrue(auditOnly.inventory().isEmpty());
            assertTrue(auditOnly.topology().accessPoints().isEmpty());

            System.setProperty("rf.bssids", "ff:ff:ff:ff:ff:ff");
            assertThrows(IllegalArgumentException.class, () -> new PassiveWifiSession(new DeviceProfiler()));
        } finally {
            restoreProperty("rf.bssids", oldBssids);
            restoreProperty("rf.neighborhoodProbes", oldProbes);
        }
    }

    private static void restoreProperty(String name, String previous) {
        if (previous == null) System.clearProperty(name);
        else System.setProperty(name, previous);
    }

    @Test void distinguishesDataFromAssociationAndExpiresOnLastConfirmingEvidence() {
        var ids = new SessionIdentifiers();
        var topology = new TopologyBuilder(ids);
        long start = 1000;
        byte[] request = join(header(0, 0, AP, CLIENT, AP, 1), new byte[4]);
        observe(topology, ids, decode(request, start));
        assertTrue(topology.snapshot().edges().isEmpty());
        for (int i = 0; i < 3; i++) {
            byte[] frame = ProbeFrames.radiotap(header(8, 1, AP, CLIENT, AP2, i + 2));
            observe(topology, ids, Dot11FrameDecoder.decodeAny(frame, 127, start + 100 + i));
        }
        var data = topology.snapshot().edges().getFirst();
        assertEquals("DATA", data.source());
        assertEquals(start + 102, data.lastDataSeen());
        assertEquals(start + 102, data.lastSeen());
        assertNull(data.associationSeen());
        assertEquals(6, data.channel());
        assertEquals(2437, data.frequencyMhz());
        assertEquals(3, data.uplink());
        assertEquals(0, data.downlink());

        byte[] response = join(header(0x10, 0, CLIENT, AP, AP, 5), new byte[6]);
        observe(topology, ids, decode(response, start + 200));
        var association = topology.snapshot().edges().getFirst();
        assertEquals("ASSOC", association.source());
        assertEquals(start + 200, association.associationSeen());
        assertEquals(start + 102, association.lastDataSeen());
        observe(topology, ids, decode(request, start + 300));
        assertEquals(association.expiresAt(), topology.snapshot().edges().getFirst().expiresAt());
        topology.purge(association.expiresAt(), TimeUnit.HOURS.toMillis(24));
        assertTrue(topology.snapshot().edges().isEmpty());
    }

    @Test void mapsConfirmedEdgesAndHiddenNamesWithoutPayloadsOrMulticastClients() throws Exception {
        var ids = new SessionIdentifiers();
        var topology = new TopologyBuilder(ids);
        long time = 1_000;
        var hidden = decode(beacon(8, AP, new byte[]{0, 0}, 1), time);
        observe(topology, ids, hidden);
        assertTrue(topology.snapshot().accessPoints().getFirst().ssidHidden());
        assertNull(topology.snapshot().accessPoints().getFirst().ssidToken());
        observe(topology, ids, decode(beacon(5, AP, "SecretSSID".getBytes(StandardCharsets.US_ASCII), 2), ++time));
        var named = topology.snapshot().accessPoints().getFirst();
        assertEquals("PROBE_RESP", named.ssidRevealedVia());
        assertNotEquals("SecretSSID", named.ssidToken());

        byte[] payload = "private-payload".getBytes(StandardCharsets.US_ASCII);
        observe(topology, ids, decode(join(header(8, 1, AP, CLIENT, AP2, 1), payload), ++time));
        observe(topology, ids, decode(join(header(8, 9, AP, CLIENT, AP2, 1), payload), ++time));
        observe(topology, ids, decode(header(8, 1, AP, CLIENT, AP2, 2), ++time));
        observe(topology, ids, decode(header(8, 2, BROADCAST, AP, CLIENT, 3), ++time));
        observe(topology, ids, decode(header(8, 0, AP, CLIENT, AP2, 3), ++time));
        assertTrue(topology.snapshot().edges().isEmpty());
        byte[] wds = join(header(8, 3, AP, CLIENT, AP2, 4), mac(AP3), payload);
        var wdsFrame = decode(wds, ++time);
        assertEquals(AP3, wdsFrame.addr4());
        assertNull(wdsFrame.ies());
        observe(topology, ids, wdsFrame);
        observe(topology, ids, decode(header(8, 2, CLIENT, AP, AP2, 5), ++time));
        var edge = topology.snapshot().edges().getFirst();
        assertEquals(3, edge.evidenceCount());
        assertEquals(2, edge.uplink());
        assertEquals(1, edge.downlink());
        byte[] reassoc = join(header(0x20, 0, AP2, CLIENT, AP2, 6), new byte[4], mac(AP), ie(0, new byte[0]));
        observe(topology, ids, decode(reassoc, ++time));
        assertEquals("REASSOC", topology.snapshot().roams().getFirst().method());
        observe(topology, ids, decode(join(header(0x30, 0, CLIENT, AP2, AP2, 7), new byte[6]), ++time));
        assertEquals(2, topology.snapshot().edges().size());
        var dot = TopologyBuilder.dot(topology.snapshot());
        assertFalse(dot.contains("private-payload"));
        assertFalse(dot.contains(CLIENT));
        assertFalse(dot.contains(AP));
        topology.purge(time + TimeUnit.MINUTES.toMillis(11), TimeUnit.HOURS.toMillis(24));
        assertTrue(topology.snapshot().edges().isEmpty());
    }

    @Test void groupsOnlyRepeatedNearEqualClockOffsetsAcrossTsfWrap() {
        var ids = new SessionIdentifiers();
        var topology = new TopologyBuilder(ids);
        for (int i = 0; i < 5; i++) {
            long receiver = -200 + i * 100L;
            observe(topology, ids, clockBeacon(AP, 1000 + i * 100, receiver, receiver + 30));
            observe(topology, ids, clockBeacon(AP2, 1003 + i * 100, receiver + 5, receiver + 50));
            observe(topology, ids, clockBeacon(AP3, 1004 + i * 100, receiver, receiver + 10000));
        }
        var aps = topology.snapshot().accessPoints();
        assertEquals(3, aps.size());
        assertEquals(2, aps.stream().filter(ap -> ap.radioGroupId() != null).count());
        assertEquals(1, aps.stream().map(TopologyBuilder.AccessPoint::radioGroupId).filter(java.util.Objects::nonNull).distinct().count());
    }

    private static Dot11Frame clockBeacon(String source, long time, long receiver, long tsf) {
        byte[] wifi = beacon(8, source, new byte[0], tsf);
        byte[] packet = ByteBuffer.allocate(20 + wifi.length).order(ByteOrder.LITTLE_ENDIAN)
                .putShort((short) 0).putShort((short) 20).putInt(9).putLong(receiver)
                .putShort((short) 5180).putShort((short) 0).put(wifi).array();
        return Dot11FrameDecoder.decodeAny(packet, 127, time);
    }

    private static void observe(TopologyBuilder topology, SessionIdentifiers ids, Dot11Frame frame) {
        topology.observe(frame, ids.id("wifi", frame.addr2()));
    }

    private static Dot11Frame decode(byte[] bytes, long time) { return Dot11FrameDecoder.decodeAny(bytes, 105, time); }

    private static byte[] beacon(int subtype, String ap, byte[] ssid, long tsf) {
        byte[] fixed = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN)
                .putLong(tsf).putShort((short) 100).putShort((short) 1).array();
        return join(header(subtype << 4, 0, BROADCAST, ap, ap, 1), fixed, ie(0, ssid));
    }

    private static byte[] header(int control, int flags, String a, String b, String c, int sequence) {
        return ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN).put((byte) control).put((byte) flags)
                .putShort((short) 0).put(mac(a)).put(mac(b)).put(mac(c)).putShort((short) (sequence << 4)).array();
    }

    private static byte[] mac(String address) { return HexFormat.ofDelimiter(":").parseHex(address); }
    private static byte[] ie(int id, byte[] value) { return join(new byte[]{(byte) id, (byte) value.length}, value); }

    private static byte[] join(byte[]... bytes) {
        var result = ByteBuffer.allocate(Arrays.stream(bytes).mapToInt(value -> value.length).sum());
        for (byte[] part : bytes) result.put(part);
        return result.array();
    }
}
