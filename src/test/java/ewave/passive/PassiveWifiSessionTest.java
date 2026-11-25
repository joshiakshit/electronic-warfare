package ewave.passive;

import com.fasterxml.jackson.databind.ObjectMapper;
import ewave.decoder.CapabilityDecoder;
import ewave.decoder.Dot11ChannelSwitchDecoder;
import ewave.decoder.Dot11Frame;
import ewave.decoder.IeSignature;
import ewave.decoder.Dot11FrameDecoder;
import ewave.fixtures.ProbeFrames;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
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

    @Test void decodesAllEhtMapsOnSixGhzDespiteAReservedTwoGhzWidthBit() {
        byte[] he = new byte[22], eht = new byte[21];
        he[0] = 35;
        he[18] = (byte) 0xf0;
        he[19] = (byte) 0xff;
        he[7] = 14; // Mixed 2.4/5 GHz flags; only the current band's maps apply.
        eht[0] = 108;
        eht[3] = 2;
        eht[12] = 2;
        eht[15] = 4;
        eht[18] = 8;
        byte[] frame = join(ProbeFrames.frame(""), ie(255, he), ie(255, eht));
        var six = CapabilityDecoder.decode(decode(frame, 1000).ies(), 5975);
        assertEquals("Wi-Fi 7", six.wifiGeneration());
        assertEquals(8, six.spatialStreams());
        assertEquals(320, six.maxWidthMhz());
        assertEquals(8, CapabilityDecoder.decode(decode(frame, 1000).ies(), 0).spatialStreams());
        var two = CapabilityDecoder.decode(decode(frame, 1000).ies(), 2437);
        assertEquals(2, two.spatialStreams());
        var truncated = CapabilityDecoder.decode(decode(join(ProbeFrames.frame(""), ie(255, he),
                ie(255, Arrays.copyOf(eht, 18))), 1000).ies(), 5975);
        assertNotEquals("Wi-Fi 7", truncated.wifiGeneration());
    }

    @Test void selectableApsExcludeDataOnlyAndExpiredTopologyRows() throws Exception {
        var clock = new java.util.concurrent.atomic.AtomicLong(1000);
        var session = new PassiveWifiSession(new DeviceProfiler(), MyNetworkProfile.EMPTY, clock::get);
        session.observe(Dot11FrameDecoder.decodeAny(ProbeFrames.radiotap(beacon(8, AP,
                "Lab".getBytes(StandardCharsets.UTF_8), 1)), 127, clock.get()));
        for (int i = 1; i <= 3; i++) session.observe(Dot11FrameDecoder.decodeAny(
                ProbeFrames.radiotap(header(8, 1, AP2, CLIENT, AP2, i)), 127, clock.get()));
        assertEquals(2, session.topology().accessPoints().size());
        assertEquals(List.of(session.addressId(AP)), session.selectableAccessPoints().stream()
                .map(PassiveWifiSession.SelectableAccessPoint::bssid).toList());
        assertEquals(2437, session.selectableAccessPoints().getFirst().frequencyMhz());
        clock.addAndGet(TimeUnit.MINUTES.toMillis(11));
        assertEquals(2, session.topology().accessPoints().size(), "Historical reports retain the APs");
        assertTrue(session.selectableAccessPoints().isEmpty());
        assertNull(session.observedAp(session.addressId(AP)));
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

    @Test void savedFingerprintSamplesClassifyRetainedAndNewSessionDevices() throws Exception {
        var clock = new java.util.concurrent.atomic.AtomicLong(1_000);
        var session = new PassiveWifiSession(new DeviceProfiler(), MyNetworkProfile.EMPTY, clock::get);
        byte[] probe = ProbeFrames.frame("Fixture");
        session.observe(Dot11FrameDecoder.decodeAny(ProbeFrames.radiotap(probe), 127, clock.get()));
        String id = session.addressId(CLIENT);
        assertNull(session.inventory().getFirst().fingerprintHint());
        var evidence = session.inventoryDetail(id).fingerprints().getFirst();
        var profile = MyNetworkProfile.EMPTY.saveSample(new MyNetworkProfile.SampleChange(id, evidence.hash(),
                evidence.source(), "Phone", "Fixture OS"), evidence);

        session.useFingerprintSamples(profile.fingerprintSamples());
        var device = session.inventory().getFirst();
        assertEquals("Phone", device.classLabel());
        assertEquals(new WifiInventory.FingerprintHint("Phone", "Fixture OS", FingerprintDb.SAMPLE_CONFIDENCE),
                device.fingerprintHint());

        var fresh = new PassiveWifiSession(new DeviceProfiler(), profile, clock::get);
        fresh.observe(Dot11FrameDecoder.decodeAny(ProbeFrames.radiotap(probe), 127, clock.get()));
        assertEquals("Phone", fresh.inventory().getFirst().fingerprintHint().family());

        session.useFingerprintSamples(profile.removeSample(profile.fingerprintSamples().getFirst().id()).fingerprintSamples());
        assertNull(session.inventory().getFirst().fingerprintHint());
        assertNotEquals("Phone", session.inventory().getFirst().classLabel());
    }

    @Test void conflictingSavedSamplesUseTheMajorityClassWithReducedConfidence() throws Exception {
        var evidence = new WifiInventory.FingerprintObservation("0123456789abcdef",
                WifiInventory.FrameSource.PROBE_REQUEST, 1, "Wi-Fi 6", 80, 2);
        var other = new WifiInventory.FingerprintObservation("0123456789abcdef",
                WifiInventory.FrameSource.ASSOCIATION_REQUEST, 1, "Wi-Fi 6", 80, 2);
        var db = new FingerprintDb();
        assertNull(db.get(evidence.hash()));
        db.useSamples(List.of(
                new MyNetworkProfile.FingerprintSample(java.util.UUID.randomUUID(), "Laptop", "", evidence),
                new MyNetworkProfile.FingerprintSample(java.util.UUID.randomUUID(), "Phone", "Android", evidence),
                new MyNetworkProfile.FingerprintSample(java.util.UUID.randomUUID(), "Phone", "Android", other)));
        var finding = db.get(evidence.hash());
        assertEquals("Phone", finding.family());
        assertEquals("Android", finding.osHint());
        assertEquals(FingerprintDb.SAMPLE_CONFIDENCE * 2 / 3, finding.confidence(), 1e-9);
        db.useSamples(List.of());
        assertNull(db.get(evidence.hash()));
    }

    @Test void classifiesTheAndroidScanPrefixWithoutRetainingTheDeviceAddress() throws Exception {
        var session = new PassiveWifiSession(new DeviceProfiler(), MyNetworkProfile.EMPTY, () -> 1000);
        String androidMac = "da:a1:19:12:34:56";
        session.observe(decode(ProbeFrames.frame("Fixture", androidMac, 1), 1000));
        var row = session.profilerReport().getFirst();
        assertEquals(session.addressId(androidMac), row.device().id());
        assertEquals("Phone", row.device().classLabel());
        assertEquals("Android", row.device().osHint());
        assertEquals("VENDOR_IE_HEURISTIC", row.device().classificationBasis());
        assertEquals(0.75, row.device().classConfidence());
        assertTrue(row.device().randomizedScanSeen());
        assertNull(row.device().fingerprintHint());
        String json = new ObjectMapper().writeValueAsString(row);
        assertFalse(json.contains(androidMac));
        assertFalse(json.contains("da:a1:19"));
    }

    @Test void dataOnlyClientUsesObservedHePhyUntilManagementCapabilitiesArrive() throws Exception {
        var session = new PassiveWifiSession(new DeviceProfiler(), MyNetworkProfile.EMPTY, () -> 1010);
        for (int i = 1; i <= 3; i++) {
            byte[] data = header(8, 1, AP, CLIENT, AP, i);
            byte[] packet = ByteBuffer.allocate(24 + data.length).order(ByteOrder.LITTLE_ENDIAN)
                    .putShort((short) 0).putShort((short) 24).putInt((1 << 3) | (1 << 23))
                    .putShort((short) 5975).putShort((short) 0)
                    .putShort((short) 0x4020).putShort((short) 0).putInt(0)
                    .putShort((short) 2).putShort((short) 2).put(data).array();
            session.observe(Dot11FrameDecoder.decodeAny(packet, 127, 1000 + i));
        }
        var row = session.profilerReport().getFirst();
        assertNull(row.device().capabilities());
        assertEquals(WifiInventory.Role.CLIENT, row.device().role());
        assertEquals("Wi-Fi 6E", row.device().inferredGeneration());
        assertEquals(80, row.device().inferredWidthMhz());
        assertEquals(2, row.device().inferredStreams());
        assertEquals("Wi-Fi 6E Client", row.device().classLabel());
        assertEquals("RADIOTAP_DATA_HEURISTIC", row.device().classificationBasis());
        assertEquals(0.40, row.device().classConfidence());
        assertNull(row.device().fingerprintHint());
        assertEquals("DATA", row.associatedAp().source());

        byte[] legacyProbe = Arrays.copyOf(ProbeFrames.frame("Fixture", CLIENT, 4), 24 + 2 + "Fixture".length() + 6);
        session.observe(decode(legacyProbe, 1010));
        var advertised = session.profilerReport().getFirst().device();
        assertEquals("802.11b", advertised.capabilities().wifiGeneration());
        assertNull(advertised.inferredGeneration());
        assertEquals("UNCLASSIFIED", advertised.classLabel());
    }

    @Test void enrichesDevicesWithEnrollmentAndOnlyTheCurrentConfirmedAssociation() throws Exception {
        var enrollment = new MyNetworkProfile(List.of(new MyNetworkProfile.Entry(UUID.randomUUID(), AP, "Lab router")),
                List.of(new MyNetworkProfile.Entry(UUID.randomUUID(), CLIENT, "Lab client")), false);
        var session = new PassiveWifiSession(new DeviceProfiler(), enrollment, () -> 2000);
        String clientId = session.addressId(CLIENT), apId = session.addressId(AP), secondApId = session.addressId(AP2);
        session.observe(Dot11FrameDecoder.decodeAny(radiotapFreq(beacon(8, AP, ssid("Lab Wi-Fi"), 0), 2437), 127, 1000));
        session.observe(decode(associationRequest(AP, CLIENT, "Lab Wi-Fi"), 1100));
        assertNull(session.inventoryDetail(clientId).associatedAp());
        session.observe(decode(associationStatus(AP, CLIENT, 0), 1200));

        var first = new WifiInventory.AssociatedAp(apId, "Lab Wi-Fi", 6, 2437, "ASSOC");
        var detail = session.inventoryDetail(clientId);
        assertEquals(first, detail.associatedAp());
        assertEquals("Lab client", detail.enrolledLabel());
        var report = session.profilerReport();
        var client = report.stream().filter(row -> row.device().id().equals(clientId)).findFirst().orElseThrow();
        var accessPoint = report.stream().filter(row -> row.device().id().equals(apId)).findFirst().orElseThrow();
        assertEquals("Lab client", client.enrolledLabel());
        assertEquals(first, client.associatedAp());
        assertEquals("Lab router", accessPoint.enrolledLabel());
        assertNull(accessPoint.associatedAp());

        session.observe(Dot11FrameDecoder.decodeAny(radiotapFreq(beacon(8, AP2, ssid("Lab 5 GHz"), 0), 5180), 127, 1300));
        session.observe(decode(associationStatus(AP2, CLIENT, 0), 1400));
        assertEquals(new WifiInventory.AssociatedAp(secondApId, "Lab 5 GHz", 36, 5180, "ASSOC"),
                session.inventoryDetail(clientId).associatedAp());
        session.observe(decode(join(header(0xc0, 0, CLIENT, AP2, AP2, 9), new byte[]{3, 0}), 1500));
        assertNull(session.inventoryDetail(clientId).associatedAp());

        assertFalse(session.configure(MyNetworkProfile.EMPTY));
        assertNull(session.inventoryDetail(clientId).enrolledLabel());
        String json = new ObjectMapper().writeValueAsString(List.of(report, detail));
        assertFalse(json.contains(CLIENT));
        assertFalse(json.contains(AP));
    }

    @Test void retainsOrderedFingerprintEvidenceAndReadsLegacySavedSamples() throws Exception {
        var session = new PassiveWifiSession(new DeviceProfiler(), MyNetworkProfile.EMPTY, () -> 1000);
        byte[] he = new byte[22];
        he[0] = 35;
        byte[] legacyProbe = Arrays.copyOf(ProbeFrames.frame("Fixture"), 24 + 2 + "Fixture".length() + 6);
        var probe = decode(join(legacyProbe, ie(50, new byte[]{12}), ie(255, he),
                ie(221, HEX.parseHex("0017f201")), ie(221, HEX.parseHex("0050f204")),
                ie(221, HEX.parseHex("0050f202")), ie(221, HEX.parseHex("506f9a09")),
                ie(221, HEX.parseHex("0017f201"))), 1000);
        session.observe(probe);
        var observed = session.inventoryDetail(session.addressId(CLIENT)).fingerprints().getFirst();
        assertEquals(List.of("1", "50", "255:35", "221", "221", "221", "221", "221"), observed.ieOrder());
        assertEquals(List.of("00:17:f2 (Apple)", "00:50:f2:04 (WPS)", "00:50:f2:02 (WMM)",
                "50:6f:9a:09 (Wi-Fi P2P)"), observed.vendorElements());
        assertNotNull(observed.bandCohort());
        assertEquals(IeSignature.bandInvariantCohortOf(probe.ies()), observed.bandCohort());

        var mapper = new ObjectMapper();
        var sample = new MyNetworkProfile.FingerprintSample(UUID.randomUUID(), "Reference", "Fixture OS", observed);
        var profile = new MyNetworkProfile(List.of(), List.of(), false, List.of(sample));
        var enrichedJson = mapper.valueToTree(profile);
        assertEquals(profile, mapper.treeToValue(enrichedJson, MyNetworkProfile.class));
        var evidenceJson = (com.fasterxml.jackson.databind.node.ObjectNode) enrichedJson.at("/fingerprintSamples/0/evidence");
        evidenceJson.remove(List.of("ieOrder", "vendorElements", "bandCohort"));
        var legacy = mapper.treeToValue(enrichedJson, MyNetworkProfile.class);
        assertEquals(new WifiInventory.FingerprintObservation(observed.hash(), observed.source(), 1,
                observed.generation(), observed.maxWidthMhz(), observed.spatialStreams()), legacy.fingerprintSamples().getFirst().evidence());
        assertEquals(enrichedJson, mapper.valueToTree(legacy));

        session.useFingerprintSamples(legacy.fingerprintSamples());
        var device = session.inventory().getFirst();
        assertEquals("SAVED_SAMPLE", device.classificationBasis());
        assertEquals("Reference", device.fingerprintHint().family());
        session.useFingerprintSamples(List.of());
        assertEquals("VENDOR_IE_HEURISTIC", session.inventory().getFirst().classificationBasis());
        assertNull(session.inventory().getFirst().fingerprintHint());
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

    @Test void inspectorDecodesRsnTailAndChecksItsBounds() {
        var ids = new SessionIdentifiers();
        var topology = new TopologyBuilder(ids);
        byte[] rsn = HEX.parseHex("0100000fac040100000fac040100000fac08c040");
        byte[] extended = new byte[11];
        extended[10] = 0x10;
        byte[] ap = beacon(8, AP, ssid("Secure"), 1);
        observe(topology, ids, decode(join(ap, ie(48, join(rsn, HEX.parseHex("0000000fac06"))),
                ie(244, new byte[]{0x70}), ie(127, extended)), 1000));
        var point = accessPoint(topology, ids, AP);
        assertEquals("BIP-CMAC-128", point.groupManagementCipher());
        assertTrue(point.ocvc());
        assertTrue(point.beaconProtection());
        assertEquals(List.of("SAE H2E", "SAE-PK", "Protected TWT"), point.rsnxeFeatures());
        assertTrue(ApSecurityAuditor.audit(topology.snapshot()).get(point.bssid()).isEmpty());

        observe(topology, ids, decode(join(ap, ie(48, join(rsn, new byte[]{1, 0}, new byte[16], HEX.parseHex("000fac0c"))),
                ie(244, new byte[]{0x71})), 1001));
        point = accessPoint(topology, ids, AP);
        assertEquals("BIP-GMAC-256", point.groupManagementCipher());
        assertTrue(point.rsnxeFeatures().isEmpty());
        assertFalse(point.beaconProtection());
        assertTrue(findingCodes(topology, ids, AP).contains("SAE_HNP_ENABLED"));

        observe(topology, ids, decode(join(ap, ie(48, join(rsn, HEX.parseHex("0200000fac06")))), 1002));
        assertNull(accessPoint(topology, ids, AP).groupManagementCipher());
        assertTrue(accessPoint(topology, ids, AP).ocvc());
    }

    @Test void inspectorReportsOperatingWidthIndependentlyOfRadioCapabilities() {
        var ids = new SessionIdentifiers();
        var topology = new TopologyBuilder(ids);
        byte[] ap = beacon(8, AP, ssid("Radio"), 1);
        byte[] ht = new byte[26], vht = new byte[12], he = new byte[22], eht = new byte[21];
        ht[0] = 2;
        ht[3] = ht[4] = (byte) 0xff;
        vht[4] = (byte) 0xf0;
        vht[5] = (byte) 0xff;
        he[0] = 35;
        he[7] = 4;
        he[18] = (byte) 0xf0;
        he[19] = (byte) 0xff;
        eht[0] = 108;
        eht[3] = 2;
        eht[15] = 4;
        byte[] htOp = ie(61, new byte[]{36, 5}), heCaps = ie(255, he), ehtCaps = ie(255, eht);

        observe(topology, ids, decode(join(ap, ie(45, ht), htOp), 1000));
        assertEquals(new TopologyBuilder.ApRadioSummary("Wi-Fi 4", 40, 40, 2, null),
                accessPoint(topology, ids, AP).apRadio());
        observe(topology, ids, decode(join(ap, ie(191, vht), htOp, ie(192, new byte[]{1, 42, 0})), 1001));
        assertEquals(new TopologyBuilder.ApRadioSummary("Wi-Fi 5", 80, 80, 2, null),
                accessPoint(topology, ids, AP).apRadio());
        observe(topology, ids, decode(join(ap, ie(191, vht), htOp, ie(192, new byte[]{1, 42, 50})), 1002));
        assertEquals(160, accessPoint(topology, ids, AP).apRadio().operatingWidthMhz());

        byte[] heOp = ie(255, HEX.parseHex("2400c002510000000000010502070000"));
        observe(topology, ids, Dot11FrameDecoder.decodeAny(radiotapFreq(join(ap, heCaps, heOp), 5975), 127, 1003));
        assertEquals(new TopologyBuilder.ApRadioSummary("Wi-Fi 6E", 80, 80, 2, 17),
                accessPoint(topology, ids, AP).apRadio());
        byte[] ehtOp = ie(255, HEX.parseHex("6a0100000000041f3f"));
        observe(topology, ids, Dot11FrameDecoder.decodeAny(
                radiotapFreq(join(ap, heCaps, heOp, ehtCaps, ehtOp), 5975), 127, 1004));
        assertEquals(new TopologyBuilder.ApRadioSummary("Wi-Fi 7", 320, 320, 4, 17),
                accessPoint(topology, ids, AP).apRadio());
        observe(topology, ids, decode(join(ap, htOp, ie(255, HEX.parseHex("240000028b00000503")),
                ie(255, HEX.parseHex("6a0100000000071f3f"))), 1005));
        assertEquals(40, accessPoint(topology, ids, AP).apRadio().operatingWidthMhz());
        assertNull(accessPoint(topology, ids, AP).apRadio().bssColor());
    }

    @Test void inspectorFindsColorCollisionsOnlyBetweenRadiosOnTheSameFrequency() {
        var ids = new SessionIdentifiers();
        var topology = new TopologyBuilder(ids);
        byte[] color = ie(255, HEX.parseHex("24000000110000"));
        for (int i = 0; i < 5; i++) {
            long time = 1000 + i * 100, clock = time * 1000;
            observe(topology, ids, clockBeacon(join(beacon(8, AP, ssid("One"), clock), color), time, clock, clock + 30));
            observe(topology, ids, clockBeacon(join(beacon(8, AP2, ssid("Two"), clock), color), time, clock, clock + 30));
        }
        assertNotNull(accessPoint(topology, ids, AP).radioGroupId());
        assertEquals(accessPoint(topology, ids, AP).radioGroupId(), accessPoint(topology, ids, AP2).radioGroupId());
        assertFalse(findingCodes(topology, ids, AP).contains("BSS_COLOR_COLLISION"));

        String elsewhere = "02:aa:bb:cc:dd:f1";
        observe(topology, ids, Dot11FrameDecoder.decodeAny(
                radiotapFreq(join(beacon(8, AP3, ssid("Three"), 1), color), 5180), 127, 1500));
        observe(topology, ids, Dot11FrameDecoder.decodeAny(
                radiotapFreq(join(beacon(8, elsewhere, ssid("Four"), 1), color), 5200), 127, 1501));
        for (String address : List.of(AP, AP2, AP3))
            assertTrue(findingCodes(topology, ids, address).contains("BSS_COLOR_COLLISION"), address);
        assertFalse(findingCodes(topology, ids, elsewhere).contains("BSS_COLOR_COLLISION"));
    }

    @Test void inspectorMergesWpsHardwareAndLockStateAndResolvesApVendors() throws Exception {
        long now = 1_100;
        var oui = new OuiLookup(new ByteArrayInputStream(ssid("00:AA:BB Cisco fixture\n02:AA:BB Aruba fixture\n")));
        var session = PassiveWifiSession.forReplay(new DeviceProfiler(oui), MyNetworkProfile.EMPTY, () -> now);
        byte[] ccx = new byte[26];
        byte[] ciscoName = ssid("HQ-\u0001Cisco\0skip");
        System.arraycopy(ciscoName, 0, ccx, 10, ciscoName.length);
        session.observe(decode(join(beacon(8, AP, ssid("Office"), 1), ie(133, ccx),
                ie(221, HEX.parseHex("0050f20410440001021057000100"))), 1000));
        byte[] wpsModel = join(HEX.parseHex("0050f2041023000b"), ssid("Archer\n C20"),
                HEX.parseHex("10240003312e3010110041"), ssid("A".repeat(65)), HEX.parseHex("10210100"));
        session.observe(decode(join(beacon(5, AP, ssid("Office"), 2), ie(221, wpsModel)), 1010));
        session.observe(decode(join(beacon(5, AP, ssid("Office"), 3),
                ie(221, HEX.parseHex("0050f2041057000101"))), 999));

        String locallyRegistered = "02:aa:bb:cc:dd:ee", locallyUnknown = "02:bb:cc:dd:ee:ff";
        session.observe(decode(join(beacon(8, locallyRegistered, ssid("Annex"), 1),
                ie(221, join(HEX.parseHex("000b860103"), ssid("AP-\tAruba\0suffix")))), 1012));
        session.observe(decode(beacon(8, locallyUnknown, ssid("Guest"), 1), 1013));
        var topology = session.topology();
        var ap = topology.accessPoints().stream().filter(row -> row.bssid().equals(session.addressId(AP))).findFirst().orElseThrow();
        assertEquals("Cisco fixture", ap.vendor());
        assertEquals("HQ-Cisco", ap.apHostname());
        assertEquals("Configured", ap.wpsInfo().state());
        assertEquals(Boolean.FALSE, ap.wpsInfo().apSetupLocked());
        assertEquals("Archer C20", ap.wpsInfo().modelName());
        assertEquals("1.0", ap.wpsInfo().modelNumber());
        assertEquals("A".repeat(64), ap.wpsInfo().deviceName());
        assertNull(ap.wpsInfo().manufacturer());
        assertTrue(ApSecurityAuditor.audit(topology).get(ap.bssid()).stream()
                .anyMatch(finding -> finding.code().equals("WPS_UNLOCKED") && finding.severity().equals("MEDIUM")));
        assertTrue(topology.accessPoints().stream().anyMatch(row -> "Aruba fixture".equals(row.vendor())
                && "AP-Aruba".equals(row.apHostname())));
        assertTrue(topology.accessPoints().stream().anyMatch(row -> "Locally administered".equals(row.vendor())
                && row.bssid().equals(session.addressId(locallyUnknown))));

        session.observe(decode(join(beacon(8, AP, ssid("Office"), 4),
                ie(221, HEX.parseHex("0050f2041057000101"))), 1005));
        var updated = session.topology();
        assertFalse(ApSecurityAuditor.audit(updated).get(ap.bssid()).stream()
                .anyMatch(finding -> finding.code().equals("WPS_UNLOCKED")));
        assertTrue(updated.accessPoints().stream().anyMatch(row -> row.bssid().equals(ap.bssid())
                && "Archer C20".equals(row.wpsInfo().modelName())));
    }

    @Test void inspectorFlagsWeakerSameNameApsAndExemptsOweTransition() {
        var ids = new SessionIdentifiers();
        var topology = new TopologyBuilder(ids);
        byte[] enterprise = ie(48, HEX.parseHex("0100000fac040100000fac040100000fac01c000"));
        byte[] pskTkip = ie(48, HEX.parseHex("0100000fac020100000fac020100000fac020000"));
        observe(topology, ids, decode(join(beacon(8, AP, ssid("Staff"), 1), enterprise), 1000));
        observe(topology, ids, decode(join(beacon(8, AP2, ssid("Staff"), 1), pskTkip), 1001));
        observe(topology, ids, decode(beacon(8, AP3, ssid("Staff"), 1), 1002));
        String differentCase = "02:aa:bb:cc:dd:fa";
        observe(topology, ids, decode(beacon(8, differentCase, ssid("staff"), 1), 1003));
        assertTrue(findingCodes(topology, ids, AP).isEmpty());
        assertEquals(List.of("ESS_SECURITY_DOWNGRADE", "WEAK_CIPHER", "PMF_DISABLED"), findingCodes(topology, ids, AP2));
        assertEquals("LOW", ApSecurityAuditor.audit(topology.snapshot()).get(ids.id("wifi", AP2)).getLast().severity());
        assertEquals(List.of("ESS_SECURITY_DOWNGRADE", "UNENCRYPTED_OPEN"), findingCodes(topology, ids, AP3));
        assertEquals(List.of("UNENCRYPTED_OPEN"), findingCodes(topology, ids, differentCase));

        byte[] owe = ie(48, HEX.parseHex("0100000fac040100000fac040100000fac120000"));
        observe(topology, ids, decode(join(beacon(8, AP, ssid("Guest"), 2), owe, oweTransition(AP2, "Guest")), 1010));
        observe(topology, ids, decode(join(beacon(8, AP2, ssid("Guest"), 2), oweTransition(AP, "Guest")), 1011));
        var findings = ApSecurityAuditor.audit(topology.snapshot()).get(ids.id("wifi", AP));
        assertEquals(List.of("UNENCRYPTED_OPEN"), findingCodes(topology, ids, AP2));
        assertEquals(List.of("PMF_DISABLED"), findings.stream().map(ApSecurityAuditor.SecurityFinding::code).toList());
        assertEquals("HIGH", findings.getFirst().severity());
    }

    private static List<String> findingCodes(TopologyBuilder topology, SessionIdentifiers ids, String bssid) {
        return ApSecurityAuditor.audit(topology.snapshot()).get(ids.id("wifi", bssid)).stream()
                .map(ApSecurityAuditor.SecurityFinding::code).toList();
    }

    @Test void auditsAddressPercentagesAndUuidEPresenceAndExpiresWindow() throws Exception {
        long now = System.currentTimeMillis();
        var profiler = new DeviceProfiler();
        var session = new PassiveWifiSession(profiler);
        byte[] privateProbe = ProbeFrames.frame("NETGEAR42");
        byte[] wps = ie(221, HEX.parseHex("0050f204104700100123456789abcdef0123456789abcdef"));
        var directed = decode(join(privateProbe, wps), now);
        var wildcard = decode(ProbeFrames.frame(new byte[]{0, 0}), now);
        byte[] globalProbe = ProbeFrames.frame("");
        globalProbe[10] = 0;
        session.observe(directed);
        session.observe(wildcard);
        session.observe(decode(globalProbe, now));
        session.observe(decode(privateProbe, now - TimeUnit.MINUTES.toMillis(20)));
        assertTrue(directed.ies().hasWpsUuidE());
        assertArrayEquals(HEX.parseHex("0123456789abcdef0123456789abcdef"), directed.ies().wpsUuidE().orElseThrow());
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
        var row = report.corpus().getFirst();
        assertEquals("NETGEAR42", row.name());
        assertEquals(1, row.deviceCount());
        assertEquals(ProbeAuditAggregator.Source.PLAINTEXT_SSID, row.source());
        assertEquals(session.addressId(CLIENT), row.devices().getFirst().id());
        assertNotEquals(CLIENT, row.devices().getFirst().id());
        assertEquals(List.of("NETGEAR42"), report.ssidTokens().get("ROUTER_DEFAULT_PATTERN"));

        var other = new PassiveWifiSession(profiler);
        other.observe(directed);
        assertEquals(report.ssidTokens(), other.audit().ssidTokens());
        assertNotEquals(row.id(), other.audit().corpus().getFirst().id());
        assertTrue(profiler.all().isEmpty());
    }

    @Test void revealsProbeNamesAndTokenizedDevicesInLiveAndReplaySessions() throws Exception {
        long now = 1_000L;
        var profiler = new DeviceProfiler();
        var probe = decode(ProbeFrames.frame("JIOFIBER fixture"), now);
        for (var session : List.of(new PassiveWifiSession(profiler, MyNetworkProfile.EMPTY, () -> now),
                PassiveWifiSession.forReplay(profiler, MyNetworkProfile.EMPTY, () -> now))) {
            session.observe(probe);
            var report = session.audit();
            var row = report.corpus().getFirst();
            assertTrue(report.deviceDetailsEnabled());
            assertEquals("JIOFIBER fixture", row.name());
            assertEquals(1, row.deviceCount());
            assertEquals(1, row.timeline().stream().mapToInt(Integer::intValue).sum());
            assertEquals(List.of(new ProbeAuditAggregator.ProbeDevice(session.addressId(CLIENT), now)), row.devices());
            assertEquals(session.inventory().getFirst().id(), row.devices().getFirst().id());
            assertNotEquals(CLIENT, row.devices().getFirst().id());
        }
    }

    @Test void dropsOnlyRecentlySeenProbeRetriesForTheSameSenderAndSequenceControl() throws Exception {
        var session = new PassiveWifiSession(new DeviceProfiler(), MyNetworkProfile.EMPTY, () -> 3_120L);
        byte[] original = ProbeFrames.frame("Lab", CLIENT, 5);
        byte[] retry = original.clone();
        retry[1] |= 8;
        var first = decode(original, 1_000);
        assertTrue(session.observe(first).probe());
        assertFalse(session.observe(decode(retry, 1_100)).probe());
        assertFalse(session.observe(decode(retry, 2_100)).probe());
        assertTrue(session.observe(decode(retry, 3_101)).probe());
        retry[22] = (byte) (6 << 4);
        assertTrue(session.observe(decode(retry, 3_102)).probe());
        retry[10] = 6;
        assertTrue(session.observe(decode(retry, 3_103)).probe());
        var report = session.audit();
        assertEquals(4, report.totalProbes());
        assertEquals(4, report.directedProbes());
        assertEquals(2, report.directedPerAddress().get("1"));
        assertEquals(4, report.corpus().getFirst().timeline().stream().mapToInt(Integer::intValue).sum());
    }

    @Test void reportsSsidListAndShortSsidMatchesAndWithdrawsMatchesOnCrcCollision() throws Exception {
        var session = new PassiveWifiSession(new DeviceProfiler(), MyNetworkProfile.EMPTY, () -> 1_010L);
        int apCrc = Dot11ChannelSwitchDecoder.shortSsidCrc32(ssid("plumless"));
        int listCrc = Dot11ChannelSwitchDecoder.shortSsidCrc32(ssid("Campus-Staff"));
        session.observe(decode(beacon(8, AP, ssid("plumless"), 1), 1_000));
        var compressed = ByteBuffer.allocate(13).order(ByteOrder.LITTLE_ENDIAN)
                .put((byte) 58).putInt(apCrc).putInt(listCrc).putInt(0x89abcdef).array();
        byte[] list = ie(84, join(ie(0, ssid("Campus-Staff")), ie(0, ssid("eduroam")), ie(0, new byte[2])));
        session.observe(decode(join(ProbeFrames.frame(""), ie(255, compressed)), 1_001));
        session.observe(decode(join(ProbeFrames.frame("Campus-Staff"), list), 1_002));
        session.observe(decode(join(ProbeFrames.frame(""), ie(255, new byte[]{58, 1, 2, 3, 4, 5})), 1_003));
        var report = session.audit();
        assertEquals(3, report.totalProbes());
        assertEquals(2, report.directedProbes());
        assertEquals(4, report.distinctDirectedSsids());
        var campus = probeRow(report, "Campus-Staff");
        assertEquals(List.of(ProbeAuditAggregator.Source.PLAINTEXT_SSID, ProbeAuditAggregator.Source.SSID_LIST,
                ProbeAuditAggregator.Source.SHORT_SSID_MATCH), campus.sources());
        assertEquals(2, campus.timeline().stream().mapToInt(Integer::intValue).sum());
        assertEquals(ProbeAuditAggregator.Source.SSID_LIST, probeRow(report, "eduroam").source());
        assertEquals(ProbeAuditAggregator.Source.SHORT_SSID_MATCH, probeRow(report, "plumless").source());
        var unresolved = probeRow(report, "Short-SSID 0x89abcdef");
        assertEquals(ProbeAuditAggregator.Source.SHORT_SSID_HASH, unresolved.source());
        assertEquals("SHORT_SSID_HASH", unresolved.exposure());
        assertEquals(session.addressId(CLIENT), unresolved.devices().getFirst().id());

        session.observe(decode(beacon(8, AP2, ssid("buckeroo"), 1), 1_004));
        var collision = session.audit();
        assertFalse(collision.corpus().stream().anyMatch(row -> row.name().equals("plumless") || row.name().equals("buckeroo")));
        assertEquals(2L, collision.ssidExposureCounts().get("SHORT_SSID_HASH"));
        assertEquals(2, collision.directedProbes());
    }

    @Test void reportsPasspointAndSanitizedP2pNamesAndRejectsTruncatedAttributes() throws Exception {
        var session = new PassiveWifiSession(new DeviceProfiler(), MyNetworkProfile.EMPTY, () -> 1_010L);
        byte[] deviceName = ssid(" Lab\u0000 Phone ");
        byte[] deviceInfo = join(HEX.parseHex("021122334455008000100050f204000101"), new byte[8],
                new byte[]{0x10, 0x11, 0, (byte) deviceName.length}, deviceName);
        byte[] p2pAttribute = join(new byte[]{13, (byte) deviceInfo.length, 0}, deviceInfo);
        byte[] vendor = HEX.parseHex("506f9a09");
        byte[] first = ie(221, join(vendor, Arrays.copyOfRange(p2pAttribute, 0, 12)));
        byte[] second = ie(221, join(vendor, Arrays.copyOfRange(p2pAttribute, 12, p2pAttribute.length)));
        session.observe(decode(join(ProbeFrames.frame(""), ie(107, new byte[]{0}), first, second), 1_001));
        session.observe(decode(join(ProbeFrames.frame(""), ie(111, new byte[]{0, 0}), first), 1_002));
        session.observe(decode(join(ProbeFrames.frame(""), ie(221, HEX.parseHex("506f9a1000"))), 1_003));
        session.observe(decode(ProbeFrames.frame(""), 1_004));
        var report = session.audit();
        assertEquals(75.0, report.passpointPct());
        assertEquals(1, report.p2pNamedProbes());
        assertEquals(java.util.Map.of(session.addressId(CLIENT), "Lab Phone"), report.p2pDeviceNames());
    }

    private static ProbeAuditAggregator.Ssid probeRow(ProbeAuditAggregator.Report report, String name) {
        return report.corpus().stream().filter(row -> row.name().equals(name)).findFirst().orElseThrow();
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

    @Test void materializesVirtualApWithParentRadioAndSecurityEvenWhenOnlyChildIsInScope() throws Exception {
        String virtualAp = "00:aa:bb:cc:dd:ec";
        byte[] profile = join(ie(85, new byte[]{2}), ie(0, new byte[]{'G', 'u', 'e', 's', 't'}));
        byte[] parent = join(beacon(8, AP, new byte[]{'M', 'a', 'i', 'n'}, 1),
                ie(7, new byte[]{'U', 'S', ' '}),
                ie(48, HEX.parseHex("0100000fac040100000fac040100000fac08c000")),
                ie(71, join(new byte[]{2}, ie(0, profile))));
        String oldScope = System.getProperty("rf.bssids");
        try {
            for (String scope : List.of(AP + "," + virtualAp, virtualAp)) {
                System.setProperty("rf.bssids", scope);
                var session = new PassiveWifiSession(new DeviceProfiler(), MyNetworkProfile.EMPTY, () -> 2000L);
                session.observe(Dot11FrameDecoder.decodeAny(radiotapFreq(parent, 5975), 127, 1000));
                for (int i = 0; i < 3; i++) {
                    session.observe(Dot11FrameDecoder.decodeAny(
                            radiotapFreq(header(8, 1, virtualAp, CLIENT, AP, i + 2), 5975), 127, 1001 + i));
                }
                var snapshot = session.topology();
                String parentId = session.addressId(AP), virtualId = session.addressId(virtualAp);
                var child = snapshot.accessPoints().stream().filter(ap -> ap.bssid().equals(virtualId))
                        .findFirst().orElseThrow();
                assertEquals("Guest", child.ssid());
                assertTrue(child.nonTransmitted());
                assertEquals(5975, child.frequencyMhz());
                assertEquals(5, child.channel());
                assertEquals(100, child.beaconIntervalTu());
                assertEquals("US", child.country());
                assertEquals(-47, child.rssiMedian());
                assertEquals("Required", child.advertisedSecurity().getFirst().managementFrameProtection());
                assertEquals(parentId, child.radioGroupId());
                assertEquals("Guest", session.observedAp(virtualId).ssid());
                assertEquals(virtualId, snapshot.edges().getFirst().bssid());
                assertEquals(List.of(session.addressId(CLIENT)), child.clients());
                assertEquals(scope.contains(",") ? 2 : 1, snapshot.accessPoints().size());
                if (scope.contains(",")) {
                    var root = snapshot.accessPoints().stream().filter(ap -> ap.bssid().equals(parentId))
                            .findFirst().orElseThrow();
                    assertEquals(root.radioGroupId(), child.radioGroupId());
                    assertEquals(root.security(), child.security());
                }
                assertTrue(session.evidencedTargets(null).isEmpty());
            }
        } finally {
            restoreProperty("rf.bssids", oldScope);
        }
    }

    @Test void maintainsOneActiveLinkAcrossRoamsIncludingAfterTheRoamEventWindow() {
        var ids = new SessionIdentifiers();
        var topology = new TopologyBuilder(ids);
        long first = 1000, second = first + TimeUnit.SECONDS.toMillis(45);
        observe(topology, ids, decode(associationResponse(AP, CLIENT), first));
        topology.purge(second, TimeUnit.HOURS.toMillis(1));
        for (int i = 0; i < 3; i++)
            observe(topology, ids, decode(header(8, 1, AP2, CLIENT, AP, i), second + i));
        assertEquals("ROAMED_AWAY", edge(topology.snapshot(), ids.id("wifi", AP)).state());
        assertEquals("ACTIVE", edge(topology.snapshot(), ids.id("wifi", AP2)).state());
        observe(topology, ids, decode(header(8, 1, AP, CLIENT, AP2, 5), second - 1));
        assertEquals("ROAMED_AWAY", edge(topology.snapshot(), ids.id("wifi", AP)).state());
        assertEquals(1, topology.snapshot().edges().stream().filter(link -> link.state().equals("ACTIVE")).count());
    }

    @Test void appliesDisconnectEvidenceUnderScopeAndIgnoresClearFramesForPmfRequired() throws Exception {
        String oldScope = System.getProperty("rf.bssids");
        try {
            System.setProperty("rf.bssids", AP + "," + AP2);
            var session = new PassiveWifiSession(new DeviceProfiler(), MyNetworkProfile.EMPTY, () -> 2000L);
            session.observe(decode(join(beacon(8, AP, new byte[]{'P'}, 1),
                    ie(48, HEX.parseHex("0100000fac040100000fac040100000fac08c000"))), 1000));
            session.observe(decode(associationResponse(AP, CLIENT), 1001));
            String protectedApId = session.addressId(AP);
            session.observe(decode(join(header(0xc0, 0, CLIENT, AP, AP, 3), new byte[2]), 1002));
            assertEquals("ACTIVE", edge(session.topology(), protectedApId).state());
            session.observe(decode(join(header(0xc0, 0x40, CLIENT, AP, AP, 4), new byte[2]), 1005));
            assertEquals("DISCONNECTED", edge(session.topology(), protectedApId).state());
            session.observe(decode(header(8, 1, AP, CLIENT, AP2, 6), 1004));
            assertEquals("DISCONNECTED", edge(session.topology(), protectedApId).state());
            session.observe(decode(header(8, 1, AP, CLIENT, AP2, 7), 1006));
            assertEquals("ACTIVE", edge(session.topology(), protectedApId).state());

            session.observe(decode(associationResponse(AP2, CLIENT), 1007));
            String apId = session.addressId(AP2);
            session.observe(decode(join(header(0xa0, 0, AP2, CLIENT, AP2, 8), new byte[2]), 1008));
            assertEquals("DISCONNECTED", edge(session.topology(), apId).state());
            session.observe(decode(control(9, CLIENT, AP2), 1009));
            assertEquals("ACTIVE", edge(session.topology(), apId).state());
            assertEquals("ROAMED_AWAY", edge(session.topology(), protectedApId).state());
        } finally {
            restoreProperty("rf.bssids", oldScope);
        }
    }

    @Test void countsControlEvidenceWithoutInventingAccessPointsFromBlockAcks() throws Exception {
        String oldScope = System.getProperty("rf.bssids");
        try {
            System.setProperty("rf.bssids", AP);
            var session = new PassiveWifiSession(new DeviceProfiler(), MyNetworkProfile.EMPTY, () -> 2000L);
            session.observe(decode(control(9, AP, CLIENT), 1000));
            assertTrue(session.topology().accessPoints().isEmpty());
            session.observe(decode(beacon(8, AP, new byte[]{'A'}, 1), 1001));
            session.observe(decode(control(9, AP, CLIENT), 1002));
            session.observe(decode(control(9, CLIENT, AP), 1003));
            session.observe(decode(control(8, CLIENT, AP), 1004));
            assertTrue(session.topology().edges().isEmpty());
            session.observe(decode(header(8, 1, AP, CLIENT, AP2, 3), 1005));
            String ap = session.addressId(AP);
            assertEquals("DATA", edge(session.topology(), ap).source());
            assertEquals(3, edge(session.topology(), ap).controlFrames());
            assertEquals(1, edge(session.topology(), ap).uplink());
            assertEquals(0, edge(session.topology(), ap).downlink());
            assertNull(session.observedClient(session.addressId(CLIENT)));
            assertTrue(session.evidencedTargets(null).isEmpty());

            var other = new PassiveWifiSession(new DeviceProfiler(), MyNetworkProfile.EMPTY, () -> 2000L);
            other.observe(decode(header(8, 1, AP, CLIENT, AP2, 4), 1000));
            other.observe(decode(control(9, AP, CLIENT), 1001));
            assertTrue(other.topology().edges().isEmpty());
            other.observe(decode(control(9, CLIENT, AP), 1002));
            assertEquals(2, other.topology().edges().getFirst().controlFrames());

            var polls = new PassiveWifiSession(new DeviceProfiler(), MyNetworkProfile.EMPTY, () -> 2000L);
            for (int i = 0; i < 3; i++) polls.observe(decode(control(10, AP, CLIENT), 1000 + i));
            var link = polls.topology().edges().getFirst();
            assertEquals("ACTIVE", link.state());
            assertEquals("CONTROL", link.source());
            assertEquals(3, link.controlFrames());
            assertEquals(1002, link.lastSeen());
        } finally {
            restoreProperty("rf.bssids", oldScope);
        }
    }

    @Test void recordsScopedWdsPeersInEitherDirectionWithoutCreatingInventoryOrClientLinks() throws Exception {
        String oldScope = System.getProperty("rf.bssids");
        try {
            System.setProperty("rf.bssids", AP);
            var clock = new java.util.concurrent.atomic.AtomicLong(2000);
            var session = new PassiveWifiSession(new DeviceProfiler(), MyNetworkProfile.EMPTY, clock::get);
            for (int i = 0; i < 2; i++) {
                byte[] wds = join(header(8, 3, i == 0 ? AP : AP2, i == 0 ? AP2 : AP, CLIENT, i), mac(AP3));
                session.observe(Dot11FrameDecoder.decodeAny(radiotapFreq(wds, 5180), 127, 1000 + i));
            }
            session.observe(decode(join(header(8, 3, AP2, CLIENT, AP, 3), mac(AP3)), 1002));
            session.observe(decode(join(header(8, 3, AP, AP, AP2, 4), mac(AP3)), 1003));
            var snapshot = session.topology();
            assertTrue(snapshot.edges().isEmpty());
            assertTrue(snapshot.accessPoints().isEmpty());
            assertTrue(session.inventory().isEmpty());
            var mesh = snapshot.meshLinks().getFirst();
            assertEquals(1, snapshot.meshLinks().size());
            assertEquals(List.of(session.addressId(AP), session.addressId(AP2)).stream().sorted().toList(),
                    List.of(mesh.peerA(), mesh.peerB()));
            assertEquals(2, mesh.frameCount());
            assertEquals(1000, mesh.firstSeen());
            assertEquals(1001, mesh.lastSeen());
            assertEquals(36, mesh.channel());
            assertEquals(5180, mesh.frequencyMhz());
            clock.addAndGet(TimeUnit.MINUTES.toMillis(11));
            assertTrue(session.topology().meshLinks().isEmpty());
        } finally {
            restoreProperty("rf.bssids", oldScope);
        }
    }

    @Test void groupsMldAcrossBandsAndUsesItToRelateDistinctApAdvertisements() {
        var ids = new SessionIdentifiers();
        var topology = new TopologyBuilder(ids);
        String otherAp = "00:66:77:88:99:aa";
        String otherClient = "02:22:33:44:55:66";
        String apMld = "00:aa:bb:44:55:66", clientMld = "02:aa:bb:cc:dd:01";
        byte[] twt = ie(255, new byte[]{35, 4, 0, 0, 0, 0, 0});
        byte[] ht = new byte[26];
        ht[0] = 0x2c;
        ht[3] = (byte) 0xff;
        byte[] capabilities = join(ie(45, ht), multiLink(clientMld));
        observe(topology, ids, Dot11FrameDecoder.decodeAny(radiotapFreq(
                join(beacon(8, AP, new byte[]{'A'}, 1), multiLink(apMld), twt), 2437), 127, 1000));
        observe(topology, ids, Dot11FrameDecoder.decodeAny(radiotapFreq(
                join(beacon(8, otherAp, new byte[]{'B'}, 1), multiLink(apMld)), 5975), 127, 1001));
        observe(topology, ids, Dot11FrameDecoder.decodeAny(radiotapFreq(join(
                header(0, 0, AP, CLIENT, AP, 2), new byte[4], capabilities), 2437), 127, 1002));
        observe(topology, ids, Dot11FrameDecoder.decodeAny(radiotapFreq(
                associationResponse(AP, CLIENT), 2437), 127, 1003));
        observe(topology, ids, Dot11FrameDecoder.decodeAny(radiotapFreq(join(
                header(0, 0, otherAp, otherClient, otherAp, 2), new byte[4], capabilities), 5975), 127, 1004));
        observe(topology, ids, Dot11FrameDecoder.decodeAny(radiotapFreq(
                associationResponse(otherAp, otherClient), 5975), 127, 1005));
        var snapshot = topology.snapshot();
        assertEquals(List.of("2.4 GHz", "6 GHz"), snapshot.accessPoints().stream()
                .map(TopologyBuilder.AccessPoint::band).sorted().toList());
        assertTrue(snapshot.accessPoints().stream().allMatch(ap -> ids.id("mld", apMld).equals(ap.mldId())));
        assertTrue(snapshot.accessPoints().stream().filter(ap -> ap.ssid().equals("A")).findFirst().orElseThrow()
                .managementFeatures().twtResponder());
        assertEquals(2, snapshot.edges().size());
        assertTrue(snapshot.edges().stream().allMatch(link -> ids.id("mld", clientMld).equals(link.clientMldId())));
        assertEquals("INFERRED_MAC_ROTATION", snapshot.roams().getFirst().method());
        assertFalse(snapshot.toString().contains(apMld));
        assertFalse(snapshot.toString().contains(clientMld));
    }

    private static byte[] multiLink(String address) {
        return ie(255, join(new byte[]{107, 0, 0, 7}, mac(address)));
    }

    @Test void keepsAllPingPongHopsAndMergesOnlyConsecutiveEvidenceForTheSameHop() {
        var ids = new SessionIdentifiers();
        var topology = new TopologyBuilder(ids);
        observe(topology, ids, decode(associationResponse(AP, CLIENT), 1_000));
        observe(topology, ids, decodeRadio(header(8, 1, AP, CLIENT, AP, 2), 2437, -77, 1_500));
        observe(topology, ids, decodeRadio(header(8, 2, CLIENT, AP, AP, 3), 2437, -25, 1_600));
        observe(topology, ids, decodeRadio(reassociation(AP, AP2, 4), 5180, -54, 2_000));
        observe(topology, ids, decodeRadio(reassociation(AP, AP2, 5), 5180, -54, 2_015));
        for (int seq = 6; seq <= 8; seq++)
            observe(topology, ids, decodeRadio(header(8, 1, AP2, CLIENT, AP2, seq), 5180, -54, 2_020 + seq));
        assertEquals(1, topology.snapshot().roams().size());
        observe(topology, ids, decodeRadio(reassociation(AP2, AP, 9), 2437, -70, 5_000));
        observe(topology, ids, decodeRadio(reassociation(AP, AP2, 10), 5180, -51, 7_000));
        var roams = topology.snapshot().roams();
        assertEquals(List.of(ids.id("wifi", AP2), ids.id("wifi", AP), ids.id("wifi", AP2)),
                roams.stream().map(TopologyBuilder.RoamEvent::toBssid).toList());
        assertEquals(List.of(false, true, true), roams.stream().map(TopologyBuilder.RoamEvent::pingPong).toList());
        assertEquals(List.of(1_000L, 3_000L, 2_000L), roams.stream().map(TopologyBuilder.RoamEvent::previousDwellMs).toList());
        assertEquals(-77, roams.getFirst().fromRssiDbm());
        assertEquals(-54, roams.getFirst().toRssiDbm());
        assertEquals("REASSOC", roams.getFirst().method());
        assertEquals(6, roams.getFirst().fromChannel());
        assertEquals(36, roams.getFirst().toChannel());

        observe(topology, ids, decode(reassociation(AP2, AP, 11), 52_000));
        observe(topology, ids, decode(reassociation(AP, AP2, 12), 112_001));
        roams = topology.snapshot().roams();
        assertTrue(roams.get(3).pingPong(), "Return after the deduplication window still counts");
        assertFalse(roams.getLast().pingPong());
    }

    @Test void upgradesFtEvidenceAndClassifiesFtReassociationElements() {
        var ids = new SessionIdentifiers();
        var topology = new TopologyBuilder(ids);
        byte[] overDs = ie(54, new byte[]{1, 2, 1}), ft = ie(55, new byte[82]);
        observe(topology, ids, decode(reassociation(AP, AP2, 2, overDs), 1_000));
        assertEquals("REASSOC", topology.snapshot().roams().getFirst().method());
        observe(topology, ids, decode(reassociation(AP, AP2, 3, overDs, ft), 1_015));
        assertEquals(1, topology.snapshot().roams().size());
        assertEquals("FT_OVER_DS", topology.snapshot().roams().getFirst().method());
        byte[] rsnFt = ie(48, HEX.parseHex("0100000fac040100000fac040100000fac04"));
        observe(topology, ids, decode(reassociation(AP2, AP, 4, ie(54, new byte[]{1, 2, 0}), rsnFt), 1_030));
        assertEquals("FT_REASSOC", topology.snapshot().roams().getLast().method());

        topology.clear();
        observe(topology, ids, decode(associationResponse(AP, CLIENT), 2_000));
        observe(topology, ids, decode(join(header(0xb0, 0, AP2, CLIENT, AP2, 5), new byte[]{2, 0, 1, 0, 0, 0}), 2_010));
        observe(topology, ids, decode(reassociation(AP, AP2, 6), 2_025));
        assertEquals(List.of("FT"), topology.snapshot().roams().stream().map(TopologyBuilder.RoamEvent::method).toList());
    }

    @Test void recordsSuccessfulOverDsActionsAndKeepsTargetsScopedAndTokenized() throws Exception {
        var session = new PassiveWifiSession(new DeviceProfiler(), MyNetworkProfile.EMPTY, () -> 2_000);
        byte[] request = join(header(0xd0, 0, AP, CLIENT, AP, 1), new byte[]{6, 1}, mac(CLIENT), mac(AP2));
        byte[] failure = join(header(0xd0, 0, CLIENT, AP, AP, 2), new byte[]{6, 2}, mac(CLIENT), mac(AP2), new byte[]{1, 0});
        byte[] success = join(header(0xd0, 0, CLIENT, AP, AP, 3), new byte[]{6, 2}, mac(CLIENT), mac(AP2), new byte[2]);
        session.observe(decode(failure, 1_000));
        assertTrue(session.topology().roams().isEmpty());
        session.observe(decode(request, 1_010));
        session.observe(decode(success, 1_012));
        session.observe(decode(reassociation(AP, AP2, 4), 1_025));
        var roams = session.topology().roams();
        assertEquals(1, roams.size());
        assertEquals("FT_OVER_DS", roams.getFirst().method());
        assertEquals(session.addressId(AP2), roams.getFirst().toBssid());
        assertEquals(session.addressId(AP), roams.getFirst().fromBssid());
        assertEquals(session.addressId(CLIENT), roams.getFirst().clientId());

        var ids = new SessionIdentifiers();
        var responseOnly = new TopologyBuilder(ids);
        observe(responseOnly, ids, decode(success, 1_012));
        assertEquals("FT_OVER_DS", responseOnly.snapshot().roams().getFirst().method());
        var scoped = new TopologyBuilder(ids, AP::equals, false);
        observe(scoped, ids, decode(request, 1_010));
        observe(scoped, ids, decode(success, 1_012));
        assertTrue(scoped.snapshot().roams().isEmpty());
    }

    @Test void associatesBtmAcceptanceWithTheMatchingHopAndRetainsRejections() throws Exception {
        var clock = new java.util.concurrent.atomic.AtomicLong(1_000);
        var session = new PassiveWifiSession(new DeviceProfiler(), MyNetworkProfile.EMPTY, clock::get);
        byte[] request = join(header(0xd0, 0, CLIENT, AP, AP, 2), new byte[]{10, 7, 1, 0, 0, 0, 1});
        byte[] accepted = join(header(0xd0, 0, AP, CLIENT, AP, 3), new byte[]{10, 8, 1, 0, 0}, mac(AP2));
        session.observe(decode(request, 1_000));
        session.observe(decode(accepted, 1_001));
        assertTrue(session.topology().roams().isEmpty());
        session.observe(decode(reassociation(AP, AP3, 4), 1_010));
        assertFalse(session.topology().roams().getFirst().btmSteered());
        session.observe(decode(reassociation(AP, AP2, 5), 1_020));
        assertTrue(session.topology().roams().getLast().btmSteered());
        byte[] rejected = join(header(0xd0, 0, AP2, CLIENT, AP2, 6), new byte[]{10, 8, 2, 7, 0});
        session.observe(decode(rejected, 1_025));
        session.observe(decode(reassociation(AP2, AP, 7), 1_030));
        assertFalse(session.topology().roams().getLast().btmSteered());
        assertEquals(List.of(new TopologyBuilder.BtmRejection(session.addressId(CLIENT), session.addressId(AP2), 7, 1_025)),
                session.topology().btmRejections());

        session.observe(decode(request, 2_000));
        session.observe(decode(accepted, 2_001));
        clock.set(17_002);
        session.observe(decode(reassociation(AP, AP2, 8), 17_002));
        assertFalse(session.topology().roams().getLast().btmSteered());
        for (int n = 0; n < 256; n++) session.observe(decode(rejected, 18_000 + n));
        assertEquals(256, session.topology().btmRejections().size());
        assertEquals(18_000, session.topology().btmRejections().getFirst().time());
    }

    @Test void distinguishesBandSteersSpatialRoamsAndNetworkSwitches() {
        var ids = new SessionIdentifiers();
        var topology = new TopologyBuilder(ids);
        String otherAp = "00:66:77:88:99:aa", otherEssAp = "00:66:77:88:99:bb";
        observe(topology, ids, decodeRadio(beacon(8, AP, ssid("Campus"), 1), 2437, -70, 1_000));
        observe(topology, ids, decodeRadio(beacon(8, AP2, ssid("Campus 5G"), 1), 5180, -60, 1_001));
        observe(topology, ids, decodeRadio(beacon(8, otherAp, ssid("Campus 5G"), 1), 5200, -61, 1_002));
        observe(topology, ids, decodeRadio(beacon(8, otherEssAp, ssid("Guest"), 1), 5200, -58, 1_003));
        observe(topology, ids, decode(reassociation(AP, AP2, 2), 1_010));
        observe(topology, ids, decode(reassociation(AP2, otherAp, 3), 1_020));
        observe(topology, ids, decode(reassociation(AP2, otherEssAp, 4), 1_030));
        var roams = topology.snapshot().roams();
        assertEquals(List.of("BAND_STEER", "INTER_AP_ROAM", "ESS_SWITCH"),
                roams.stream().map(TopologyBuilder.RoamEvent::transitionType).toList());
        assertEquals("2.4 GHz", roams.getFirst().fromBand());
        assertEquals("5 GHz", roams.getFirst().toBand());
    }

    @Test void suppressesDataBurstsBetweenAffiliatedMloLinksButRecordsManagementEvidence() {
        var ids = new SessionIdentifiers();
        var topology = new TopologyBuilder(ids);
        byte[] mld = multiLink("00:aa:bb:44:55:66");
        observe(topology, ids, decodeRadio(join(beacon(8, AP, ssid("Lab"), 1), mld), 5180, -70, 1_000));
        observe(topology, ids, decodeRadio(join(beacon(8, AP2, ssid("Lab"), 1), mld), 5975, -60, 1_001));
        observe(topology, ids, decode(associationResponse(AP, CLIENT), 1_002));
        for (int seq = 2; seq < 14; seq++) {
            String ap = seq % 2 == 0 ? AP2 : AP;
            observe(topology, ids, decode(header(8, 1, ap, CLIENT, ap, seq), 1_003 + seq));
        }
        assertEquals(2, topology.snapshot().edges().size());
        assertTrue(topology.snapshot().roams().isEmpty());
        observe(topology, ids, decode(reassociation(AP, AP2, 15), 1_020));
        assertEquals("MLO_LINK_SWITCH", topology.snapshot().roams().getFirst().transitionType());
    }

    private static byte[] reassociation(String from, String to, int sequence, byte[]... ies) {
        return join(header(0x20, 0, to, CLIENT, to, sequence), new byte[4], mac(from), join(ies));
    }

    private static Dot11Frame decodeRadio(byte[] frame, int frequency, int rssi, long time) {
        byte[] packet = radiotapFreq(frame, frequency);
        packet[12] = (byte) rssi;
        return Dot11FrameDecoder.decodeAny(packet, 127, time);
    }

    private static byte[] associationResponse(String ap, String client) {
        return join(header(0x10, 0, client, ap, ap, 1), new byte[6]);
    }

    private static byte[] control(int subtype, String receiver, String sender) {
        return Arrays.copyOf(header((subtype << 4) | 4, 0, receiver, sender, BROADCAST, 0), 16);
    }

    private static TopologyBuilder.AssociationEdge edge(TopologyBuilder.Snapshot snapshot, String apId) {
        return snapshot.edges().stream().filter(link -> link.bssid().equals(apId)).findFirst().orElseThrow();
    }

    @Test void mapsConfirmedEdgesAndHiddenNamesWithoutPayloadsOrMulticastClients() throws Exception {
        var ids = new SessionIdentifiers();
        var topology = new TopologyBuilder(ids);
        long time = 1_000;
        var hidden = decode(beacon(8, AP, new byte[]{0, 0}, 1), time);
        observe(topology, ids, hidden);
        assertTrue(topology.snapshot().accessPoints().getFirst().ssidHidden());
        assertNull(topology.snapshot().accessPoints().getFirst().ssidToken());
        assertEquals(new TopologyBuilder.HiddenSsidEvidence(null, "NONE", null, time),
                topology.snapshot().accessPoints().getFirst().hiddenSsidEvidence());
        observe(topology, ids, decode(beacon(5, AP, "SecretSSID".getBytes(StandardCharsets.US_ASCII), 2), ++time));
        var named = topology.snapshot().accessPoints().getFirst();
        assertEquals("PROBE_RESP", named.ssidRevealedVia());
        assertNotEquals("SecretSSID", named.ssidToken());
        assertEquals(new TopologyBuilder.HiddenSsidEvidence(null, "PROBE_RESP", time, time - 1),
                named.hiddenSsidEvidence());

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

    @Test void replayShowsNamesOnlyForHiddenAccessPointsWithMatchingFrameEvidence() throws Exception {
        var session = PassiveWifiSession.forReplay(new DeviceProfiler(), MyNetworkProfile.EMPTY, () -> 1_000L);
        String apId = session.addressId(AP);
        String secondId = session.addressId(AP2);
        byte[] name = "Lab hidden".getBytes(StandardCharsets.UTF_8);

        session.observe(decode(beacon(8, AP, new byte[0], 1), 1_000));
        session.observe(decode(beacon(8, AP2, new byte[0], 2), 1_001));
        session.observe(decode(ProbeFrames.frame("Unrelated network"), 1_002));
        assertTrue(session.topology().accessPoints().stream().allMatch(ap -> ap.hiddenSsidEvidence().observedAt() == null));

        session.observe(decode(beacon(5, AP, name, 3), 1_003));
        session.observe(decode(beacon(5, AP, "Older".getBytes(StandardCharsets.UTF_8), 4), 1_002));
        var first = session.topology().accessPoints().stream().filter(ap -> ap.bssid().equals(apId)).findFirst().orElseThrow();
        assertEquals(new TopologyBuilder.HiddenSsidEvidence("Lab hidden", "PROBE_RESP", 1_003L, 1_000L),
                first.hiddenSsidEvidence());

        byte[] request = join(header(0x20, 0, AP2, CLIENT, AP2, 7), new byte[4], mac(AP), ie(0, name));
        session.observe(decode(request, 1_004));
        var second = session.topology().accessPoints().stream().filter(ap -> ap.bssid().equals(secondId)).findFirst().orElseThrow();
        assertEquals("ASSOC_REQ", second.ssidRevealedVia());
        assertEquals(new TopologyBuilder.HiddenSsidEvidence("Lab hidden", "REASSOC_REQ", 1_004L, 1_001L),
                second.hiddenSsidEvidence());

        session.observe(decode(beacon(8, AP, name, 5), 1_005));
        assertNull(session.topology().accessPoints().stream().filter(ap -> ap.bssid().equals(apId))
                .findFirst().orElseThrow().hiddenSsidEvidence());
    }

    @Test void rejectsOnlyTheMatchingTentativeClaimAndPromotesTheAcceptedAssociation() {
        var ids = new SessionIdentifiers();
        var topology = new TopologyBuilder(ids, name -> true, true);
        String anotherClient = "02:11:22:33:44:66";
        observe(topology, ids, decode(beacon(8, AP, new byte[0], 0), 1_000));

        observe(topology, ids, decode(associationRequest(AP, CLIENT, "Wrong"), 1_010));
        assertEquals("Wrong", accessPoint(topology, ids, AP).ssid());
        assertEquals("TENTATIVE_CLIENT", accessPoint(topology, ids, AP).revealConfidence());
        observe(topology, ids, decode(associationStatus(AP, anotherClient, 17), 1_012));
        observe(topology, ids, decode(associationStatus(AP, CLIENT, 17), 1_009));
        assertEquals("Wrong", accessPoint(topology, ids, AP).ssid());
        observe(topology, ids, decode(associationStatus(AP, CLIENT, 17), 1_013));
        var cleared = accessPoint(topology, ids, AP);
        assertNull(cleared.ssid());
        assertNull(cleared.ssidToken());
        assertNull(cleared.revealConfidence());
        assertEquals("NONE", cleared.ssidRevealedVia());
        assertEquals(new TopologyBuilder.HiddenSsidEvidence(null, "NONE", null, 1_000), cleared.hiddenSsidEvidence());
        assertTrue(topology.snapshot().edges().isEmpty());

        observe(topology, ids, decode(associationRequest(AP, CLIENT, "Lab network"), 1_020));
        observe(topology, ids, decode(associationRequest(AP, anotherClient, "Newer claim"), 1_021));
        assertEquals("Newer claim", accessPoint(topology, ids, AP).ssid());
        observe(topology, ids, decode(associationResponse(AP, CLIENT), 1_022));
        var confirmed = accessPoint(topology, ids, AP);
        assertEquals("CONFIRMED_ASSOC", confirmed.revealConfidence());
        assertEquals(new TopologyBuilder.HiddenSsidEvidence("Lab network", "ASSOC_REQ", 1_020L, 1_000),
                confirmed.hiddenSsidEvidence());
        observe(topology, ids, decode(associationStatus(AP, anotherClient, 17), 1_023));
        assertEquals(confirmed.hiddenSsidEvidence(), accessPoint(topology, ids, AP).hiddenSsidEvidence());
        observe(topology, ids, decode(beacon(5, AP, ssid("AP name"), 0), 1_019));
        assertEquals("AP name", accessPoint(topology, ids, AP).ssid());
        assertEquals("AP_AUTHORITATIVE", accessPoint(topology, ids, AP).revealConfidence());
        observe(topology, ids, decode(associationRequest(AP, CLIENT, "Later claim"), 1_024));
        assertEquals("AP name", accessPoint(topology, ids, AP).ssid());
    }

    @Test void promotesAPendingReassociationWhenDataConfirmsItsClientEdge() {
        var ids = new SessionIdentifiers();
        var topology = new TopologyBuilder(ids, name -> true, true);
        observe(topology, ids, decode(beacon(8, AP, new byte[0], 0), 1_000));
        byte[] request = join(header(0x20, 0, AP, CLIENT, AP, 1), new byte[4], mac(AP2), ie(0, ssid("Rejoined")));
        observe(topology, ids, decode(request, 1_001));
        assertEquals("TENTATIVE_CLIENT", accessPoint(topology, ids, AP).revealConfidence());
        for (int i = 0; i < 3; i++) {
            observe(topology, ids, decode(header(8, 1, AP, CLIENT, AP2, i + 2), 1_002 + i));
        }
        var ap = accessPoint(topology, ids, AP);
        assertEquals("CONFIRMED_ASSOC", ap.revealConfidence());
        assertEquals("ASSOC_REQ", ap.ssidRevealedVia());
        assertEquals("REASSOC_REQ", ap.hiddenSsidEvidence().source());
    }

    @Test void enforcesNullPaddingForClientNamesAndRequiresTargetedProbeAddresses() {
        var ids = new SessionIdentifiers();
        var topology = new TopologyBuilder(ids);
        observe(topology, ids, decode(probe(AP, AP, "Good"), 1_000));
        assertTrue(topology.snapshot().accessPoints().isEmpty());
        observe(topology, ids, decode(beacon(8, AP, new byte[4], 0), 1_001));
        observe(topology, ids, decode(probe(BROADCAST, AP, "Good"), 1_002));
        observe(topology, ids, decode(probe(AP, AP2, "Good"), 1_003));
        observe(topology, ids, decode(probe(AP, AP, "Wrong length"), 1_004));
        observe(topology, ids, decode(associationRequest(AP, CLIENT, "Wrong length"), 1_005));
        observe(topology, ids, decode(associationResponse(AP, CLIENT), 1_006));
        var masked = accessPoint(topology, ids, AP);
        assertEquals("NULL_PADDED", masked.concealmentMode());
        assertEquals(4, masked.maskedSsidLength());
        assertEquals("HIDDEN_INFRASTRUCTURE", masked.hiddenRole());
        assertNull(masked.ssid());
        assertNull(masked.revealConfidence());

        observe(topology, ids, decode(probe(AP, AP, "Good"), 1_007));
        assertEquals("Good", accessPoint(topology, ids, AP).ssid());
        assertEquals("PROBE_REQ", accessPoint(topology, ids, AP).ssidRevealedVia());
        assertEquals("TENTATIVE_CLIENT", accessPoint(topology, ids, AP).revealConfidence());
        observe(topology, ids, decode(probe(AP, AP, "Old!"), 1_006));
        assertEquals("Good", accessPoint(topology, ids, AP).ssid());
    }

    @Test void revealsOweNamesFromAHiddenBeaconOrItsOpenPartnerInEitherOrder() {
        var ids = new SessionIdentifiers();
        var topology = new TopologyBuilder(ids, name -> true, true);
        observe(topology, ids, decode(join(beacon(8, AP, new byte[0], 0), oweTransition(AP2, "Open partner")), 1_000));
        var direct = accessPoint(topology, ids, AP);
        assertEquals("Open partner", direct.ssid());
        assertEquals("OWE_TRANSITION", direct.ssidRevealedVia());
        assertEquals("AP_AUTHORITATIVE", direct.revealConfidence());
        assertEquals("OWE_TRANSITION_BSS", direct.hiddenRole());
        assertEquals("ZERO_LENGTH", direct.concealmentMode());
        assertEquals(ids.id("wifi", AP2), direct.owePeerBssid());
        assertFalse(topology.snapshot().toString().contains(AP2));

        for (boolean partnerFirst : List.of(false, true)) {
            topology.clear();
            var hidden = decode(beacon(8, AP, new byte[0], 0), partnerFirst ? 1_001 : 1_000);
            var open = decode(join(beacon(8, AP2, ssid("Visible network"), 0), oweTransition(AP, "Enhanced network")),
                    partnerFirst ? 1_000 : 1_001);
            observe(topology, ids, partnerFirst ? open : hidden);
            if (partnerFirst) assertNull(accessPoint(topology, ids, AP).ssid());
            observe(topology, ids, partnerFirst ? hidden : open);
            var linked = accessPoint(topology, ids, AP);
            assertEquals("Enhanced network", linked.ssid());
            assertEquals("OWE_TRANSITION", linked.ssidRevealedVia());
            assertEquals("AP_AUTHORITATIVE", linked.revealConfidence());
            assertEquals("OWE_TRANSITION_BSS", linked.hiddenRole());
            assertEquals(ids.id("wifi", AP2), linked.owePeerBssid());
            assertEquals(List.of("Visible network"), linked.coHostedVisibleSsids());
        }
    }

    @Test void resolvesRnrMatchesInEitherOrderAndWithdrawsANameWhenTheCrcBecomesAmbiguous() {
        var ids = new SessionIdentifiers();
        var topology = new TopologyBuilder(ids, name -> true, true);
        assertEquals(Dot11ChannelSwitchDecoder.shortSsidCrc32(ssid("plumless")),
                Dot11ChannelSwitchDecoder.shortSsidCrc32(ssid("buckeroo")));
        for (boolean visibleFirst : List.of(false, true)) {
            topology.clear();
            var hidden = Dot11FrameDecoder.decodeAny(radiotapFreq(beacon(8, AP, new byte[8], 0), 5975),
                    127, visibleFirst ? 1_002 : 1_000);
            var visible = Dot11FrameDecoder.decodeAny(radiotapFreq(join(beacon(8, AP2, ssid("plumless"), 0),
                    rnr(AP, "plumless")), 5180), 127, visibleFirst ? 1_000 : 1_002);
            observe(topology, ids, visibleFirst ? visible : hidden);
            observe(topology, ids, visibleFirst ? hidden : visible);
            observe(topology, ids, decode(associationRequest(AP, CLIENT, "Fallback"), 1_003));
            var matched = accessPoint(topology, ids, AP);
            assertEquals("plumless", matched.ssid());
            assertEquals("RNR_SHORT_SSID", matched.ssidRevealedVia());
            assertEquals("AP_AUTHORITATIVE", matched.revealConfidence());
            assertEquals(5975, matched.frequencyMhz());

            observe(topology, ids, decode(beacon(8, AP3, ssid("buckeroo"), 0), 1_004));
            assertEquals("Fallback", accessPoint(topology, ids, AP).ssid());
            observe(topology, ids, decode(associationStatus(AP, CLIENT, 17), 1_005));
            observe(topology, ids, decode(beacon(8, AP2, ssid("plumless"), 0), 1_006));
            assertNull(accessPoint(topology, ids, AP).ssid());
            assertNull(accessPoint(topology, ids, AP).revealConfidence());
        }
    }

    @Test void matchesRnrOnlyWithinScopeAndWithTheAdvertisedMaskLength() {
        var ids = new SessionIdentifiers();
        var topology = new TopologyBuilder(ids, name -> !name.equals(AP3), true);
        observe(topology, ids, decode(beacon(8, AP, new byte[3], 0), 1_000));
        observe(topology, ids, decode(join(beacon(8, AP2, ssid("Lab name"), 0),
                rnr(AP, "Lab name"), rnr(AP3, "Lab name"), oweTransition(AP3, "Lab name")), 1_001));
        assertNull(accessPoint(topology, ids, AP).ssid());
        assertEquals(2, topology.snapshot().accessPoints().size());
        observe(topology, ids, decode(beacon(8, AP, new byte[8], 0), 1_002));
        assertEquals("RNR_SHORT_SSID", accessPoint(topology, ids, AP).ssidRevealedVia());
    }

    @Test void indexesConfirmedAssociationNamesAndDirectedProbeNames() throws Exception {
        var session = new PassiveWifiSession(new DeviceProfiler(), MyNetworkProfile.EMPTY, () -> 1_010L);
        session.observe(decode(beacon(8, AP, new byte[0], 0), 1_000));
        session.observe(decode(join(beacon(8, AP2, ssid("Reporter"), 0), rnr(AP, "Probe name")), 1_001));
        session.observe(decode(probe(BROADCAST, BROADCAST, "Probe name"), 1_002));
        assertEquals("Probe name", session.topology().accessPoints().stream()
                .filter(ap -> ap.bssid().equals(session.addressId(AP))).findFirst().orElseThrow().ssid());
        var ids = new SessionIdentifiers();
        var topology = new TopologyBuilder(ids);
        observe(topology, ids, decode(beacon(8, AP, new byte[0], 0), 1_000));
        observe(topology, ids, decode(join(beacon(8, AP2, ssid("Reporter"), 0), rnr(AP, "Association name")), 1_001));
        observe(topology, ids, decode(associationRequest(AP3, CLIENT, "Association name"), 1_002));
        assertNull(accessPoint(topology, ids, AP).ssid());
        observe(topology, ids, decode(associationResponse(AP3, CLIENT), 1_003));
        assertEquals("RNR_SHORT_SSID", accessPoint(topology, ids, AP).ssidRevealedVia());
    }

    @Test void classifiesHiddenMeshAndBackhaulAndFindsVisibleSiblingsByRadioClock() {
        var ids = new SessionIdentifiers();
        var topology = new TopologyBuilder(ids);
        byte[] backhaul = ie(221, HEX.parseHex("506f9a1b060140"));
        byte[] mesh = join(beacon(8, AP, new byte[0], 0), ie(114, ssid("Lab mesh")), backhaul);
        mesh[34] = 0; // A mesh point need not advertise the ESS capability.
        for (int i = 0; i < 5; i++) {
            long tsft = i * 100_000L;
            observe(topology, ids, clockBeacon(mesh, 1_000 + i * 100, tsft, tsft + 30));
            observe(topology, ids, clockBeacon(beacon(8, AP2, ssid("Co-hosted network"), 0),
                    1_003 + i * 100, tsft + 5, tsft + 50));
        }
        observe(topology, ids, decode(join(beacon(8, AP3, new byte[0], 0), backhaul), 1_404));
        var meshAp = accessPoint(topology, ids, AP);
        assertEquals("MESH_POINT", meshAp.hiddenRole());
        assertEquals("Lab mesh", meshAp.meshId());
        assertNull(meshAp.ssid());
        assertNotNull(meshAp.radioGroupId());
        assertEquals(accessPoint(topology, ids, AP2).radioGroupId(), meshAp.radioGroupId());
        assertEquals(List.of("Co-hosted network"), meshAp.coHostedVisibleSsids());
        assertEquals("MULTI_AP_BACKHAUL", accessPoint(topology, ids, AP3).hiddenRole());
        assertTrue(accessPoint(topology, ids, AP3).coHostedVisibleSsids().isEmpty());
    }

    @Test void distinguishesQbssAdvertisedStationCountFromObservedClientLinksAndExpiresOldLinks() throws Exception {
        var clock = new java.util.concurrent.atomic.AtomicLong(10_000L);
        var session = PassiveWifiSession.forReplay(new DeviceProfiler(), MyNetworkProfile.EMPTY, clock::get);
        String apId = session.addressId(AP);
        String clientId = session.addressId(CLIENT);

        // Beacon advertising QBSS Load stationCount=26 with zero observed client frames.
        byte[] qbss = ByteBuffer.allocate(5).order(ByteOrder.LITTLE_ENDIAN)
                .putShort((short) 26).put((byte) 40).putShort((short) 1000).array();
        session.observe(decode(join(beacon(8, AP, "BusyLab".getBytes(StandardCharsets.UTF_8), 1), ie(11, qbss)),
                clock.get()));
        var beaconOnly = session.topology();
        assertEquals(1, beaconOnly.accessPoints().size());
        var apSummary = beaconOnly.accessPoints().getFirst();
        assertEquals(apId, apSummary.bssid());
        assertEquals(26, apSummary.stationCount());
        assertTrue(apSummary.clients().isEmpty());
        assertTrue(beaconOnly.edges().isEmpty());

        // Failed association response (status code 1) must not establish a client link.
        byte[] fixedAssocFail = ByteBuffer.allocate(6).order(ByteOrder.LITTLE_ENDIAN)
                .putShort((short) 1).putShort((short) 1).putShort((short) 1).array();
        byte[] assocFail = join(header(0x10, 0, CLIENT, AP, AP, 10), fixedAssocFail);
        session.observe(decode(assocFail, clock.addAndGet(100)));
        assertTrue(session.topology().edges().isEmpty());

        // Successful association response (status code 0) plus a duplicate retry (FC retry=0x0800) count once.
        byte[] fixedAssocOk = ByteBuffer.allocate(6).order(ByteOrder.LITTLE_ENDIAN)
                .putShort((short) 1).putShort((short) 0).putShort((short) 1).array();
        byte[] assocOk = join(header(0x10, 0, CLIENT, AP, AP, 11), fixedAssocOk);
        byte[] assocRetry = join(header(0x10, 0x08, CLIENT, AP, AP, 11), fixedAssocOk);
        session.observe(decode(assocOk, clock.addAndGet(100)));
        session.observe(decode(assocRetry, clock.addAndGet(20)));
        var linked = session.topology();
        assertEquals(1, linked.edges().size());
        var edge = linked.edges().getFirst();
        assertEquals(apId, edge.bssid());
        assertEquals(clientId, edge.clientId());
        assertEquals("ASSOC", edge.source());
        assertEquals(1, edge.evidenceCount());
        assertEquals(List.of(clientId), linked.accessPoints().getFirst().clients());
        assertEquals(26, linked.accessPoints().getFirst().stationCount());

        // Link expiry removes the edge when no new evidence arrives.
        long expiryDelay = edge.expiresAt() - clock.get() + 1;
        clock.addAndGet(expiryDelay);
        var expired = session.topology();
        assertTrue(expired.edges().isEmpty());
        assertTrue(expired.accessPoints().getFirst().clients().isEmpty());
    }

    @Test void infersDualBandRoamAcrossRotatedClientMacsWhenUnambiguousAndRejectsAmbiguity() {
        var ids = new SessionIdentifiers();
        var topology = new TopologyBuilder(ids);
        String ap24 = "00:11:22:33:44:50", ap5 = "00:11:22:33:44:51";
        String mac24 = "02:aa:bb:cc:dd:01", mac5 = "02:aa:bb:cc:dd:02", macAmbiguous = "02:aa:bb:cc:dd:03";
        byte[] assocOk = ByteBuffer.allocate(6).order(ByteOrder.LITTLE_ENDIAN)
                .putShort((short) 1).putShort((short) 0).putShort((short) 1).array();
        byte[] ht24 = new byte[26];
        ht24[0] = 0x2c; ht24[3] = (byte) 0xff; ht24[4] = (byte) 0xff;
        byte[] ht5 = ht24.clone();
        ht5[0] = 0x2e; // Different 40 MHz capability bit on 5 GHz while RX MCS mask (bytes 3..6) matches.
        byte[] extCap = new byte[]{0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x40};

        long t = 1_000;
        observe(topology, ids, Dot11FrameDecoder.decodeAny(
                radiotapFreq(beacon(8, ap24, "EWAVE-LAB".getBytes(StandardCharsets.UTF_8), 100), 2437), 127, t));
        observe(topology, ids, Dot11FrameDecoder.decodeAny(
                radiotapFreq(beacon(8, ap5, "EWAVE-LAB-5G".getBytes(StandardCharsets.UTF_8), 200), 5180), 127, t + 10));

        byte[] req24 = join(header(0, 0, ap24, mac24, ap24, 1), new byte[4],
                ie(0, "EWAVE-LAB".getBytes(StandardCharsets.UTF_8)), ie(45, ht24), ie(127, extCap));
        observe(topology, ids, Dot11FrameDecoder.decodeAny(radiotapFreq(req24, 2437), 127, t + 100));
        observe(topology, ids, Dot11FrameDecoder.decodeAny(
                radiotapFreq(join(header(0x10, 0, mac24, ap24, ap24, 2), assocOk), 2437), 127, t + 120));

        // Client rotates its random MAC 8 seconds later when associating on 5 GHz of the same dual-band router.
        byte[] req5 = join(header(0, 0, ap5, mac5, ap5, 1), new byte[4],
                ie(0, "EWAVE-LAB-5G".getBytes(StandardCharsets.UTF_8)), ie(45, ht5), ie(127, extCap));
        observe(topology, ids, Dot11FrameDecoder.decodeAny(radiotapFreq(req5, 5180), 127, t + 8_100));
        observe(topology, ids, Dot11FrameDecoder.decodeAny(
                radiotapFreq(join(header(0x10, 0, mac5, ap5, ap5, 2), assocOk), 5180), 127, t + 8_120));

        var roams = topology.snapshot().roams();
        assertEquals(1, roams.size());
        assertEquals("INFERRED_MAC_ROTATION", roams.getFirst().method());
        assertEquals(ids.id("wifi", mac5), roams.getFirst().clientId());
        assertEquals(ids.id("wifi", ap24), roams.getFirst().fromBssid());
        assertEquals(ids.id("wifi", ap5), roams.getFirst().toBssid());

        // Ambiguous scenario: if a second identical-cohort phone is already on ap24 within roamWindow, do not infer roam.
        var ambiguous = new TopologyBuilder(ids);
        observe(ambiguous, ids, Dot11FrameDecoder.decodeAny(
                radiotapFreq(beacon(8, ap24, "EWAVE-LAB".getBytes(StandardCharsets.UTF_8), 100), 2437), 127, t));
        observe(ambiguous, ids, Dot11FrameDecoder.decodeAny(
                radiotapFreq(beacon(8, ap5, "EWAVE-LAB-5G".getBytes(StandardCharsets.UTF_8), 200), 5180), 127, t + 10));
        byte[] reqAmb = join(header(0, 0, ap24, macAmbiguous, ap24, 1), new byte[4],
                ie(0, "EWAVE-LAB".getBytes(StandardCharsets.UTF_8)), ie(45, ht24), ie(127, extCap));
        observe(ambiguous, ids, Dot11FrameDecoder.decodeAny(radiotapFreq(req24, 2437), 127, t + 100));
        observe(ambiguous, ids, Dot11FrameDecoder.decodeAny(
                radiotapFreq(join(header(0x10, 0, mac24, ap24, ap24, 2), assocOk), 2437), 127, t + 120));
        observe(ambiguous, ids, Dot11FrameDecoder.decodeAny(radiotapFreq(reqAmb, 2437), 127, t + 200));
        observe(ambiguous, ids, Dot11FrameDecoder.decodeAny(
                radiotapFreq(join(header(0x10, 0, macAmbiguous, ap24, ap24, 2), assocOk), 2437), 127, t + 220));
        observe(ambiguous, ids, Dot11FrameDecoder.decodeAny(radiotapFreq(req5, 5180), 127, t + 8_100));
        observe(ambiguous, ids, Dot11FrameDecoder.decodeAny(
                radiotapFreq(join(header(0x10, 0, mac5, ap5, ap5, 2), assocOk), 5180), 127, t + 8_120));
        assertTrue(ambiguous.snapshot().roams().isEmpty());
    }

    private static byte[] radiotapFreq(byte[] wifi, int frequencyMhz) {
        return ByteBuffer.allocate(13 + wifi.length).order(ByteOrder.LITTLE_ENDIAN)
                .put((byte) 0).put((byte) 0).putShort((short) 13).putInt(0x28)
                .putShort((short) frequencyMhz).putShort((short) 0xa0).put((byte) -47).put(wifi).array();
    }

    private static Dot11Frame clockBeacon(String source, long time, long receiver, long tsf) {
        return clockBeacon(beacon(8, source, new byte[0], tsf), time, receiver, tsf);
    }

    private static Dot11Frame clockBeacon(byte[] wifi, long time, long receiver, long tsf) {
        byte[] packet = ByteBuffer.allocate(20 + wifi.length).order(ByteOrder.LITTLE_ENDIAN)
                .putShort((short) 0).putShort((short) 20).putInt(9).putLong(receiver)
                .putShort((short) 5180).putShort((short) 0).put(wifi).array();
        ByteBuffer.wrap(packet).order(ByteOrder.LITTLE_ENDIAN).putLong(44, tsf);
        return Dot11FrameDecoder.decodeAny(packet, 127, time);
    }

    private static TopologyBuilder.AccessPoint accessPoint(TopologyBuilder topology, SessionIdentifiers ids, String ap) {
        return topology.snapshot().accessPoints().stream().filter(row -> row.bssid().equals(ids.id("wifi", ap)))
                .findFirst().orElseThrow();
    }

    private static byte[] ssid(String name) { return name.getBytes(StandardCharsets.UTF_8); }

    private static byte[] associationRequest(String ap, String client, String name) {
        return join(header(0, 0, ap, client, ap, 1), new byte[4], ie(0, ssid(name)));
    }

    private static byte[] associationStatus(String ap, String client, int status) {
        byte[] fixed = ByteBuffer.allocate(6).order(ByteOrder.LITTLE_ENDIAN).putShort(2, (short) status).array();
        return join(header(0x10, 0, client, ap, ap, 2), fixed);
    }

    private static byte[] probe(String receiver, String bssid, String name) {
        return join(header(0x40, 0, receiver, CLIENT, bssid, 1), ie(0, ssid(name)));
    }

    private static byte[] oweTransition(String peer, String name) {
        byte[] bytes = ssid(name);
        return ie(221, join(HEX.parseHex("506f9a1c"), mac(peer), new byte[]{(byte) bytes.length}, bytes));
    }

    private static byte[] rnr(String ap, String name) {
        byte[] entry = ByteBuffer.allocate(15).order(ByteOrder.LITTLE_ENDIAN)
                .put(new byte[]{0, 11, (byte) 131, 5, 0}).put(mac(ap))
                .putInt(Dot11ChannelSwitchDecoder.shortSsidCrc32(ssid(name))).array();
        return ie(201, entry);
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
