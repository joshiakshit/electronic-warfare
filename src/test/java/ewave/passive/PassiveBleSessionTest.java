package ewave.passive;

import ewave.decoder.BleHciDecoder;
import ewave.fixtures.BleFrames;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class PassiveBleSessionTest {
    private static final HexFormat HEX = HexFormat.of();
    private static final String TAG = "c2:11:22:33:44:55";

    @Test void recognizesTypedAdvertisementsWithoutDecodingPrivateProtocolData() throws Exception {
        var classifier = new BleClassifier();
        byte[] apple = ad(255, "4c000702ff000c02aabb1001ff");
        byte[] pair = ad(0x16, "2cfe123456");
        byte[] eddy = ad(0x16, "aafe00010203");
        var finding = classifier.classify(decode(BleFrames.concat(apple, pair, eddy), 1000));
        assertTrue(finding.continuityTypes().containsAll(List.of("Proximity Pairing", "Handoff", "Nearby Info")));
        assertEquals("123456", finding.fastPairModel());
        assertTrue(finding.eddystoneTypes().contains("UID"));
        assertFalse(finding.toString().contains("aabb"));
        assertEquals(BleClassifier.DeviceClass.BEACON_TAG, finding.deviceClass());

        var privatePair = classifier.classify(decode(ad(0x16, "2cfe9876543210"), 1000));
        assertNull(privatePair.fastPairModel());
        assertTrue(privatePair.fastPairNonDiscoverable());
        assertTrue(classifier.classify(decode(ad(255, "4c0007ff01"), 1000)).continuityTypes().isEmpty());
        assertTrue(classifier.classify(decode(new byte[]{4, (byte) 255, 0x4c, 0}, 1000)).companies().isEmpty());
    }

    @Test void matchesPublicCompanyServiceAndMemberIdentifiersWithoutTrackingAdvertisers() throws Exception {
        var session = new PassiveBleSession();
        long now = System.currentTimeMillis();
        byte[] bytes = BleFrames.concat(ad(255, "4c00"), ad(3, "0f182cfe"), ad(0x16, "2cfe123456"));
        session.observe(decode(bytes, now));
        var report = session.snapshot();
        assertTrue(report.registryMatches().contains(new PassiveBleSession.RegistryMatch("MEMBER_UUID", "0xFE2C", "Fixture Member", 1)));
        assertTrue(report.registryMatches().contains(new PassiveBleSession.RegistryMatch("GATT_SERVICE", "0x180F", "Fixture Battery", 1)));
        assertTrue(report.registryMatches().stream().anyMatch(match -> match.kind().equals("COMPANY_ID")
                && match.code().equals("0x004C") && match.name().equals("Fixture Apple Vendor")));
        assertTrue(report.enrolledAssets().isEmpty());
        assertFalse(report.registryMatches().toString().contains(TAG));

        session.observe(decode(ad(3, "0d18"), now));
        assertEquals(report.registryMatches(), session.snapshot().registryMatches());
    }

    @Test void preservesHciEventSemanticsForBothFormats() {
        for (int type = 0; type <= 4; type++) {
            byte[] packet = BleFrames.legacy(new byte[0]);
            packet[4] = (byte) type;
            var event = BleHciDecoder.decode(packet, 1000).getFirst();
            assertEquals(type == 0 || type == 1, event.connectable());
            assertEquals(type == 0 || type == 3, event.scannable());
            assertEquals(type == 1, event.directed());
            assertEquals(type == 4, event.scanResponse());
        }
        var directed = BleHciDecoder.decode(BleFrames.extended(new byte[0], 5, 1), 1000).getFirst();
        assertTrue(directed.connectable());
        assertTrue(directed.directed());
        assertFalse(directed.scannable());
    }

    @Test void limitsHistoryToEnrolledStaticTagsAndSuppressesPersonalHealthReports(@TempDir Path temp) throws Exception {
        var csv = temp.resolve("assets.csv");
        Files.writeString(csv, "type,identifier,label\nrandom static," + TAG + ",Bench tag\n");
        String old = System.getProperty("ble.assets");
        System.setProperty("ble.assets", csv.toString());
        try {
            var session = new PassiveBleSession();
            long time = System.currentTimeMillis() - 1_000;
            byte[] beacon = ad(255, "4c00021500112233445566778899aabbccddeeff00010002c5");
            byte[] name = BleFrames.ad(9, "Sensitive tag name".getBytes(StandardCharsets.UTF_8));
            byte[] data = BleFrames.concat(beacon, name);
            var report = decode(data, time);
            assertEquals(TAG, report.address());
            for (int i = 0; i < 5; i++) session.observe(decode(data, time + 100 * i));
            byte[] rotating = BleFrames.extended(data, 1, 1);
            rotating[12] = 0x41;
            session.observe(BleHciDecoder.decode(rotating, time + 400).getFirst());
            var snapshot = session.snapshot();
            assertEquals(6, snapshot.advertisements());
            assertEquals(2, snapshot.observedAddressesByClass().get("BEACON_TAG"));
            var asset = snapshot.enrolledAssets().getFirst();
            assertEquals(1, snapshot.enrolledAssets().size());
            assertEquals(100, asset.intervalMsMedian());
            assertEquals(5, asset.history().size());
            assertEquals("NEAR", asset.history().getFirst().proximityZone());
            assertEquals(18, asset.localNameLength());
            assertFalse(snapshot.toString().contains(TAG));
            assertFalse(snapshot.toString().contains("Sensitive tag name"));
            assertFalse(snapshot.toString().contains("00112233445566778899aabbccddeeff"));

            session.observe(decode(ad(3, "0d18"), time + 500));
            session.observe(decode(data, time + 600));
            assertEquals(2, session.snapshot().advertisementsByClass().get("HEALTH_PERSONAL"));
            assertTrue(session.snapshot().enrolledAssets().isEmpty());
            assertFalse(session.snapshot().observedAddressesByClass().containsKey("HEALTH_PERSONAL"));
        } finally {
            if (old == null) System.clearProperty("ble.assets"); else System.setProperty("ble.assets", old);
        }
    }

    private static ewave.model.BleAdvertisement decode(byte[] data, long time) {
        return BleHciDecoder.decode(BleFrames.extended(data, 1, 1), time).getFirst();
    }

    private static byte[] ad(int type, String hex) { return BleFrames.ad(type, HEX.parseHex(hex)); }
}
