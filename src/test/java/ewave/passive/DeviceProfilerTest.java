package ewave.passive;

import com.fasterxml.jackson.databind.ObjectMapper;
import ewave.decoder.BleAdvertisementDecoder;
import ewave.fixtures.BleFrames;
import ewave.model.BleAdvertisement;
import ewave.model.BlePayload;
import ewave.model.PacketEvent;
import ewave.model.ProbeRequest;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.*;

class DeviceProfilerTest {
    private static final String MAC = "A4:C3:F0:11:22:33";
    private final DeviceProfiler profiler = new DeviceProfiler(new OuiLookup(new ByteArrayInputStream(
            "A4:C3:F0\tIntel\tIntel Corporate\n".getBytes(StandardCharsets.UTF_8))), new BleDecoder());

    @Test void profilesOnlyTransmittersAndKeepsChronologicalSignalMetadata() {
        profiler.observe(packet(-59, 2000));
        var first = profiler.get(MAC.toLowerCase());
        assertEquals(MAC, first.mac());
        assertEquals("Intel Corporate", first.vendor());
        assertEquals("Unknown", first.guessedType());
        assertEquals(1.0, first.estimatedMeters());
        assertEquals(Instant.ofEpochMilli(2000), first.firstSeen());
        assertNull(profiler.get("00:11:22:33:44:55"));
        profiler.observe(packet(-79, 3000));
        profiler.observe(packet(-20, 1000));
        var current = profiler.get(MAC);
        assertEquals(3, current.packetCount());
        assertEquals(-79, current.lastRssi());
        assertEquals(10.0, current.estimatedMeters());
        assertEquals(Instant.ofEpochMilli(1000), current.firstSeen());
        assertEquals(Instant.ofEpochMilli(3000), current.lastSeen());
        assertEquals(1, profiler.all().size());
        assertTrue(profiler.notable().isEmpty());
        assertThrows(UnsupportedOperationException.class, () -> profiler.all().clear());
        assertEquals(1, first.packetCount()); // Existing snapshots never mutate.
        assertNull(profiler.get(null));
        assertNull(profiler.get("malformed"));
    }

    @Test void clampsRangesAndSerializesUnavailableMeasurementsHonestly() throws Exception {
        profiler.observe(packet(-99, 1));
        assertEquals(50.0, profiler.get(MAC).estimatedMeters());
        profiler.observe(packet(-20, 2));
        assertEquals(0.5, profiler.get(MAC).estimatedMeters());
        for (double signal : new double[]{Double.NaN, Double.POSITIVE_INFINITY, 127, -128}) {
            profiler.observe(packet(signal, 3));
            assertEquals(DeviceProfiler.UNKNOWN_RSSI, profiler.get(MAC).lastRssi());
            assertTrue(Double.isNaN(profiler.get(MAC).estimatedMeters()));
        }
        var json = new ObjectMapper().readTree(new ObjectMapper().writeValueAsString(profiler.all()));
        assertTrue(json.isArray());
        assertTrue(json.get(0).path("estimatedMeters").isNull());
        assertEquals("1970-01-01T00:00:00.001Z", json.get(0).path("firstSeen").asText());
    }

    @Test void accumulatesUniqueNamedProbesWithoutTurningNetworksIntoDeviceTypes() {
        profiler.observe(probe("Lab", false));
        profiler.observe(probe("Lab", false));
        profiler.observe(probe("", true));
        profiler.observe(probe("Other lab", false));
        var profile = profiler.get(MAC);
        assertEquals(List.of("Lab", "Other lab"), profile.probedSsids());
        assertEquals(4, profile.packetCount());
        assertEquals("Unknown", profile.guessedType());
        assertThrows(UnsupportedOperationException.class, () -> profile.probedSsids().add("mutation"));
    }

    @Test void observesTextProbesWithoutDuplicatesAndPreservesExistingProfileFields() {
        profiler.observeProbe(MAC, null);
        profiler.observeProbe(MAC, "");
        profiler.observeProbe(MAC, " \t ");
        profiler.observeProbe("malformed", "Lab");
        profiler.observeProbe("ff:ff:ff:ff:ff:ff", "Lab");
        assertTrue(profiler.all().isEmpty());
        Instant before = Instant.now();
        profiler.observeProbe(MAC.toLowerCase(), "HomeNetwork");
        var first = profiler.get(MAC);
        assertEquals(List.of("HomeNetwork"), first.probedSsids());
        assertEquals(1, first.packetCount());
        assertFalse(first.lastSeen().isBefore(before.minusMillis(1)));
        assertEquals(DeviceProfiler.UNKNOWN_RSSI, first.lastRssi());
        assertTrue(Double.isNaN(first.estimatedMeters()));
        profiler.observe(advertisement(BleFrames.ad(3, new byte[]{0x0d, 0x18}), -59, null, System.currentTimeMillis()));
        var measured = profiler.get(MAC);
        profiler.observeProbe(MAC, "HomeNetwork");
        profiler.observeProbe(MAC, "CollegeWiFi");
        var current = profiler.get(MAC);
        assertEquals(List.of("HomeNetwork", "CollegeWiFi"), current.probedSsids());
        assertEquals(4, current.packetCount());
        assertFalse(current.lastSeen().isBefore(measured.lastSeen()));
        assertEquals(first.firstSeen(), current.firstSeen());
        assertEquals(measured.vendor(), current.vendor());
        assertEquals(measured.guessedType(), current.guessedType());
        assertEquals(measured.services(), current.services());
        assertEquals(measured.lastRssi(), current.lastRssi());
        assertEquals(measured.estimatedMeters(), current.estimatedMeters());
        assertEquals(1, first.packetCount());
    }

    @Test void concurrentTextProbesMergeAtomicallyAndCountEveryRequest() {
        IntStream.range(0, 1000).parallel().forEach(i -> profiler.observeProbe(MAC, "Lab " + (i % 4)));
        assertEquals(1000, profiler.get(MAC).packetCount());
        assertEquals(4, profiler.get(MAC).probedSsids().size());
        assertEquals(1, profiler.all().size());
    }

    @Test void decodesPayloadAfterCompanyBytesAndMergesServicesAndTxPower() {
        byte[] data = BleFrames.concat(BleFrames.ad(0xff, new byte[]{0x4c, 0, 0x02}),
                BleFrames.ad(3, new byte[]{0x0d, 0x18, 0x0f, 0x18}),
                BleFrames.ad(0x16, new byte[]{0x12, 0x18, 1}),
                BleFrames.ad(0x0a, new byte[]{-69}));
        profiler.observe(advertisement(data, -79, -49, 1000));
        var profile = profiler.get(MAC);
        assertEquals("iBeacon", profile.guessedType());
        assertEquals(List.of("Heart Rate Monitor", "Battery Service", "HID Device (keyboard/mouse/gamepad)"), profile.services());
        assertEquals(Math.sqrt(10), profile.estimatedMeters(), 1e-10); // Payload power takes precedence.
        profiler.observe(packet(-59, 2000));
        assertEquals("iBeacon", profiler.get(MAC).guessedType());
        assertEquals(1, profiler.notable().size());
        assertThrows(UnsupportedOperationException.class, () -> profile.services().clear());
    }

    @Test void usesHciPowerThenDefaultAndDoesNotRejectOddBleAddressPrefixes() {
        byte[] data = BleFrames.ad(3, new byte[]{0x0d, 0x18});
        profiler.observe(advertisement(data, -79, -69, 1));
        assertEquals(Math.sqrt(10), profiler.get(MAC).estimatedMeters(), 1e-10);
        assertEquals("Heart Rate Monitor", profiler.get(MAC).guessedType());
        profiler.observe(advertisement(data, -79, 127, 2));
        assertEquals(10.0, profiler.get(MAC).estimatedMeters());
        var event = advertisement(data, null, null, 3);
        profiler.observe(new BleAdvertisement("random", "D3:11:22:33:44:55", "random", false, false,
                null, event.rssi(), event.txPower(), event.timestamp(), event.rawHex(), event.payload()));
        assertNotNull(profiler.get("D3:11:22:33:44:55"));
        assertTrue(Double.isNaN(profiler.get("D3:11:22:33:44:55").estimatedMeters()));
    }

    @Test void preservesUnknownServicesAndAppliesTheLiteralNotableProfileFilter() {
        profiler.observe(advertisement(BleFrames.concat(BleFrames.ad(0xff, new byte[]{0x34, 0x12}),
                BleFrames.ad(3, new byte[]{(byte) 0xff, (byte) 0xff})), -59, null, 1));
        assertEquals("Unknown (company=0x1234)", profiler.get(MAC).guessedType());
        assertEquals(List.of("Service 0xffff"), profiler.get(MAC).services());
        assertEquals(1, profiler.notable().size());
    }

    @Test void concurrentObserversDoNotLoseCountsOrMergeUnrelatedAddresses() {
        IntStream.range(0, 2000).parallel().forEach(i -> profiler.observe(packet(-59, i)));
        assertEquals(2000, profiler.get(MAC).packetCount());
        assertEquals(Instant.ofEpochMilli(1999), profiler.get(MAC).lastSeen());
        profiler.observe(new PacketEvent("ff:ff:ff:ff:ff:ff", MAC, 1, -30, 1, "WiFi", 3000, ""));
        assertEquals(1, profiler.all().size());
        var other = advertisement(new byte[0], -50, null, 3000);
        profiler.observe(new BleAdvertisement("other", "C2:11:22:33:44:55", "random", false, false,
                null, other.rssi(), null, other.timestamp(), "", other.payload()));
        assertEquals(2, profiler.all().size());
        assertEquals("Unknown", profiler.get("C2:11:22:33:44:55").vendor());
    }

    @Test void decodesBothServiceListsAndServiceDataWithoutExposingRawBaseUuids() {
        String nearby = "0000fcf1-0000-1000-8000-00805f9b34fb";
        String custom = "12345678-abcd-1234-5678-123456789abc";
        var payload = new BlePayload(null, false, null, null, null,
                List.of(nearby, "0000ffff-0000-1000-8000-00805f9b34fb", custom), List.of(),
                List.of(new BlePayload.ServiceData(nearby, ""),
                        new BlePayload.ServiceData("0000fd69-0000-1000-8000-00805f9b34fb", "")),
                List.of(), List.of());
        profiler.observe(new BleAdvertisement("test", MAC, "public", false, false,
                null, -59, null, 1000, "", payload));
        profiler.observe(new BleAdvertisement("test", MAC, "public", false, false,
                null, -59, null, 2000, "", payload));
        assertEquals(List.of("Google Nearby Share (Android phone)", "Service 0xffff", "Custom: " + custom,
                "Google Find My Device"), profiler.get(MAC).services());
        assertEquals("Google Nearby Share (Android phone)", profiler.get(MAC).guessedType());
        assertEquals(2, profiler.get(MAC).packetCount());
    }

    @Test void enrichesNewCompanyHintsAndEspressifServices() {
        profiler.observe(advertisement(BleFrames.concat(
                BleFrames.ad(0xff, new byte[]{(byte) 0xcb, 0x0e}),
                BleFrames.ad(3, new byte[]{(byte) 0xdf, (byte) 0xfd})), -59, null, 1));
        assertEquals("OPPO device", profiler.get(MAC).guessedType());
        assertEquals(List.of("OPPO device service"), profiler.get(MAC).services());
        profiler.observe(advertisement(BleFrames.concat(
                BleFrames.ad(0xff, new byte[]{(byte) 0x8f, 0x03}),
                BleFrames.ad(3, new byte[]{(byte) 0xee, 0, (byte) 0xff, 0})), -59, null, 2));
        assertEquals("IoT module (AI-Link)", profiler.get(MAC).guessedType());
        assertEquals(List.of("OPPO device service", "Espressif custom service"), profiler.get(MAC).services());
    }

    @Test void flagsTheLocalAdministrationBitOnNewUpdatedAndSerializedProfiles() throws Exception {
        for (String prefix : new String[]{"00", "02", "04", "06", "a4", "c2"}) {
            String mac = prefix + ":11:22:33:44:55";
            boolean expected = prefix.equals("02") || prefix.equals("06") || prefix.equals("c2");
            for (long timestamp : new long[]{2000, 1000}) {
                profiler.observe(new PacketEvent(mac, MAC, 6, -59, 100, "WiFi", timestamp, ""));
                assertEquals(expected, profiler.get(mac).isRandomMac(), mac);
            }
            var json = new ObjectMapper().readTree(new ObjectMapper().writeValueAsString(profiler.get(mac)));
            assertTrue(json.path("isRandomMac").isBoolean());
            assertEquals(expected, json.path("isRandomMac").asBoolean());
        }
        var event = advertisement(new byte[0], -59, null, 3000);
        profiler.observe(new BleAdvertisement("test", "D3:11:22:33:44:55", "random", false, false,
                null, event.rssi(), null, event.timestamp(), "", event.payload()));
        assertTrue(profiler.get("D3:11:22:33:44:55").isRandomMac());
    }

    private static PacketEvent packet(double rssi, long timestamp) {
        return new PacketEvent(MAC, "00:11:22:33:44:55", 6, rssi, 100, "WiFi", timestamp, "");
    }

    private static ProbeRequest probe(String ssid, boolean wildcard) {
        return new ProbeRequest(MAC, "ff:ff:ff:ff:ff:ff", "ff:ff:ff:ff:ff:ff", ssid, "", wildcard,
                false, 6, 2437, -59, 1000, 100, List.of(), List.of());
    }

    private static BleAdvertisement advertisement(byte[] data, Integer rssi, Integer txPower, long timestamp) {
        return new BleAdvertisement("test", MAC, "public", false, false, null, rssi, txPower,
                timestamp, "", BleAdvertisementDecoder.decode(data));
    }
}
