package ewave.decoder;

import ewave.fixtures.BleFrames;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class BleAdvertisementDecoderTest {
    @Test void decodesNamesServicesAndManufacturerBytesWithoutIdentityGuesses() {
        var payload = BleAdvertisementDecoder.decode(BleFrames.data());
        assertEquals("Lab Tag", payload.localName());
        assertTrue(payload.completeName());
        assertEquals(6, payload.flags());
        assertEquals(List.of("0000180f-0000-1000-8000-00805f9b34fb"), payload.serviceUuids());
        assertEquals(0x4c, payload.manufacturerData().getFirst().companyId());
        assertEquals("010203", payload.manufacturerData().getFirst().dataHex());
        assertTrue(payload.warnings().isEmpty());
        assertThrows(UnsupportedOperationException.class, () -> payload.structures().clear());
    }

    @Test void normalizesAllUuidWidthsAndKeepsUnknownAndRepeatedStructures() {
        byte[] data = BleFrames.concat(BleFrames.ad(5, HexFormat.of().parseHex("78563412")),
                BleFrames.ad(7, HexFormat.of().parseHex("ffeeddccbbaa99887766554433221100")),
                BleFrames.ad(0x16, HexFormat.of().parseHex("aafe10ee")),
                BleFrames.ad(0x20, HexFormat.of().parseHex("7856341201")),
                BleFrames.ad(0x21, HexFormat.of().parseHex("ffeeddccbbaa9988776655443322110002")),
                BleFrames.ad(0x7e, new byte[]{1,2}), BleFrames.ad(0xff, new byte[]{0,0,3}),
                BleFrames.ad(0xff, new byte[]{0,0,4}));
        var payload = BleAdvertisementDecoder.decode(data);
        assertEquals(List.of("12345678-0000-1000-8000-00805f9b34fb", "00112233-4455-6677-8899-aabbccddeeff"), payload.serviceUuids());
        assertEquals("0000feaa-0000-1000-8000-00805f9b34fb", payload.serviceData().getFirst().uuid());
        assertEquals("10ee", payload.serviceData().getFirst().dataHex());
        assertEquals("00112233-4455-6677-8899-aabbccddeeff", payload.serviceData().getLast().uuid());
        assertEquals(8, payload.structures().size());
        assertEquals(2, payload.manufacturerData().size());
    }

    @Test void escapesNameControlsAndRetainsUntrustedNamesAsText() {
        var name = BleAdvertisementDecoder.decode(BleFrames.ad(9, "Café\n\\".getBytes(StandardCharsets.UTF_8)));
        assertEquals("Café\\u000a\\\\", name.localName());
        assertEquals("hex:fffe", BleAdvertisementDecoder.decode(BleFrames.ad(9, new byte[]{-1,-2})).localName());
        assertEquals("<img onerror=alert(1)>", BleAdvertisementDecoder.decode(
                BleFrames.ad(9, "<img onerror=alert(1)>".getBytes(StandardCharsets.UTF_8))).localName());
        var complete = BleAdvertisementDecoder.decode(BleFrames.concat(BleFrames.ad(9, new byte[]{'L','a','b'}),
                BleFrames.ad(8, new byte[]{'L'})));
        assertEquals("Lab", complete.localName());
        assertTrue(complete.completeName());
    }

    @Test void reportsMalformedFieldsAndDecodesOnlyAvailableEvidence() {
        assertEquals(List.of("Truncated AD structure"), BleAdvertisementDecoder.decode(new byte[]{5,9,65}).warnings());
        var malformed = BleAdvertisementDecoder.decode(BleFrames.concat(BleFrames.ad(3, new byte[]{1}),
                BleFrames.ad(0xff, new byte[]{1}), BleFrames.ad(0x16, new byte[]{1}),
                BleFrames.ad(0x0a, new byte[0]), BleFrames.ad(0x19, new byte[]{1})));
        assertEquals(5, malformed.warnings().size());
        assertTrue(malformed.serviceUuids().isEmpty());
        assertTrue(malformed.manufacturerData().isEmpty());
        assertNull(malformed.txPower());
        var radio = BleAdvertisementDecoder.decode(BleFrames.concat(BleFrames.ad(0x0a,new byte[]{-20}),
                BleFrames.ad(0x19, new byte[]{0x40, 0})));
        assertEquals(-20, radio.txPower());
        assertEquals(64, radio.appearance());
        assertThrows(IllegalArgumentException.class, () -> BleAdvertisementDecoder.decode(new byte[1651]));
        assertFalse(BleAdvertisementDecoder.decode(new byte[]{0,9,1}).warnings().isEmpty());
    }
}
