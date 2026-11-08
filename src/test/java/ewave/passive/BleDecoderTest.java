package ewave.passive;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class BleDecoderTest {
    private final BleDecoder decoder = new BleDecoder();

    @Test void recognizesEveryRequestedAppleSubtypeAndHandlesMissingBytes() {
        Map<Integer, String> labels = Map.of(0x02, "iBeacon", 0x0c, "Apple Handoff", 0x0f, "Apple Nearby Action",
                0x10, "Apple Nearby Info", 0x13, "Apple device", 0x09, "AirPlay device",
                0xff, "Apple device");
        labels.forEach((type, label) -> {
            var finding = decoder.decode(0x004c, new byte[]{type.byteValue()});
            assertEquals(label, finding.deviceType());
            assertEquals(type != 0x09 && type != 0x13 && type != 0xff, finding.notable());
            assertFalse(finding.detail().isBlank());
        });
        for (byte[] empty : new byte[][]{null, new byte[0]}) {
            assertEquals("Apple device", decoder.decode(0x004c, empty).deviceType());
            assertFalse(decoder.decode(0x004c, empty).notable());
        }
    }

    @Test void recognizesOtherCompaniesWithoutInventingSubtypes() {
        assertEquals("Windows device", decoder.decode(0x0006, new byte[]{2}).deviceType());
        assertEquals("Samsung device", decoder.decode(0x0075, new byte[]{2}).deviceType());
        assertEquals("OPPO device", decoder.decode(0x0ecb, null).deviceType());
        assertEquals("IoT module (AI-Link)", decoder.decode(0x038f, null).deviceType());
        assertEquals("Unknown (company=0xabcd)", decoder.decode(0xabcd, null).deviceType());
        for (int company : new int[]{0x0006, 0x0075, 0x0ecb, 0x038f, 0xabcd})
            assertFalse(decoder.decode(company, null).notable());
    }

    @Test void labelsOnlyTheRequestedServices() {
        assertEquals("Heart Rate Monitor", decoder.decodeService(0x180d));
        assertEquals("HID Device (keyboard/mouse/gamepad)", decoder.decodeService(0x1812));
        assertEquals("Battery Service", decoder.decodeService(0x180f));
        assertEquals("Audio Device (speaker/headphones)", decoder.decodeService(0x110b));
        assertEquals("Link Loss (wearable)", decoder.decodeService(0x1803));
        assertEquals("Google Nearby Share (Android phone)", decoder.decodeService(0xfcf1));
        assertEquals("Google Find My Device", decoder.decodeService(0xfd69));
        assertEquals("OPPO device service", decoder.decodeService(0xfddf));
        assertEquals("Google Eddystone Beacon", decoder.decodeService(0xfeaa));
        assertEquals("Samsung SmartThings", decoder.decodeService(0xfd5a));
        assertEquals("Espressif custom service", decoder.decodeService(0xee));
        assertEquals("Espressif custom service", decoder.decodeService(0xff));
        assertNull(decoder.decodeService(0xffff));
    }

    @Test void extractsOnlyCompleteBluetoothBaseUuidsCaseInsensitively() {
        assertEquals(0xfcf1, BleDecoder.extract16BitUuid("0000fcf1-0000-1000-8000-00805f9b34fb"));
        assertEquals(0xfd69, BleDecoder.extract16BitUuid("0000FD69-0000-1000-8000-00805F9B34FB"));
        assertEquals(0, BleDecoder.extract16BitUuid("00000000-0000-1000-8000-00805f9b34fb"));
        assertEquals(0xffff, BleDecoder.extract16BitUuid("0000ffff-0000-1000-8000-00805f9b34fb"));
        for (String uuid : new String[]{null, "", "fcf1", "0000gggg-0000-1000-8000-00805f9b34fb",
                "1234fcf1-0000-1000-8000-00805f9b34fb", "0000fcf1-0000-1000-8000-00805f9b34fc",
                "0000fcf1-0000-1000-8000-00805f9b34fb-extra", "0000fcf1-0000-1000-8000-00805f9b34fb\n"})
            assertEquals(-1, BleDecoder.extract16BitUuid(uuid), String.valueOf(uuid));
    }

    @Test void labelsKnownUnknownAndCustomServiceUuids() {
        assertEquals("Google Nearby Share (Android phone)",
                BleDecoder.decodeServiceUuid("0000fcf1-0000-1000-8000-00805f9b34fb"));
        assertEquals("Google Find My Device",
                BleDecoder.decodeServiceUuid("0000FD69-0000-1000-8000-00805F9B34FB"));
        assertEquals("Espressif custom service", BleDecoder.decodeServiceUuid("000000ee-0000-1000-8000-00805f9b34fb"));
        assertEquals("Espressif custom service", BleDecoder.decodeServiceUuid("000000ff-0000-1000-8000-00805f9b34fb"));
        assertEquals("Service 0xffff", BleDecoder.decodeServiceUuid("0000ffff-0000-1000-8000-00805f9b34fb"));
        assertEquals("Service 0x1", BleDecoder.decodeServiceUuid("00000001-0000-1000-8000-00805f9b34fb"));
        String custom = "12345678-ABCD-1234-5678-123456789ABC";
        assertEquals("Custom: " + custom, BleDecoder.decodeServiceUuid(custom));
        assertEquals("Custom: malformed", BleDecoder.decodeServiceUuid("malformed"));
        assertEquals("Custom: null", BleDecoder.decodeServiceUuid(null));
    }
}
