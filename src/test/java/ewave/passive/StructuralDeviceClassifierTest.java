package ewave.passive;

import ewave.decoder.CapabilityDecoder;
import ewave.decoder.Dot11InformationElements;
import ewave.decoder.Dot11InformationElements.Element;
import ewave.passive.WifiInventory.Role;
import org.junit.jupiter.api.Test;

import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class StructuralDeviceClassifierTest {
    private static final HexFormat HEX = HexFormat.of();

    @Test void distinguishesApplePhonesLaptopsAndHotspotsWithLocalAddresses() {
        assertVendorClassification("Phone / Tablet", "iOS / iPadOS", 0.78, Role.CLIENT, vendor("0017f201"), ht(2));
        assertVendorClassification("Laptop", "macOS", 0.78, Role.CLIENT, vendor("0017f201"), ht(3));
        assertVendorClassification("Mobile Hotspot", "iOS", 0.82, Role.AP, vendor("0017f201"), ht(2));
        assertVendorClassification("Phone / Tablet", "iOS / iPadOS", 0.78, Role.CLIENT, vendor("00a04001"));
    }

    @Test void identifiesSamsungAndroidAndWindowsFromVendorEvidence() {
        assertVendorClassification("Phone", "Android (Samsung)", 0.80, Role.CLIENT, vendor("0000f001"));
        assertVendorClassification("Phone", "Android", 0.75, Role.CLIENT, vendor("001a1101"));
        assertVendorClassification("Laptop / PC", "Windows", 0.76, Role.CLIENT, vendor("0050f208"));
        assertVendorClassification("Laptop / PC", "Windows", 0.76, Role.CLIENT,
                vendor("0050f204102100094d6963726f736f6674"));
        assertEquals("UNCLASSIFIED", classify(Role.CLIENT, vendor("0050f202"), vendor("0050f204")).family());
    }

    @Test void recognizesPrimaryWpsDeviceTypeAheadOfVendorHeuristics() {
        assertWpsClassification("Laptop", "00010050f2040005");
        assertWpsClassification("Computer / PC", "00010050f2040001");
        assertWpsClassification("Phone", "000a0050f2040001");
        assertWpsClassification("Printer", "00030050f2040001");
        assertWpsClassification("Camera", "00040050f2040001");
        assertWpsClassification("Access Point", "00060050f2040001");
        assertWpsClassification("Smart TV / Display", "00070050f2040001");
        assertWpsClassification("Media / Console", "00080050f2040001");
        assertEquals("UNCLASSIFIED", classify(Role.CLIENT, vendor("0050f20410540006000a0050f204")).family());
        assertEquals("UNCLASSIFIED", classify(Role.CLIENT, vendor("0050f20410540008000a0050f20400")).family());
    }

    @Test void usesStructuralRadioRulesOnlyWithTheRequiredCapabilityEvidence() {
        var iot = new StructuralDeviceClassifier.Classification("IoT / Embedded", null, 0.60, "RADIO_CAPABILITY_HEURISTIC");
        assertEquals(iot, classify(Role.CLIENT, ht(1)));
        assertEquals("UNCLASSIFIED", classify(Role.CLIENT, ht(2)).family());
        var transition = new Element(127, new byte[]{0, 0, 8});
        assertEquals("UNCLASSIFIED", classify(Role.CLIENT, ht(1), transition).family());
        byte[] he = new byte[22];
        he[0] = 35;
        he[18] = (byte) 0xf0;
        he[19] = (byte) 0xff;
        assertEquals(new StructuralDeviceClassifier.Classification("Phone / Mobile Client", null, 0.52,
                "RADIO_CAPABILITY_HEURISTIC"), classify(Role.CLIENT, new Element(255, he), transition));

        assertEquals("Mobile Hotspot", classify(Role.AP).family());
        assertEquals("Access Point", classify(Role.AP, new Element(54, new byte[]{1, 2, 3})).family());
    }

    @Test void mapsRegisteredVendorsAndKeepsUnrecognizedNames() {
        var classifier = new StructuralDeviceClassifier();
        for (String vendor : List.of("Espressif Inc.", "Tuya Smart", "Shenzhen Bilian Electronic", "Sonoff", "Raspberry Pi Trading Ltd"))
            assertEquals(new StructuralDeviceClassifier.Classification("IoT / Embedded", null, 0.70, "OUI_VENDOR"),
                    classifier.classify(null, Role.CLIENT, false, false, vendor, List.of(), null, false, null));
        assertEquals(new StructuralDeviceClassifier.Classification("Apple Device", "iOS / macOS", 0.65, "OUI_VENDOR"),
                classifier.classify(null, Role.CLIENT, false, false, "Apple, Inc.", List.of(), null, false, null));
        assertEquals(new StructuralDeviceClassifier.Classification("Phone", "Android", 0.60, "OUI_VENDOR"),
                classifier.classify(null, Role.CLIENT, false, false, "Beijing Xiaomi Mobile", List.of(), null, false, null));
        assertEquals(new StructuralDeviceClassifier.Classification("Fixture Inc.", null, 0.30, "OUI_VENDOR"),
                classifier.classify(null, Role.CLIENT, false, false, "Fixture Inc.", List.of(), null, false, null));
    }

    private static void assertVendorClassification(String family, String os, double confidence, Role role, Element... elements) {
        assertEquals(new StructuralDeviceClassifier.Classification(family, os, confidence, "VENDOR_IE_HEURISTIC"),
                classify(role, elements));
    }

    private static void assertWpsClassification(String family, String deviceType) {
        assertEquals(new StructuralDeviceClassifier.Classification(family, null, 0.85, "WPS_DEVICE_TYPE"),
                classify(Role.CLIENT, vendor("0050f20410540008" + deviceType), vendor("0000f001")));
    }

    private static StructuralDeviceClassifier.Classification classify(Role role, Element... elements) {
        var classifier = new StructuralDeviceClassifier();
        var ies = new Dot11InformationElements(List.of(elements));
        classifier.observe(ies, 1000, role == Role.AP);
        return classifier.classify(null, role, true, false, null, List.of("2.4 GHz"),
                CapabilityDecoder.decode(ies, 2437), false, null);
    }

    private static Element vendor(String hex) { return new Element(221, HEX.parseHex(hex)); }

    private static Element ht(int streams) {
        byte[] payload = new byte[26];
        for (int index = 0; index < streams; index++) payload[3 + index] = (byte) 0xff;
        return new Element(45, payload);
    }
}
