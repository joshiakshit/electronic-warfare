package ewave.decoder;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class MultipleBssidDecoderTest {
    private static final String PARENT = "00:11:22:33:44:ae";
    private static final byte[] RSN = java.util.HexFormat.of().parseHex("0100000fac040100000fac040100000fac08c000");

    @Test void wrapsIndexWithinTheAdvertisedBitsAndRetainsTheProfileSsid() {
        var profile = MultipleBssidDecoder.decode(advertisement(
                new byte[]{2, 0, 8, 85, 1, 2, 0, 3, 'L', 'a', 'b'})).getFirst();

        assertEquals("00:11:22:33:44:ac", profile.bssid());
        assertArrayEquals(new byte[]{'L', 'a', 'b'}, profile.ies().first(0));
        assertEquals(0x11, profile.capability());
        assertEquals(List.of("SAE"), profile.security().rsnAkmSuites());
        assertEquals("Required", profile.security().profiles().getFirst().managementFrameProtection());
    }

    @Test void honorsNonInheritanceAndExplicitCapabilityAndPreservesHiddenProfileSsid() {
        var profile = MultipleBssidDecoder.decode(advertisement(
                new byte[]{2, 0, 15, 85, 1, 1, 0, 0, 83, 2, 1, 0, (byte) 255, 4, 56, 1, 48, 0})).getFirst();

        assertEquals("00:11:22:33:44:af", profile.bssid());
        assertTrue(profile.ies().has(0));
        assertTrue(Dot11InformationElements.hidden(profile.ies().first(0)));
        assertEquals(1, profile.capability());
        assertTrue(profile.security().profiles().isEmpty());
    }

    @Test void skipsInvalidProfilesWithoutLosingValidSiblings() {
        var profiles = MultipleBssidDecoder.decode(advertisement(
                new byte[]{0, 0, 3, 85, 1, 1},
                new byte[]{2, 0, 3, 85, 1, 4, 0, 3, 85, 1, 0, 0, 3, 85, 1, 1, 0, 4, 85, 1},
                new byte[]{8, 0, 3, 85, 1, (byte) 255}));
        assertEquals(List.of("00:11:22:33:44:af", "00:11:22:33:44:ad"),
                profiles.stream().map(MultipleBssidDecoder.Profile::bssid).toList());
    }

    private static Dot11Frame advertisement(byte[]... mbssidValues) {
        var elements = new java.util.ArrayList<Dot11InformationElements.Element>();
        elements.add(new Dot11InformationElements.Element(0, new byte[]{'P', 'a', 'r', 'e', 'n', 't'}));
        elements.add(new Dot11InformationElements.Element(48, RSN));
        for (byte[] value : mbssidValues) elements.add(new Dot11InformationElements.Element(71, value));
        return new Dot11Frame(0, 8, 0, 0, -1, "ff:ff:ff:ff:ff:ff", PARENT, PARENT, null,
                1000, 5975, -52, null, 0, new Dot11InformationElements(elements), 0L, 100, 0x11, null, -1, -1);
    }
}
