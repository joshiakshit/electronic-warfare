package ewave.decoder;

import ewave.fixtures.ProbeFrames;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.List;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

class Dot11FrameDecoderTest {
    private Dot11Frame decode(byte[] packet) { return Dot11FrameDecoder.decodeAny(packet, 105, 1000); }

    @Test void decodesProbeAddressesAndCapabilitiesWithoutInventingRadioMetadata() {
        var named = decode(ProbeFrames.frame("Lab (guest)"));
        assertTrue(named.probe());
        assertEquals("02:11:22:33:44:55", named.addr2());
        assertEquals("ff:ff:ff:ff:ff:ff", named.addr1());
        assertEquals("ff:ff:ff:ff:ff:ff", named.addr3());
        assertEquals("4c61622028677565737429", HexFormat.of().formatHex(named.ies().first(0)));
        assertEquals(0, named.frequencyMhz());
        assertTrue(Double.isNaN(named.rssi()));
        assertEquals(List.of(1.0, 2.0, 5.5, 11.0, 6.0, 9.0, 12.0), rates(named));
        assertEquals("00112201", named.ies().elements().getLast().vendorKey());
        assertTrue(Dot11InformationElements.hidden(decode(ProbeFrames.frame("")).ies().first(0)));
    }

    @Test void preservesSsidOctetsAndRejectsOversizedNames() {
        byte[] raw = { 'A', 0, 10, (byte) 0xff };
        assertArrayEquals(raw, decode(ProbeFrames.frame(raw)).ies().first(0));
        assertNotNull(decode(ProbeFrames.frame("x".repeat(32))));
        assertNull(decode(ProbeFrames.frame("x".repeat(33))));
    }

    private static List<Double> rates(Dot11Frame frame) {
        return CapabilityDecoder.decode(frame.ies(), frame.frequencyMhz()).supportedRates();
    }

    @Test void doesNotReportMembershipSelectorsAsLegacyDataRates() {
        byte[] frame = ProbeFrames.frame("Lab");
        byte[] withSelectors = Arrays.copyOf(frame, frame.length + 10);
        withSelectors[frame.length] = 50;
        withSelectors[frame.length + 1] = 8;
        for (int i = 0; i < 8; i++) withSelectors[frame.length + 2 + i] = (byte) (0x80 | (120 + i));
        assertEquals(rates(decode(frame)), rates(decode(withSelectors)));
    }

    @Test void readsRadiotapAlignmentExtendedPresenceAndFcsFlags() {
        byte[] frame = ProbeFrames.frame("Lab");
        var simple = Dot11FrameDecoder.decodeAny(ProbeFrames.radiotap(frame), 127, 1000);
        assertNotNull(simple);
        assertEquals(6, Dot11FrameDecoder.channel(simple.frequencyMhz()));
        assertEquals(2437, simple.frequencyMhz());
        assertEquals(-47, simple.rssi());
        assertEquals(frame.length, simple.frameLength());

        // Two present words, aligned TSFT, flags, rate, channel, RSSI; four FCS bytes.
        byte[] extended = new byte[31 + frame.length + 4];
        ByteBuffer bytes = ByteBuffer.wrap(extended).order(ByteOrder.LITTLE_ENDIAN);
        bytes.putShort((short) 0).putShort((short) 31).putInt(0x8000002f).putInt(0);
        bytes.position(16);
        bytes.putLong(123).put((byte) 0x10).put((byte) 2).putShort((short) 5180)
                .putShort((short) 0xa0).put((byte) -65).put(frame);
        var result = Dot11FrameDecoder.decodeAny(extended, 127, 1000);
        assertNotNull(result);
        assertEquals(36, Dot11FrameDecoder.channel(result.frequencyMhz()));
        assertEquals(-65, result.rssi());
        assertEquals(frame.length, result.frameLength());
        extended[24] |= 0x40;
        assertNull(Dot11FrameDecoder.decodeAny(extended, 127, 1000));
        extended[24] = 0x10;
        extended[2] = 8; // Present words/fields now extend beyond the declared header.
        assertNull(Dot11FrameDecoder.decodeAny(extended, 127, 1000));
    }

    @Test void rejectsUnsupportedTypesFragmentsMalformedElementsAndInvalidSources() {
        byte[] frame = ProbeFrames.frame("Lab");
        for (int flag : new int[]{0x04, 0x0041, 0x0140, 0x0440, 0x4040}) {
            byte[] bad = frame.clone();
            bad[0] = (byte) flag;
            bad[1] = (byte) (flag >> 8);
            assertNull(decode(bad), Integer.toHexString(flag));
        }
        byte[] fragmented = frame.clone();
        fragmented[22] |= 1;
        assertNull(decode(fragmented));
        byte[] multicast = frame.clone();
        multicast[10] |= 1;
        assertNull(decode(multicast));
        byte[] zero = frame.clone();
        Arrays.fill(zero, 10, 16, (byte) 0);
        assertNull(decode(zero));
        assertNull(decode(Arrays.copyOf(frame, 23)));
        assertNull(decode(Arrays.copyOf(frame, frame.length - 1))); // Truncated vendor IE.
        assertFalse(decode(Arrays.copyOf(frame, 24)).ies().has(0));
        byte[] duplicate = Arrays.copyOf(frame, frame.length + 2); // Second empty SSID IE.
        assertNull(decode(duplicate));
        assertNull(Dot11FrameDecoder.decodeAny(frame, 1, 1000));
        assertNull(Dot11FrameDecoder.decodeAny(frame, 105, -1));
    }

    @Test void decodesSixteenByteTwoAddressControlHeaders() {
        for (int subtype : List.of(8, 9, 10)) {
            byte[] header = HexFormat.of().parseHex("00000000001122334466021122334455");
            header[0] = (byte) ((subtype << 4) | 4);
            var frame = Dot11FrameDecoder.decodeAny(ProbeFrames.radiotap(header), 127, 1000);
            assertTrue(Dot11FrameDecoder.supportedFrameControl(header[0] & 0xff));
            assertNotNull(frame);
            assertEquals(16, frame.frameLength());
            assertEquals(1, frame.type());
            assertEquals(subtype, frame.subtype());
            assertEquals("00:11:22:33:44:66", frame.addr1());
            assertEquals("02:11:22:33:44:55", frame.addr2());
            assertNull(frame.addr3());
            assertNull(frame.ies());
            assertEquals(0, frame.sequenceControl());
            assertEquals(-1, frame.tid());
            assertNull(decode(Arrays.copyOf(header, 15)));
            Arrays.fill(header, 10, 16, (byte) 0);
            assertNull(decode(header));
            header[10] = 1;
            assertNull(decode(header));
        }
        assertFalse(Dot11FrameDecoder.supportedFrameControl(0xd4)); // One-address ACK.
    }

    @Test void distinguishesClearReasonCodesFromOpaqueProtectedManagementBodies() {
        for (int subtype : List.of(10, 12)) {
            byte[] frame = HexFormat.of().parseHex("00000000021122334455001122334466001122334466100008007f0101");
            frame[0] = (byte) (subtype << 4);
            assertEquals(8, decode(frame).status());
            assertArrayEquals(new byte[]{1}, decode(frame).ies().first(127));
            assertNull(decode(Arrays.copyOf(frame, 25)));

            frame[1] = 0x40;
            assertTrue(Dot11FrameDecoder.supportedFrameControl((frame[0] & 0xff) | 0x4000));
            frame[28] = (byte) 0xff;
            assertEquals(-1, decode(frame).status());
            assertTrue(decode(frame).ies().elements().isEmpty());
            assertNull(decode(Arrays.copyOf(frame, 25)));
            frame[22] |= 1;
            assertNull(decode(frame));
        }
    }

    @Test void decodesUnprotectedFtActionsAndRejectsIncompleteBodies() {
        byte[] request = actionFrame("06010211223344550011223344663603010201370100");
        var ft = decode(request);
        assertEquals(13, ft.subtype());
        assertEquals(Dot11FrameDecoder.FT_ACTION_REQUEST, ft.authenticationAlgorithm());
        assertEquals("00:11:22:33:44:66", ft.currentAp());
        assertArrayEquals(new byte[]{1, 2, 1}, ft.ies().first(54));
        assertTrue(ft.ies().has(55));
        assertEquals(-1, ft.status());

        byte[] response = actionFrame("06020211223344550011223344660101370100");
        ft = decode(response);
        assertEquals(Dot11FrameDecoder.FT_ACTION_RESPONSE, ft.authenticationAlgorithm());
        assertEquals("00:11:22:33:44:66", ft.currentAp());
        assertEquals(257, ft.status());
        assertTrue(ft.ies().has(55));
        assertNull(decode(Arrays.copyOf(response, 39)));
        assertNull(decode(Arrays.copyOf(request, 37)));
        assertNull(decode(Arrays.copyOf(request, request.length - 1)));

        assertTrue(Dot11FrameDecoder.supportedFrameControl(0xd0));
        for (int flags : new int[]{1, 2, 4, 0x40}) {
            request[1] = (byte) flags;
            assertFalse(Dot11FrameDecoder.supportedFrameControl(0xd0 | flags << 8));
            assertNull(decode(request));
        }
        request[1] = 0;
        request[22] |= 1;
        assertNull(decode(request));
    }

    @Test void readsBtmStatusAndTargetWithoutTreatingActionPayloadsAsIes() {
        var request = decode(actionFrame("0a0701010000ff"));
        assertEquals(Dot11FrameDecoder.BTM_ACTION_REQUEST, request.authenticationAlgorithm());
        assertTrue(request.ies().elements().isEmpty());
        var accepted = decode(actionFrame("0a08010000001122334466"));
        assertEquals(Dot11FrameDecoder.BTM_ACTION_RESPONSE, accepted.authenticationAlgorithm());
        assertEquals(0, accepted.status());
        assertEquals("00:11:22:33:44:66", accepted.currentAp());
        assertNull(decode(actionFrame("0a08010000")).currentAp());
        var rejected = decode(actionFrame("0a0801ff00001122334466"));
        assertEquals(255, rejected.status());
        assertNull(rejected.currentAp());
        assertTrue(rejected.ies().elements().isEmpty());
        assertTrue(decode(actionFrame("0405ff")).ies().elements().isEmpty());
        for (String body : List.of("0a", "0a0701010000", "0a080100")) assertNull(decode(actionFrame(body)));
    }

    private static byte[] actionFrame(String body) {
        return HexFormat.of().parseHex("d00000000011223344550211223344550011223344551000" + body);
    }

    @Test void decodesLegacyHtHeAndCoLocatedAntennaReadingsAcrossPresentWords() {
        byte[] frame = ProbeFrames.frame("Lab");
        int headerLength = 91;
        var buffer = ByteBuffer.allocate(headerLength + frame.length + 4).order(ByteOrder.LITTLE_ENDIAN);
        buffer.putShort((short) 0).putShort((short) headerLength).putInt(0xa0f808ff).putInt(0x860);
        buffer.position(16);
        buffer.putLong(123).put((byte) 0x10).put((byte) 11).putShort((short) 5955).putShort((short) 0xa000)
                .putShort((short) 0).put((byte) -51).put((byte) -96).putShort((short) 0).put((byte) 0)
                .put((byte) 7).put((byte) 5).put((byte) 0);
        buffer.position(76);
        buffer.putShort((short) 0x4062).putShort((short) 2).putShort((short) 0x1900).putShort((short) 0)
                .putShort((short) 0x28).putShort((short) 2);
        buffer.put((byte) -42).put((byte) -92).put((byte) 2).put(frame);
        var decoded = Dot11FrameDecoder.decodeAny(buffer.array(), 127, 1000);
        assertNotNull(decoded);
        assertEquals(frame.length, decoded.frameLength());
        assertEquals(5955, decoded.frequencyMhz());
        assertEquals(123L, decoded.radiotapTsft());
        var radio = decoded.radiotap();
        assertEquals(0xa000, radio.channelFlags());
        assertEquals(5.5, radio.legacyRateMbps());
        assertEquals(new Radiotap.HtRate(0, "40 MHz", true), radio.ht());
        assertEquals(new Radiotap.HeRate("HE MU", 9, 2, "484-tone RU", 3.2, true), radio.he());
        assertEquals(-51, radio.signalDbm());
        assertEquals(-96, radio.noiseDbm());
        assertEquals(0, radio.antenna());
        assertEquals(45, radio.snrDb());
        buffer.putShort(2, (short) 87);
        assertNull(Dot11FrameDecoder.decodeAny(buffer.array(), 127, 1000));
    }

    @Test void skipsVendorNamespaceAndOnlyDecodesFieldsMarkedKnown() {
        byte[] frame = ProbeFrames.frame("Lab");
        var bytes = ByteBuffer.allocate(43 + frame.length).order(ByteOrder.LITTLE_ENDIAN);
        bytes.putShort((short) 0).putShort((short) 43).putInt(0xc0000000).putInt(0xa0000001).putInt(0x00880860);
        bytes.put(new byte[]{0, 17, 34, 1}).putShort((short) 3).put(new byte[]{5, 6, 7});
        bytes.put((byte) -53).put((byte) -87).put((byte) 1);
        bytes.put((byte) 0).put((byte) 0xff).put((byte) 22);
        bytes.position(32);
        bytes.putShort((short) 1).putShort((short) 0).putShort((short) 0x1900).putShort((short) 0)
                .putShort((short) 0x23).put((byte) 0);
        // HE is 12 bytes and must fit entirely before the 802.11 header.
        assertNull(Dot11FrameDecoder.decodeAny(bytes.array(), 127, 1000));
        var complete = ByteBuffer.allocate(44 + frame.length).order(ByteOrder.LITTLE_ENDIAN);
        complete.put(bytes.array(), 0, 43).put((byte) 0).put(frame).putShort(2, (short) 44);
        var radio = Dot11FrameDecoder.decodeAny(complete.array(), 127, 1000).radiotap();
        assertEquals(new Radiotap.HtRate(null, null, null), radio.ht());
        assertEquals(new Radiotap.HeRate("HE extended SU", null, null, null, null, null), radio.he());
        assertEquals(34, radio.snrDb());
        assertNull(Dot11FrameDecoder.decodeAny(ProbeFrames.radiotap(frame), 127, 1000).radiotap().snrDb());
        assertNull(decode(frame).radiotap());
    }

    @Test void distinguishesRsnAkmSelectorsByOuiAndIgnoresAnInvalidSuiteCount() {
        byte[] rsn = HexFormat.of().parseHex("0100000fac040100000fac040400000fac18000fac190050f208506f9a02c000");
        var ies = new Dot11InformationElements(List.of(new Dot11InformationElements.Element(48, rsn)));
        var caps = CapabilityDecoder.decode(ies, 5955, true);
        assertEquals(List.of("SAE Extended Key", "FT/SAE Extended Key", "0x0050f208", "DPP"), caps.rsnAkmSuites());
        assertEquals(List.of("WPA3-Personal (SAE)"), caps.securityModes());
        assertTrue(caps.managementFeatures().fastTransition());
        rsn[12] = (byte) 0xff;
        var malformed = new Dot11InformationElements(List.of(new Dot11InformationElements.Element(48, rsn)));
        assertTrue(CapabilityDecoder.decode(malformed, 5955).rsnAkmSuites().isEmpty());
    }

    @Test void decodesOnlyOweTransitionElementsWithABoundedNameAndUnicastPeer() {
        var hex = HexFormat.of();
        for (String malformed : List.of("506f9a1c001122334455", "506f9a1c0011223344550241",
                "506f9a1c0111223344550141", "506f9a1c0000000000000141",
                "506f9a1c00112233445521" + "41".repeat(33))) {
            var ies = new Dot11InformationElements(List.of(new Dot11InformationElements.Element(221, hex.parseHex(malformed))));
            assertNull(SecurityDecoder.decodeOweTransition(ies));
        }
        var ies = new Dot11InformationElements(List.of(new Dot11InformationElements.Element(221,
                hex.parseHex("506f9a1c021122334455034100ff00"))));
        var owe = SecurityDecoder.decodeOweTransition(ies);
        assertNotNull(owe);
        assertEquals("02:11:22:33:44:55", owe.peerBssid());
        assertArrayEquals(new byte[]{'A', 0, (byte) 0xff}, owe.ssidBytes());
        assertEquals("SSID bytes 41 00 ff", owe.ssidLabel());
    }
}
