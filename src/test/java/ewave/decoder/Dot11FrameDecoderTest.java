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
}
