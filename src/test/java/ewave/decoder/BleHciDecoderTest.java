package ewave.decoder;

import ewave.fixtures.BleFrames;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

class BleHciDecoderTest {
    @Test void decodesLegacyReportsAndKeepsPublicAndRandomAddressSpacesSeparate() {
        byte[] random = BleFrames.legacy(BleFrames.data());
        var report = BleHciDecoder.decode(random, 1000).getFirst();
        assertEquals("c2:11:22:33:44:55", report.address());
        assertEquals("random static", report.addressType());
        assertEquals(-55, report.rssi());
        assertFalse(report.extended());
        var publicReport = BleHciDecoder.decode(BleFrames.legacy(BleFrames.data(),0,
                HexFormat.of().parseHex("5544332211c2")),1000).getFirst();
        assertNotEquals(report.deviceId(), publicReport.deviceId());
        byte[] noSignal = random.clone(); noSignal[noSignal.length-1] = 127;
        assertNull(BleHciDecoder.decode(noSignal,1000).getFirst().rssi());
    }

    @Test void decodesExtendedReportsAndSkipsIncompleteAnonymousPayloads() {
        var report = BleHciDecoder.decode(BleFrames.extended(BleFrames.data(), 0x01, 1),1000).getFirst();
        assertTrue(report.extended());
        assertEquals(7,report.advertisingSid());
        assertEquals(-8,report.txPower());
        assertEquals(-65,report.rssi());
        assertTrue(BleHciDecoder.decode(BleFrames.extended(BleFrames.data(),0x20,1),1000).isEmpty());
        assertTrue(BleHciDecoder.decode(BleFrames.extended(BleFrames.data(),0x40,1),1000).isEmpty());
        assertTrue(BleHciDecoder.decode(BleFrames.extended(BleFrames.data(),0,255),1000).isEmpty());
        assertTrue(BleHciDecoder.decode(BleFrames.extended(BleFrames.data(),8,1),1000).getFirst().scanResponse());
    }

    @Test void supportsMultipleReportsAndRejectsStructurallyTruncatedEventsAtomically() {
        byte[] one = BleFrames.legacy(BleFrames.data());
        byte[] body = Arrays.copyOfRange(one,4,one.length);
        assertEquals(2,BleHciDecoder.decode(BleFrames.event(2,body,body),1000).size());
        byte[] cut = Arrays.copyOf(one,one.length-1);
        cut[1]--;
        assertTrue(BleHciDecoder.decode(cut,1000).isEmpty());
        assertTrue(BleHciDecoder.decode(new byte[3],1000).isEmpty());
        assertTrue(BleHciDecoder.decode(one,-1).isEmpty());
        byte[] wrongLength = one.clone(); wrongLength[1] = 1;
        assertTrue(BleHciDecoder.decode(wrongLength,1000).isEmpty());
    }

    @Test void neverDecodesTheFinalPieceOfAKnownFragmentChainAsACompletePayload() {
        var stream = new BleHciDecoder();
        assertTrue(stream.accept(BleFrames.extended(new byte[]{4,9,65},0x20,1),1000).isEmpty());
        assertTrue(stream.accept(BleFrames.extended(BleFrames.data(),0,1),1001).isEmpty());
        assertEquals(1,stream.accept(BleFrames.extended(BleFrames.data(),0,1),1002).size());
    }
}
