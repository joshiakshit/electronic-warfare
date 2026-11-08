package ewave.capture;

import ewave.fixtures.BleFrames;
import ewave.model.BleAdvertisement;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class BleCaptureReaderTest {
    private List<BleAdvertisement> read(byte[] bytes, int index) throws IOException {
        var ads = new ArrayList<BleAdvertisement>();
        BleCaptureReader.read(new ByteArrayInputStream(bytes),index,ads::add);
        return ads;
    }
    @Test void streamsH4AndBluezMonitorWithCorrectEpochAndControllerFiltering() throws Exception {
        for (int format : new int[]{1002,2001}) {
            byte[] bytes = BleFrames.snoop(format,2,BleFrames.legacy(BleFrames.data()),
                    BleFrames.extended(BleFrames.data(),0,1));
            var ads = read(bytes,2);
            assertEquals(2,ads.size());
            assertEquals(1_700_000_000_000L,ads.getFirst().timestamp());
            assertEquals(1_700_000_000_001L,ads.getLast().timestamp());
            if (format == 2001) assertTrue(read(bytes,0).isEmpty());
        }
    }
    @Test void rejectsMalformedHeadersLengthsAndPartialRecords() {
        byte[] valid = BleFrames.snoop(1002,0,BleFrames.legacy(BleFrames.data()));
        for(int cut:new int[]{0,7,15,18,39,valid.length-1})
            assertThrows(IOException.class,()->read(Arrays.copyOf(valid,cut),0));
        for(int offset:new int[]{0,8,12,16,20}) {
            byte[] invalid=valid.clone(); ByteBuffer.wrap(invalid).putInt(offset,-1);
            assertThrows(IOException.class,()->read(invalid,0));
        }
    }
    @Test void skipsSnappedRecordsAndNonEventPackets() throws Exception {
        byte[] bytes=BleFrames.snoop(1002,0,BleFrames.legacy(BleFrames.data()),BleFrames.legacy(BleFrames.data()));
        ByteBuffer.wrap(bytes).putInt(16,1000); // Original length exceeds captured length.
        assertEquals(1,read(bytes,0).size());
        bytes=BleFrames.snoop(1002,0,BleFrames.legacy(BleFrames.data()));
        bytes[40]=1; // H4 command packet, not an event.
        assertTrue(read(bytes,0).isEmpty());
    }

    @Test void decodesCheckedInBtsnoopAndKeepsMalformedAdWarnings() throws Exception {
        var ads=new ArrayList<BleAdvertisement>();
        try(var input=getClass().getResourceAsStream("/ble/advertisements.btsnoop")) {
            assertNotNull(input);
            BleCaptureReader.read(input,0,ads::add);
        }
        assertEquals(4,ads.size());
        assertEquals("Lab Tag",ads.getFirst().payload().localName());
        assertEquals("Lab Sensor",ads.get(1).payload().localName());
        assertEquals("hex:fffe",ads.get(2).payload().localName());
        assertEquals(List.of("Truncated AD structure"),ads.getLast().payload().warnings());
    }
}
