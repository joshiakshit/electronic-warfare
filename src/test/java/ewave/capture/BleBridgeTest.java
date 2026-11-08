package ewave.capture;

import ewave.fixtures.BleFrames;
import ewave.fixtures.StreamingCaptureProcess;
import ewave.model.EwaveEvent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(15)
class BleBridgeTest {
    @Test void ownsPassiveCaptureProcessPublishesImmutableEventsAndRemovesExtractedHelper() throws Exception {
        var process=new StreamingCaptureProcess();
        var events=new LinkedBlockingQueue<EwaveEvent>();
        var helper=new AtomicReference<Path>();
        try(var bridge=new BleBridge(events,builder->{
            assertEquals(List.of("python3","-I","-u"),builder.command().subList(0,3));
            assertEquals(List.of("--index","2"),builder.command().subList(4,6));
            assertFalse(builder.redirectErrorStream());
            helper.set(Path.of(builder.command().get(3)));
            assertTrue(Files.isRegularFile(helper.get()));
            return process;
        })) {
            assertThrows(IllegalArgumentException.class,()->bridge.start(-1));
            bridge.start(2);
            assertThrows(IllegalStateException.class,()->bridge.start(2));
            process.write(BleFrames.snoop(1002,2,BleFrames.legacy(BleFrames.data())));
            var updated=events.poll(3,TimeUnit.SECONDS);
            assertNotNull(updated);
            assertEquals(EwaveEvent.BLE_DEVICE_UPDATED,updated.type());
            assertEquals(EwaveEvent.BLE_ADVERTISEMENT,events.poll(3,TimeUnit.SECONDS).type());
            var device=bridge.getDevices().values().iterator().next();
            assertEquals("Lab Tag",device.lastAdvertisedName());
            assertEquals(1,device.advertisementCount());
            assertEquals(1L,bridge.getStatus().get("advertisements"));
            var snapshot=bridge.getAdvertisements();
            assertThrows(UnsupportedOperationException.class,snapshot::clear);
            bridge.stop();
            assertEquals(1,snapshot.size());
            assertEquals(1,bridge.getDevices().size());
            assertFalse(Files.exists(helper.get()));
            assertFalse(bridge.getStatus().containsKey("captureError"));
        }
    }

    @Test void boundsAddressesAndReportsAndPublishesDeviceEviction() throws Exception {
        var process=new StreamingCaptureProcess();
        var events=new LinkedBlockingQueue<EwaveEvent>();
        try(var bridge=new BleBridge(events,builder->process)) {
            bridge.start(0);
            byte[][] packets=new byte[520][];
            for(int i=0;i<packets.length;i++) packets[i]=BleFrames.legacy(BleFrames.data(),1,
                    new byte[]{(byte)i,(byte)(i>>8),0x22,0x33,0x11,(byte)0xc2});
            process.write(BleFrames.snoop(1002,0,packets));
            await(()->bridge.getStatus().get("advertisements").equals(520L));
            assertEquals(BleBridge.RECENT_LIMIT,bridge.getAdvertisements().size());
            assertEquals(BleBridge.DEVICE_LIMIT,bridge.getDevices().size());
            assertEquals(8L,bridge.getStatus().get("evictedDevices"));
            assertEquals(8,events.stream().filter(event->event.type().equals(EwaveEvent.BLE_DEVICE_REMOVED)).count());
        }
    }

    @Test void surfacesPermissionsAndCanRestartWhilePreservingHistory() throws Exception {
        var failure=new StreamingCaptureProcess("BLE capture failed: Operation not permitted; use sudo",1);
        failure.finish();
        var success=new StreamingCaptureProcess();
        var restarted=new StreamingCaptureProcess();
        var processes=new ArrayDeque<>(List.of(failure,success,restarted));
        try(var bridge=new BleBridge(new LinkedBlockingQueue<>(),builder->processes.remove())) {
            bridge.start(0);
            await(()->!bridge.getStatus().get("captureRunning").equals(true));
            assertTrue(bridge.getStatus().get("captureError").toString().contains("Operation not permitted"));
            bridge.start(0);
            assertFalse(bridge.getStatus().containsKey("captureError"));
            success.write(BleFrames.snoop(1002,0,BleFrames.legacy(BleFrames.data())));
            await(()->bridge.getAdvertisements().size()==1);
            bridge.stop();
            bridge.start(0);
            restarted.write(BleFrames.snoop(1002,0,BleFrames.legacy(BleFrames.data())));
            await(()->bridge.getAdvertisements().size()==2);
            assertEquals(2,bridge.getDevices().values().iterator().next().advertisementCount());
        }
    }

    private static void await(BooleanSupplier condition) throws InterruptedException {
        long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);
        while(!condition.getAsBoolean() && System.nanoTime()<deadline) Thread.sleep(5);
        assertTrue(condition.getAsBoolean());
    }
}
