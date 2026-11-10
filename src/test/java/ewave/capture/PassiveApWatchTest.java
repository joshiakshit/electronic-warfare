package ewave.capture;

import ewave.decoder.Dot11Frame;
import ewave.decoder.Dot11InformationElements;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class PassiveApWatchTest {
    private static final String LAB = "00:11:22:33:44:55";

    @Test void recordsTheFirstNewChannelFrameAndTheTuneInItsObservationGap() {
        var watch = new PassiveApWatch("lab-token", LAB, true, 1000);
        watch.observe(beacon(LAB, 6, 6, 999));
        assertNull(watch.snapshot().lastHeard());

        watch.observe(beacon(LAB, 6, 6, 1100));
        watch.tuneConfirmed(1, 1200);
        watch.observe(beacon(LAB, 6, 1, 1300));
        watch.observe(beacon("00:aa:bb:cc:dd:ee", 1, 1, 1400));
        assertTrue(watch.active());

        watch.observe(beacon(LAB, 6, 6, 1500));
        watch.tuneConfirmed(1, 1600);
        watch.tuneConfirmed(1, 1700);
        watch.observe(beacon(LAB, 1, 1, 1800));
        watch.observe(beacon(LAB, 1, 1, 1900));

        var run = watch.snapshot();
        assertFalse(watch.active());
        assertEquals(new PacketBridge.ApWatchEvent(6, 1500), run.lastHeard());
        assertEquals(new PacketBridge.ApWatchEvent(1, 1600), run.tuned());
        assertEquals(new PacketBridge.ApWatchEvent(1, 1800), run.heardAgain());
        assertEquals(1800L, run.endedAt());
    }

    @Test void stoppingAFixedWatchKeepsTheLastFrameWithoutInventingAMove() {
        var watch = new PassiveApWatch("lab-token", LAB, false, 1000);
        watch.observe(beacon(LAB, 6, 6, 1200));
        watch.stop(1800);
        watch.observe(beacon(LAB, 1, 1, 2000));
        var run = watch.snapshot();
        assertFalse(run.adaptive());
        assertEquals(1800L, run.endedAt());
        assertEquals(new PacketBridge.ApWatchEvent(6, 1200), run.lastHeard());
        assertNull(run.tuned());
        assertNull(run.heardAgain());
    }

    private static Dot11Frame beacon(String bssid, int advertised, int received, long at) {
        var ds = new Dot11InformationElements.Element(3, new byte[]{(byte) advertised});
        return new Dot11Frame(0, 8, 0, 0, -1, "ff:ff:ff:ff:ff:ff", bssid, bssid, null,
                at, 2407 + received * 5, -35, null, 40, new Dot11InformationElements(List.of(ds)),
                0L, 100, 1, null, 0, 0);
    }
}
