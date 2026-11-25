package ewave.core;

import ewave.capture.PacketBridge;
import org.junit.jupiter.api.Test;
import java.util.ArrayList;
import static org.junit.jupiter.api.Assertions.*;

class PeriodFingerprinterTest {
    @Test void defaultCadenceCanFitBeaconAndHighFrequencyHintsWithoutManualFlags() {
        for (int period : new int[]{2, 5}) {
            var samples = new ArrayList<PeriodFit.Sample>();
            for (int tick = 0; tick < 400; tick++) samples.add(new PeriodFit.Sample(tick, tick % period == 0));
            int fitted = PeriodFit.fit(samples, 6, 100);
            assertEquals(period, fitted);
            String hint = PeriodFingerprinter.hint(fitted, fitted * PacketBridge.DEFAULT_TICK_MS);
            assertEquals(period == 5 ? "802.11 AP (beacon cycle)" : "Active client / high-frequency beacon", hint);
        }
    }

    @Test void classifiesQuantizedBeaconAndIotPeriods() {
        assertEquals("802.11 AP (beacon cycle)", PeriodFingerprinter.hint(6, 120));
        assertEquals("802.11 AP / IoT (300 TU cycle)", PeriodFingerprinter.hint(15, 300));
        assertEquals("802.11 AP / IoT (300 TU cycle)", PeriodFingerprinter.hint(16, 320));
        assertEquals("IoT / DTIM sleep cycle (1s)", PeriodFingerprinter.hint(51, 1020));
        assertEquals("IoT sensor / sleeping device", PeriodFingerprinter.hint(100, 2000));
        assertEquals("IoT sensor / sleeping device", PeriodFingerprinter.hint(200, 4000));
        assertEquals("Unclassified", PeriodFingerprinter.hint(99, 1980));
    }
}
