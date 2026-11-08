package ewave.active;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class WifiAccessPointsTest {
    @TempDir Path temporary;
    @Test void readsEscapedSsidsRadioIdentifiersAndFrequenciesAndDeduplicates() throws Exception {
        Path cache = temporary.resolve("wifi-aps.txt");
        Files.write(cache, List.of(
                "Lab\\:guest\\\\room:78\\:bb\\:c1\\:4b\\:ce\\:81:2:2417 MHz",
                "Lab 5 GHz:78\\:BB\\:C1\\:4B\\:CE\\:82:149:5745 MHz",
                ":78\\:BB\\:C1\\:4B\\:CE\\:83:5:5975 MHz",
                "Duplicate:78\\:BB\\:C1\\:4B\\:CE\\:81:2:2417 MHz",
                "Incomplete:78\\:BB\\:C1\\:4B\\:CE\\:84:--:--", "bad record"));
        var points = new WifiAccessPoints(cache).all();
        assertEquals(List.of(new WifiAccessPoints.AccessPoint("Lab:guest\\room", "78:BB:C1:4B:CE:81", 2, 2417),
                new WifiAccessPoints.AccessPoint("Lab 5 GHz", "78:BB:C1:4B:CE:82", 149, 5745),
                new WifiAccessPoints.AccessPoint("", "78:BB:C1:4B:CE:83", 5, 5975)), points);
    }
    @Test void reportsMissingCacheAndIgnoresInvalidRadioRecords() {
        assertThrows(NoSuchFileException.class, () -> new WifiAccessPoints(temporary.resolve("missing")).all());
        assertTrue(WifiAccessPoints.parse(List.of("Bad:aa\\:bb\\:cc\\:dd\\:ee\\:ff:234:2417 MHz",
                "Bad:aa\\:bb\\:cc\\:dd\\:ee\\:ff:2:1 MHz", "Bad:invalid:2:2417 MHz")).isEmpty());
    }

    @Test void defaultsMissingZeroAndNegativeCacheChannelsToSix() {
        for (String channel : List.of("0", "-1", "", "--", "null")) {
            var points = WifiAccessPoints.parse(List.of("Lab:aa\\:bb\\:cc\\:dd\\:ee\\:ff:" + channel + ":2437 MHz"));
            assertEquals(1, points.size(), channel);
            assertEquals(6, points.getFirst().channel(), channel);
        }
        assertEquals(6, new WifiAccessPoints.AccessPoint("Lab", "AA:BB:CC:DD:EE:FF", -1, 2437).channel());
    }
}
