package ewave.capture;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RadioStatusTest {
    static final String PHY_INFO = """
            Wiphy phy8
                Band 1:
                    Frequencies:
                        * 2412 MHz [1] (20.0 dBm)
                        * 2484 MHz [14] (disabled, no IR)
                Band 2:
                    Frequencies:
                        * 5260 MHz [52] (23.0 dBm) (no IR, radar detection)
                        * 5500 MHz [100] (disabled)
                Band 4:
                    Frequencies:
                        * 5955.0 MHz [1] (20.0 dBm) (passive scanning)
                        * 5975 MHz [5] (disabled)
                Band 5:
                    Frequencies:
                        * 58320 MHz [1] (25.0 dBm)
            """;

    @Test void usesResolvedPhysicalRadioAndKeepsOverlappingChannelNumbersDistinct() {
        var channels = RadioStatus.readChannels("lab0mon", iface -> {
            assertEquals("lab0mon", iface);
            return "phy8";
        }, command -> {
            assertEquals(List.of("iw", "phy", "phy8", "info"), command);
            return PHY_INFO;
        }).orElseThrow();
        assertEquals(List.of(new RadioStatus.Channel(1, 2412, false, false),
                new RadioStatus.Channel(52, 5260, true, true),
                new RadioStatus.Channel(1, 5955, true, false)), channels);
    }

    @Test void distinguishesAnUnavailableQueryFromAPlanWithEveryChannelDisabled() {
        assertTrue(RadioStatus.readChannels("lab0mon", iface -> "phy8", command -> null).isEmpty());
        assertTrue(RadioStatus.parseChannels("Wiphy phy8\nmissing frequencies").isEmpty());
        assertEquals(List.of(), RadioStatus.parseChannels("* 2412 MHz [1] (disabled)\n").orElseThrow());
    }
}
