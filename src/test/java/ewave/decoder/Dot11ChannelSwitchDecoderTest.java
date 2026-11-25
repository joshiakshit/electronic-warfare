package ewave.decoder;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;

import static ewave.decoder.Dot11ChannelSwitchDecoder.*;
import static org.junit.jupiter.api.Assertions.*;

class Dot11ChannelSwitchDecoderTest {
    @Test void prefersExtendedAnnouncementsAndResolvesOverlappingChannelsByBand() {
        var basic = ie(37, "000501");
        assertEquals(new ChannelSwitch(0, 5, 2432, 1), decodeChannelSwitch(ies(basic), 2412));
        assertEquals(5975, decodeChannelSwitch(ies(basic), 5955).frequencyMhz());
        assertEquals(new ChannelSwitch(1, 5, 5975, 3),
                decodeChannelSwitch(ies(basic, ie(60, "01830503")), 2412));
        assertEquals(5260, decodeChannelSwitch(ies(ie(60, "00763400")), 2412).frequencyMhz());
        assertEquals(2484, decodeChannelSwitch(ies(ie(60, "00520e00")), 5180).frequencyMhz());
        assertEquals(5935, decodeChannelSwitch(ies(ie(60, "00880200")), 5180).frequencyMhz());
        assertEquals(2432, decodeChannelSwitch(ies(ie(60, "00000501"), basic), 2412).frequencyMhz());
        assertNull(decodeChannelSwitch(ies(ie(37, "0025")), 5180));
        assertNull(decodeChannelSwitch(ies(basic), 0));
    }

    @Test void readsMultipleTbttEntriesAndSkipsUnknownAndTruncatedBlocks() {
        var neighbors = decodeReducedNeighborReport(ies(
                ie(201, "01018305001006830500785634124200ddccbbaa0000108365"),
                ie(201, "0010832500021122334455efcdab89420000f3000007834500021122334466")));
        assertEquals(4, neighbors.size());
        assertEquals(new Neighbor(131, 5, 5975, null, 0x12345678, true, true, null, null), neighbors.get(0));
        assertEquals(0xaabbccdd, neighbors.get(1).shortSsid());
        assertEquals(new Neighbor(131, 37, 6135, "02:11:22:33:44:55", 0x89abcdef,
                true, true, 0, 3), neighbors.get(2));
        assertEquals("02:11:22:33:44:66", neighbors.get(3).bssid());
        assertNull(neighbors.get(3).shortSsid());
        assertEquals(0xcbf43926, shortSsidCrc32("123456789".getBytes(StandardCharsets.US_ASCII)));
    }

    @Test void readsShortBssParameterLayouts() {
        var neighbors = decodeReducedNeighborReport(ies(ie(201,
                "000883050002112233445542000283050002")));
        assertEquals(2, neighbors.size());
        assertTrue(neighbors.get(0).coLocated());
        assertTrue(neighbors.get(0).sameSsid());
        assertTrue(neighbors.get(1).sameSsid());
        assertFalse(neighbors.get(1).coLocated());
    }

    @Test void extractsBasicMultiLinkCommonInfoAndRejectsInvalidLengths() {
        assertEquals(new BasicMultiLink("02:11:22:33:44:55", 7),
                decodeBasicMultiLink(ies(ie(255, "6b100008021122334455f7"))));
        assertEquals(new BasicMultiLink("02:11:22:33:44:55", null),
                decodeBasicMultiLink(ies(ie(255, "6b000007021122334455"))));
        for (String malformed : List.of("6b010007021122334455", "6b100007021122334455",
                "6b100008021122334455", "6b000006021122334455", "6c10000802112233445501")) {
            assertNull(decodeBasicMultiLink(ies(ie(255, malformed))), malformed);
        }
    }

    private static Dot11InformationElements ies(Dot11InformationElements.Element... elements) {
        return new Dot11InformationElements(List.of(elements));
    }

    private static Dot11InformationElements.Element ie(int id, String hex) {
        return new Dot11InformationElements.Element(id, HexFormat.of().parseHex(hex));
    }
}
