package ewave.passive;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class OuiLookupTest {
    @Test void readsManufFullNamesAndNormalizesThreeOctetPrefixes() {
        var lookup = new OuiLookup(new ByteArrayInputStream(("# comment\n"
                + "A4:C3:F0  Apple_Inc  Apple, Inc.\n"
                + "00:11:22\tCIMSYS\tCIMSYS Inc\n"
                + "38:8C:EF\tSamsung\n"
                + "00:11:22:30/28\tOther\tMore specific allocation\n"
                + "00:11:22:33:40/36\tSmall\tSmall allocation\n"
                + "02:11:22\tLocal\tMust not resolve\n"
                + "malformed\n").getBytes(StandardCharsets.UTF_8)));
        assertEquals("Apple, Inc.", lookup.lookup("a4:c3:f0:01:02:03"));
        assertEquals("Apple, Inc.", lookup.lookup("A4:C3:F0"));
        assertEquals("Small allocation", lookup.lookup("00:11:22:33:44:55"));
        assertEquals("More specific allocation", lookup.lookup("00:11:22:33:54:55"));
        assertEquals("CIMSYS Inc", lookup.lookup("00:11:22:20:44:55"));
        assertEquals("Unknown", lookup.lookup("02:11:22:33:44:55"));
        assertEquals("Samsung", lookup.lookup("38:8c:ef:33:44:55"));
        for (String invalid : new String[]{"", "bad", "A4:C3", "GG:C3:F0", "A4::F0", "FF:FF:FF:FF:FF:FF"})
            assertEquals("Unknown", lookup.lookup(invalid));
        assertEquals("Unknown", lookup.lookup(null));
        assertEquals("Unknown", new OuiLookup(null).lookup("00:11:22:33:44:55"));
    }

    @Test void classpathTablesAreAvailableOfflineAndPreferSpecificRegistrations() {
        var lookup = new OuiLookup();
        assertEquals("Fixture Manufacturer", lookup.lookup("A4:C3:F0:01:02:03"));
        assertEquals("Fixture Specific Allocation", lookup.lookup("00:11:22:33:44:55"));
    }
}
