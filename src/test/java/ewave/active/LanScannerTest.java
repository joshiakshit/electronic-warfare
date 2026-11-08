package ewave.active;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class LanScannerTest {
    @TempDir Path temporary;
    private static final String HEADER = "Interface: wlo1, type: EN10MB, MAC: aa:bb:cc:dd:ee:ff, IPv4: 192.168.29.136";

    @Test void parsesCachedRowsStripsVendorParenthesesAndSkipsHeadersAndOwnAddresses() {
        var devices = LanScanner.parse(List.of(HEADER,
                "Starting arp-scan with 256 hosts",
                "192.168.29.1\t78:bb:c1:4b:ce:80\t(Unknown)",
                "  192.168.29.94\t46:f9:b7:de:09:48\t(Unknown: locally administered)  ",
                "192.168.29.136 aa:bb:cc:dd:ee:ff (This laptop before monitor mode)",
                "192.168.29.20 AA:BB:CC:DD:EE:FF (This laptop on another interface)",
                "192.168.29.21 00:11:22:33:44:55 Vendor Company (Research)",
                "192.168.29.22 00:11:22:33:44:66\t",
                "#192.168.29.23 00:11:22:33:44:77 (Comment)",
                "Ending arp-scan", "malformed row", ""), Set.of("192.168.29.20"));
        assertEquals(List.of(new LanScanner.Device("192.168.29.1", "78:bb:c1:4b:ce:80", "Unknown"),
                new LanScanner.Device("192.168.29.94", "46:f9:b7:de:09:48", "Unknown: locally administered"),
                new LanScanner.Device("192.168.29.21", "00:11:22:33:44:55", "Vendor Company (Research)"),
                new LanScanner.Device("192.168.29.22", "00:11:22:33:44:66", "")), devices);
        assertEquals(List.of(), LanScanner.parse(List.of(HEADER), Set.of()));
        assertEquals(List.of(), LanScanner.parse(List.of(), Set.of()));
    }

    @Test void readsTheCacheOnEveryRequestAndRetainsPreMonitorLocalAddressFiltering() throws IOException {
        Path cache = temporary.resolve("ewave-lan-hosts.txt");
        Files.write(cache, List.of(HEADER,
                "192.168.29.94\t46:f9:b7:de:09:48\t(Unknown: locally administered)",
                "192.168.29.136 aa:bb:cc:dd:ee:ff (This laptop)"));
        var scanner = new LanScanner(cache);
        assertEquals(List.of(new LanScanner.Device("192.168.29.94", "46:f9:b7:de:09:48", "Unknown: locally administered")), scanner.scan());
        Files.write(cache, List.of(HEADER));
        assertTrue(scanner.scan().isEmpty());
    }

    @Test void reportsMissingCacheAsNoSuchFileException() {
        var scanner = new LanScanner(temporary.resolve("missing-cache"));
        assertThrows(NoSuchFileException.class, scanner::scan);
    }
}
