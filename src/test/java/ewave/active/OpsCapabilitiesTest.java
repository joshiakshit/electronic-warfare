package ewave.active;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class OpsCapabilitiesTest {
    @TempDir Path directory;

    @Test void reportsToolsCachesAndPerOperationReadiness() throws Exception {
        Path aps = Files.writeString(directory.resolve("aps.txt"), "Lab AP:02\\:11\\:22\\:33\\:44\\:55:6:2437 MHz\n");
        Path lan = Files.writeString(directory.resolve("lan.txt"), String.join("\n",
                "Interface: wlo1, type: EN10MB, MAC: aa:bb:cc:dd:ee:ff, IPv4: 192.168.1.5",
                "192.168.1.20 02:aa:bb:cc:dd:01 (Lab device)", ""));
        Path wordlist = Files.writeString(directory.resolve("words.txt"), "lab password\n");
        Set<String> present = Set.of("sudo", "iw", "aireplay-ng", "tcpdump", "tshark", "aircrack-ng",
                "mdk3", "hostapd", "dnsmasq", "python3");
        OpsCapabilities.ToolLocator locator = name ->
                present.contains(name) ? Path.of("/usr/bin", name) : null;

        Map<String, Object> report = OpsCapabilities.snapshot(aps, lan, wordlist.toString(),
                List.of("wlo1"), List.of(new OpsCapabilities.Interface("wlo1", true, false, false)),
                Map.of("status", Map.of("captureMode", "watch")), "deauth", locator);

        assertEquals(true, report.get("operationsEnabled"));
        assertEquals("deauth", report.get("activeOperation"));
        var caches = (Map<?, ?>) report.get("caches");
        var apCache = (OpsCapabilities.Cache) caches.get("accessPoints");
        var lanCache = (OpsCapabilities.Cache) caches.get("lanHosts");
        assertTrue(apCache.available());
        assertEquals(1, apCache.entries());
        assertTrue(lanCache.available());
        assertEquals(1, lanCache.entries());

        @SuppressWarnings("unchecked")
        var operations = (List<OpsCapabilities.Operation>) report.get("operations");
        assertTrue(operation(operations, "deauth").ready());
        assertTrue(operation(operations, "handshake").ready());
        assertTrue(operation(operations, "beacon").ready());
        assertTrue(operation(operations, "evil-twin").ready());
        var pmkid = operation(operations, "pmkid");
        assertFalse(pmkid.ready());
        assertTrue(pmkid.missing().contains("hcxdumptool"));
        assertTrue(pmkid.missing().contains("hcxpcapngtool"));

        var wordlistView = (Map<?, ?>) report.get("wordlist");
        assertEquals(wordlist.toString(), wordlistView.get("path"));
        assertEquals(true, wordlistView.get("available"));
    }

    @Test void reportsMissingToolsAndCaches() {
        Map<String, Object> report = OpsCapabilities.snapshot(directory.resolve("missing-aps"),
                directory.resolve("missing-lan"), null, List.of(), List.of(), Map.of(), null, name -> null);
        var caches = (Map<?, ?>) report.get("caches");
        assertFalse(((OpsCapabilities.Cache) caches.get("accessPoints")).available());
        assertFalse(((OpsCapabilities.Cache) caches.get("lanHosts")).available());
        @SuppressWarnings("unchecked")
        var operations = (List<OpsCapabilities.Operation>) report.get("operations");
        assertTrue(operations.stream().noneMatch(OpsCapabilities.Operation::ready));
        assertNull(report.get("activeOperation"));
    }

    private static OpsCapabilities.Operation operation(List<OpsCapabilities.Operation> operations, String id) {
        return operations.stream().filter(operation -> operation.id().equals(id)).findFirst().orElseThrow();
    }
}
