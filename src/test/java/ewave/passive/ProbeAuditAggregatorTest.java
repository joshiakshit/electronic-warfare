package ewave.passive;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ProbeAuditAggregatorTest {
    @Test void wildcardOverflowEvictsTheMatchingDirectedNamesAndCorpus() throws Exception {
        var audit = new ProbeAuditAggregator(new SessionIdentifiers());
        observe(audit, 1_000, "directed", "Lab name");
        for (int i = 0; i < 65_536; i++) observe(audit, 1_001 + i, "wildcard", "");
        var report = audit.prepareSnapshot(70_000, 1_000_000, 0).build();
        assertEquals(65_536, report.totalProbes());
        assertEquals(0, report.directedProbes());
        assertEquals(0, report.distinctDirectedSsids());
        assertTrue(report.corpus().isEmpty());
        assertTrue(report.ssidTokens().values().stream().allMatch(List::isEmpty));
        assertTrue(report.sampleLimitReached());
    }

    @Test void classifiesRegionalDefaultsAndEnterpriseNamesAndCountsDistinctNetworksPerAddress() throws Exception {
        String previous = System.setProperty("audit.corporateSsids", "Example Custom, JioFiber-Office");
        try {
            var audit = new ProbeAuditAggregator(new SessionIdentifiers());
            var cases = Map.of(
                    "PERSONAL_NAME_PATTERN", List.of("Riya’s iPhone 15", "Galaxy S24", "Redmi Note", "POCO X3",
                            "OnePlus 12", "Pixel_8", "Nothing Phone (2)", "AndroidAP", "vivo V20",
                            "OPPO A9", "realme_10", "Moto G"),
                    "ROUTER_DEFAULT_PATTERN", List.of("NETGEAR42", "TP-Link_123a", "Linksys123", "Linksys", "JioFiber Home",
                            "Airtel_91", "ACTFiber-1", "ACT_2", "BSNL-3", "Tenda_42", "ASUS_5", "D-Link-6", "DIR-7",
                            "Mercusys_8", "Xiaomi_9", "MiFibra_10", "Huawei11", "HG812", "ZTE_13", "Nokia-14"),
                    "CORPORATE", List.of("eduroam", "OpenRoaming", "Example-Corp", "Example-Enterprise", "Example-Staff",
                            "Example-Faculty", "Example-Campus", "Example Custom", "JioFiber-Office"),
                    "OTHER", List.of("Lab Unclassified"));
            for (var group : cases.values()) {
                for (String name : group) observe(audit, 1_000, name, name);
            }
            observe(audit, 1_100, "Galaxy S24", "Galaxy S24");
            observe(audit, 1_200, "Galaxy S24", "Galaxy S24");
            var report = audit.prepareSnapshot(1_200, 1_000_000, 0).build();
            cases.forEach((exposure, names) -> {
                assertEquals(names.stream().sorted().toList(), report.ssidTokens().get(exposure), exposure);
                assertEquals((long) names.size(), report.ssidExposureCounts().get(exposure), exposure);
            });
            assertEquals(report.totalObservedAddresses(), report.directedPerAddress().get("1"));
            assertEquals(report.totalObservedAddresses() + 2, report.directedProbes());
        } finally {
            if (previous == null) System.clearProperty("audit.corporateSsids");
            else System.setProperty("audit.corporateSsids", previous);
        }
    }

    private static void observe(ProbeAuditAggregator audit, long time, String sender, String ssid) {
        audit.observe(time, sender, true, "sig", null, ssid.getBytes(StandardCharsets.UTF_8),
                List.of(), List.of(), false, null);
    }
}
