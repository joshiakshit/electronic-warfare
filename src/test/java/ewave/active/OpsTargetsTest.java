package ewave.active;

import ewave.passive.PassiveWifiSession;
import ewave.passive.TopologyBuilder;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class OpsTargetsTest {
    private static final String AP = "02:11:22:33:44:55";
    private static final String AP_TOKEN = "wifi:ap-token";
    private static final String CLIENT = "02:aa:bb:cc:dd:01";
    private static final UUID SESSION = UUID.randomUUID();

    @Test void resolvesALiveTargetWithoutAnyCache() {
        var resolved = OpsTargets.resolve("target-1", null, null, null,
                List.of(target("target-1", CLIENT, AP_TOKEN, AP, 36, 5180)),
                List.of(), token -> null, List.of(), true);

        assertEquals("target-1", resolved.targetId());
        assertEquals(AP_TOKEN, resolved.apId());
        assertEquals(AP, resolved.apBssid());
        assertEquals(CLIENT, resolved.clientMac());
        assertEquals(36, resolved.channel());
        assertEquals(5180, resolved.frequencyMhz());
    }

    @Test void resolvesAnObservedApTokenAndRejectsAnUnevidencedClient() {
        var ap = accessPoint(AP_TOKEN, "Lab", 6);
        var lookup = (java.util.function.Function<String, String>) token -> AP_TOKEN.equals(token) ? AP : null;

        var resolved = OpsTargets.resolve(null, AP_TOKEN, null, CLIENT,
                List.of(target("target-1", CLIENT, AP_TOKEN, AP, 6, 2437)), List.of(ap), lookup, List.of(), true);
        assertEquals(AP, resolved.apBssid());
        assertEquals(CLIENT, resolved.clientMac());

        assertThrows(IllegalArgumentException.class, () -> OpsTargets.resolve(
                null, AP_TOKEN, null, "02:aa:bb:cc:dd:99",
                List.of(target("target-1", CLIENT, AP_TOKEN, AP, 6, 2437)), List.of(ap), lookup, List.of(), true));
    }

    @Test void resolvesACachedApForDirectLabCalls() {
        var cached = new WifiAccessPoints.AccessPoint("Lab AP", AP, 11, 2462);
        var resolved = OpsTargets.resolve(null, null, AP, null, List.of(), List.of(), token -> null,
                List.of(cached), false);
        assertEquals(AP, resolved.apBssid());
        assertNull(resolved.clientMac());
        assertEquals(11, resolved.channel());
        assertEquals(2462, resolved.frequencyMhz());
    }

    @Test void requiresASelectorAndAClientWhenRequested() {
        assertThrows(IllegalArgumentException.class, () -> OpsTargets.resolve(
                null, null, null, null, List.of(), List.of(), token -> null, List.of(), false));
        assertThrows(IllegalArgumentException.class, () -> OpsTargets.resolve(
                null, AP_TOKEN, null, null, List.of(), List.of(accessPoint(AP_TOKEN, "Lab", 6)),
                token -> AP, List.of(), true));
    }

    @Test void rejectsAStaleTarget() {
        assertThrows(IllegalArgumentException.class, () -> OpsTargets.resolve(
                "gone", null, null, null, List.of(), List.of(), token -> null, List.of(), false));
    }

    private static PassiveWifiSession.EvidencedTarget target(String id, String client, String apId, String apBssid,
                                                             int channel, int frequencyMhz) {
        return new PassiveWifiSession.EvidencedTarget(id, client, "Client", "Lab vendor", "Client · Lab vendor",
                -55, apId, apBssid, "Lab", channel, frequencyMhz, "ASSOCIATION", 1_000L, SESSION);
    }

    private static TopologyBuilder.AccessPoint accessPoint(String token, String ssid, int channel) {
        return new TopologyBuilder.AccessPoint(token, ssid, "ssid-token", false, null, channel,
                "2.4", "WPA2", 100, null, 2, 10, null, null, null, null, -60.0, "2.4", 1_000L,
                List.of(), List.of(), null);
    }
}
