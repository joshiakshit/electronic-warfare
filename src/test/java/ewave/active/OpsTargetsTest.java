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
        var lookup = (java.util.function.Function<String, PassiveWifiSession.ObservedApDetails>) token -> AP_TOKEN.equals(token) ? details(6, 2437) : null;

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
                token -> details(6, 2437), List.of(), true));
    }

    @Test void rejectsAStaleTarget() {
        assertThrows(IllegalArgumentException.class, () -> OpsTargets.resolve(
                "gone", null, null, null, List.of(), List.of(), token -> null, List.of(), false));
    }

    @Test void resolvesSixGhzFromMeasuredDetailsAndPrefersLiveEvidenceOverCachedChannels() {
        var ap = accessPoint(AP_TOKEN, "6 GHz lab", 1);
        for (boolean raw : new boolean[]{false, true}) {
            var resolved = OpsTargets.resolve(null, raw ? null : AP_TOKEN, raw ? AP : null, null,
                    List.of(), List.of(ap), token -> details(1, 5955),
                    List.of(new WifiAccessPoints.AccessPoint("Old cache", AP, 6, 2437)), false);
            assertEquals(5955, resolved.frequencyMhz());
            assertEquals(1, resolved.channel());
        }
    }

    @Test void rejectsExpiredApDetailsAndUnknownFrequenciesRatherThanInventingChannelSix() {
        var ap = accessPoint(AP_TOKEN, "Lab", 0);
        assertThrows(IllegalArgumentException.class, () -> OpsTargets.resolve(null, AP_TOKEN, null, null,
                List.of(), List.of(ap), token -> null, List.of(), false));
        assertThrows(IllegalArgumentException.class, () -> OpsTargets.resolve(null, AP_TOKEN, null, null,
                List.of(), List.of(ap), token -> details(0, 0), List.of(), false));
        var lookups = new java.util.concurrent.atomic.AtomicInteger();
        assertThrows(IllegalArgumentException.class, () -> OpsTargets.resolve(null, null, AP, null,
                List.of(), List.of(ap), token -> lookups.getAndIncrement() == 0 ? details(1, 5955) : null,
                List.of(), false));
        for (int channel : new int[]{-1, 0, 15, 31, 178, 233})
            assertThrows(IllegalArgumentException.class, () -> HandshakeAnalyzer.frequencyMhz(channel));
    }

    private static PassiveWifiSession.ObservedApDetails details(int channel, int frequency) {
        return new PassiveWifiSession.ObservedApDetails(AP_TOKEN, AP, null, "Lab", channel, frequency, 100, -50.0, 1000);
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
