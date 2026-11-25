package ewave.active;

import ewave.passive.PassiveWifiSession;
import ewave.passive.TopologyBuilder;

import java.util.List;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * Resolves an Ops request target from live passive evidence, an observed AP token, a real BSSID,
 * or the optional pre-monitor AP cache. Live evidence wins where both exist.
 */
public final class OpsTargets {
    private static final Pattern MAC = Pattern.compile("(?i)(?:[0-9a-f]{2}:){5}[0-9a-f]{2}");

    public record Resolved(String targetId, String apId, String apBssid, String clientMac, String ssid,
                           int channel, int frequencyMhz) { }

    private OpsTargets() { }

    public static Resolved resolve(String targetId, String apId, String apBssid, String clientMac,
                                   List<PassiveWifiSession.EvidencedTarget> targets,
                                   List<TopologyBuilder.AccessPoint> accessPoints,
                                   Function<String, PassiveWifiSession.ObservedApDetails> observedAp,
                                   List<WifiAccessPoints.AccessPoint> cachedAccessPoints,
                                   boolean clientRequired) {
        String wantedTarget = text(targetId);
        String wantedAp = text(apId);
        String wantedBssid = text(apBssid);
        String wantedClient = text(clientMac);
        List<PassiveWifiSession.EvidencedTarget> evidence = targets == null ? List.of() : targets;
        List<TopologyBuilder.AccessPoint> observed = accessPoints == null ? List.of() : accessPoints;
        List<WifiAccessPoints.AccessPoint> cached = cachedAccessPoints == null ? List.of() : cachedAccessPoints;
        Function<String, PassiveWifiSession.ObservedApDetails> lookup = observedAp == null ? ignored -> null : observedAp;

        if (wantedTarget != null) {
            var match = evidence.stream().filter(target -> wantedTarget.equals(target.id())).findFirst()
                    .orElseThrow(() -> new IllegalArgumentException(
                            "Target is no longer observed. Refresh the target list."));
            if (wantedClient != null && !wantedClient.equalsIgnoreCase(match.mac()))
                throw new IllegalArgumentException("clientMac does not match the selected target");
            return finish(wantedTarget, match.apId(), match.apBssid(), match.mac(), match.apSsid(),
                    match.channel(), match.frequencyMhz(), clientRequired);
        }

        if (wantedAp != null) {
            TopologyBuilder.AccessPoint ap = observed.stream()
                    .filter(candidate -> wantedAp.equals(candidate.bssid()))
                    .findFirst()
                    .orElseGet(() -> observed.stream().filter(candidate -> {
                        var details = lookup.apply(candidate.bssid());
                        return details != null && details.bssid().equalsIgnoreCase(wantedAp);
                    }).findFirst().orElse(null));
            if (ap == null) throw new IllegalArgumentException("Access point is not in the current capture");
            var details = lookup.apply(ap.bssid());
            String real = details == null ? null : details.bssid();
            if (real == null) throw new IllegalArgumentException("Access point address is no longer available");
            requireEvidencedClient(evidence, real, wantedClient);
            return finish(null, ap.bssid(), real, wantedClient, ap.ssid(), details.channel(),
                    details.frequencyMhz(), clientRequired);
        }

        if (wantedBssid != null) {
            if (!MAC.matcher(wantedBssid).matches())
                throw new IllegalArgumentException("apBssid must be a MAC address, an apId token, or a targetId");
            var observedMatch = observed.stream().filter(candidate -> {
                var details = lookup.apply(candidate.bssid());
                return details != null && details.bssid().equalsIgnoreCase(wantedBssid);
            }).findFirst();
            if (observedMatch.isPresent()) {
                var ap = observedMatch.get();
                var details = lookup.apply(ap.bssid());
                if (details == null) throw new IllegalArgumentException("Access point has expired. Refresh the AP list.");
                requireEvidencedClient(evidence, wantedBssid, wantedClient);
                return finish(null, ap.bssid(), wantedBssid, wantedClient, ap.ssid(), details.channel(),
                        details.frequencyMhz(), clientRequired);
            }
            var cachedMatch = cached.stream().filter(candidate -> candidate.bssid().equalsIgnoreCase(wantedBssid))
                    .findFirst();
            if (cachedMatch.isPresent()) {
                var ap = cachedMatch.get();
                return finish(null, null, ap.bssid(), wantedClient, ap.ssid(), ap.channel(), ap.frequencyMhz(), clientRequired);
            }
            throw new IllegalArgumentException("Select a live target, an observed AP, or a cached AP");
        }

        throw new IllegalArgumentException("targetId, apId, or apBssid is required");
    }

    private static Resolved finish(String targetId, String apId, String apBssid, String clientMac, String ssid,
                                   int channel, int frequencyMhz, boolean clientRequired) {
        if (clientRequired && clientMac == null)
            throw new IllegalArgumentException("A client target is required for this operation");
        if (frequencyMhz <= 0) throw new IllegalArgumentException("AP frequency is unknown. Wait for a fresh advertisement.");
        int normalized = channel > 0 ? channel : ewave.decoder.Dot11FrameDecoder.channel(frequencyMhz);
        int resolvedFrequency = frequencyMhz;
        HandshakeAnalyzer.validateTarget(apBssid, clientMac, normalized);
        HandshakeAnalyzer.validateFrequency(resolvedFrequency);
        return new Resolved(targetId, apId, apBssid, clientMac, ssid, normalized, resolvedFrequency);
    }

    private static void requireEvidencedClient(List<PassiveWifiSession.EvidencedTarget> targets,
                                               String apBssid, String clientMac) {
        if (clientMac == null) return;
        boolean evidenced = targets.stream().anyMatch(target ->
                target.apBssid() != null && target.apBssid().equalsIgnoreCase(apBssid)
                        && target.mac().equalsIgnoreCase(clientMac));
        if (!evidenced)
            throw new IllegalArgumentException("clientMac is not an evidenced client of the selected AP");
    }

    private static String text(String value) {
        if (value == null) return null;
        String stripped = value.strip();
        return stripped.isEmpty() ? null : stripped;
    }
}
