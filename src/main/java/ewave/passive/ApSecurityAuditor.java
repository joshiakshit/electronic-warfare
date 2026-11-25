package ewave.passive;

import ewave.passive.TopologyBuilder.AccessPoint;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Compares advertised AP security and operation within one passive snapshot. */
public final class ApSecurityAuditor {
    private ApSecurityAuditor() { }

    public record SecurityFinding(String code, String severity, String summary) { }
    private record SsidKey(String token, String label) { }
    private record ChannelColor(int frequency, int color) { }
    private record Posture(boolean open, boolean protectedNetwork, boolean enterprise, boolean psk,
                           boolean sae, boolean owe, boolean oweTransition) {
        static Posture of(AccessPoint ap) {
            var akms = ap.advertisedSecurity().stream().flatMap(profile -> profile.authentication().stream()).toList();
            return new Posture("Open".equals(ap.security()), "Privacy bit set".equals(ap.security())
                    || !ap.advertisedSecurity().isEmpty(),
                    akms.stream().anyMatch(akm -> akm.startsWith("802.1X") || akm.startsWith("FT/802.1X")),
                    akms.stream().anyMatch(akm -> akm.startsWith("PSK") || akm.startsWith("FT/PSK")),
                    akms.stream().anyMatch(akm -> akm.startsWith("SAE") || akm.startsWith("FT/SAE")),
                    akms.contains("OWE"), ap.securityModes().contains("OWE transition"));
        }

        boolean weakerThan(Posture peer) {
            if (open) return peer.enterprise || (peer.protectedNetwork && !oweTransition && !peer.oweTransition);
            return psk && !enterprise && peer.enterprise;
        }
    }

    public static Map<String, List<SecurityFinding>> audit(TopologyBuilder.Snapshot topology) {
        var networks = new LinkedHashMap<SsidKey, List<Posture>>();
        var colors = new LinkedHashMap<ChannelColor, List<AccessPoint>>();
        var postures = new LinkedHashMap<String, Posture>();
        for (AccessPoint ap : topology.accessPoints()) {
            Posture posture = Posture.of(ap);
            postures.put(ap.bssid(), posture);
            SsidKey ssid = visibleSsid(ap);
            if (ssid != null) networks.computeIfAbsent(ssid, key -> new ArrayList<>()).add(posture);
            ChannelColor color = channelColor(ap);
            if (color != null) colors.computeIfAbsent(color, key -> new ArrayList<>()).add(ap);
        }

        var results = new LinkedHashMap<String, List<SecurityFinding>>();
        for (AccessPoint ap : topology.accessPoints()) {
            Posture posture = postures.get(ap.bssid());
            var findings = new ArrayList<SecurityFinding>();
            SsidKey ssid = visibleSsid(ap);
            if (ssid != null && networks.get(ssid).stream().anyMatch(posture::weakerThan)) {
                findings.add(new SecurityFinding("ESS_SECURITY_DOWNGRADE", "HIGH",
                        "A different AP advertises stronger security for the same SSID. Possible rogue AP."));
            }
            if ("Privacy bit set".equals(ap.security()) || ap.advertisedSecurity().stream().anyMatch(profile ->
                    weakCipher(profile.groupCipher()) || profile.pairwiseCiphers().stream().anyMatch(ApSecurityAuditor::weakCipher))) {
                findings.add(new SecurityFinding("WEAK_CIPHER", "HIGH", "Advertises a legacy privacy mode or weak cipher."));
            }
            if (posture.open && !posture.owe) {
                findings.add(new SecurityFinding("UNENCRYPTED_OPEN", "MEDIUM", "Advertises an unencrypted open network."));
            }
            if (ap.wpsInfo() != null && !Boolean.TRUE.equals(ap.wpsInfo().apSetupLocked())) {
                findings.add(new SecurityFinding("WPS_UNLOCKED", "MEDIUM",
                        Boolean.FALSE.equals(ap.wpsInfo().apSetupLocked()) ? "WPS setup is advertised as unlocked."
                                : "WPS is advertised with no setup lock state."));
            }
            if (posture.protectedNetwork && ap.advertisedSecurity().stream()
                    .anyMatch(profile -> "Disabled".equals(profile.managementFrameProtection()))) {
                String severity = "6 GHz".equals(ap.band()) || posture.sae || posture.owe ? "HIGH" : "LOW";
                findings.add(new SecurityFinding("PMF_DISABLED", severity, "Protected management frames are disabled."));
            }
            if (posture.sae && !ap.rsnxeFeatures().contains("SAE H2E")) {
                findings.add(new SecurityFinding("SAE_HNP_ENABLED", "LOW",
                        "SAE is advertised without Hash-to-Element support."));
            }
            ChannelColor color = channelColor(ap);
            if (color != null && colors.get(color).stream().anyMatch(peer -> distinctRadio(ap, peer))) {
                findings.add(new SecurityFinding("BSS_COLOR_COLLISION", "LOW",
                        "Another AP on this frequency advertises the same BSS color."));
            }
            results.put(ap.bssid(), List.copyOf(findings));
        }
        return Map.copyOf(results);
    }

    private static SsidKey visibleSsid(AccessPoint ap) {
        if (ap.ssidHidden() || ap.ssid() == null || ap.ssid().isEmpty()) return null;
        return ap.ssidToken() == null ? new SsidKey(null, ap.ssid()) : new SsidKey(ap.ssidToken(), null);
    }

    private static ChannelColor channelColor(AccessPoint ap) {
        return ap.frequencyMhz() <= 0 || ap.apRadio() == null || ap.apRadio().bssColor() == null ? null
                : new ChannelColor(ap.frequencyMhz(), ap.apRadio().bssColor());
    }

    private static boolean distinctRadio(AccessPoint ap, AccessPoint peer) {
        return !ap.bssid().equals(peer.bssid()) && (ap.radioGroupId() == null || !ap.radioGroupId().equals(peer.radioGroupId()));
    }

    private static boolean weakCipher(String cipher) {
        return "WEP-40".equals(cipher) || "WEP-104".equals(cipher) || "TKIP".equals(cipher);
    }
}
