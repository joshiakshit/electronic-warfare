package ewave.decoder;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

/** Advertised WPA/RSN suites and the modes explicitly indicated by those suites. */
public final class SecurityDecoder {
    private static final String OWE_TRANSITION = "506f9a1c";
    private static final HexFormat MAC = HexFormat.ofDelimiter(":");

    private SecurityDecoder() { }

    public record Profile(String key, String protocol, String groupCipher, List<String> pairwiseCiphers,
                          List<String> authentication, String managementFrameProtection) { }
    public record Summary(List<Profile> profiles, List<String> rsnAkmSuites, List<String> modes,
                          String groupManagementCipher, List<String> rsnxeFeatures, boolean beaconProtection,
                          boolean ocvc) {
        public Summary(List<Profile> profiles, List<String> rsnAkmSuites, List<String> modes) {
            this(profiles, rsnAkmSuites, modes, null, List.of(), false, false);
        }
    }
    private record ParsedSecurity(Profile profile, int capabilities, String groupManagementCipher) { }
    public record OweTransition(String peerBssid, byte[] ssidBytes, String ssidLabel) {
        public OweTransition { ssidBytes = ssidBytes.clone(); }
        @Override public byte[] ssidBytes() { return ssidBytes.clone(); }
    }

    public static OweTransition decodeOweTransition(Dot11InformationElements ies) {
        for (var ie : ies.elements()) {
            if (!OWE_TRANSITION.equals(ie.vendorKey())) continue;
            var transition = decodeOweTransition(ie.value());
            if (transition != null) return transition;
        }
        return null;
    }

    private static OweTransition decodeOweTransition(byte[] data) {
        if (data.length < 11 || (data[4] & 1) != 0) return null;
        int length = data[10] & 0xff;
        if (length > Math.min(32, data.length - 11)) return null;
        String peer = MAC.formatHex(data, 4, 10);
        if ("00:00:00:00:00:00".equals(peer)) return null;
        byte[] ssid = Arrays.copyOfRange(data, 11, 11 + length);
        return new OweTransition(peer, ssid, Dot11InformationElements.ssidLabel(ssid));
    }

    public static boolean hasOweTransitionElement(Dot11InformationElements ies) {
        return ies.elements().stream().anyMatch(ie -> OWE_TRANSITION.equals(ie.vendorKey()));
    }

    public static boolean isMultiApBackhaul(Dot11InformationElements ies) {
        for (var ie : ies.elements()) {
            if (!"506f9a1b".equals(ie.vendorKey())) continue;
            byte[] data = ie.value();
            for (int pos = 4; data.length - pos >= 2;) {
                int id = data[pos++] & 0xff, length = data[pos++] & 0xff;
                if (length > data.length - pos) break;
                if (id == 6 && length == 1 && (data[pos] & 0x40) != 0) return true;
                pos += length;
            }
        }
        return false;
    }

    public static Summary decode(Dot11InformationElements ies) {
        var profiles = new TreeMap<String, Profile>();
        var modes = new TreeSet<String>();
        var rsn = ies.has(48) ? addSecurity(profiles, "RSN", ies.first(48), 0) : null;
        for (var ie : ies.elements()) {
            String vendor = ie.vendorKey();
            if ("0050f201".equals(vendor)) addSecurity(profiles, "WPA", ie.value(), 4);
            if (OWE_TRANSITION.equals(vendor) && decodeOweTransition(ie.value()) != null) modes.add("OWE transition");
        }
        var akms = profiles.values().stream().filter(profile -> profile.protocol.equals("RSN"))
                .flatMap(profile -> profile.authentication.stream()).distinct().toList();
        if (akms.stream().anyMatch(akm -> akm.equals("SAE") || akm.startsWith("FT/SAE")
                || akm.equals("SAE Extended Key"))) {
            modes.add(akms.stream().anyMatch(akm -> akm.startsWith("PSK") || akm.startsWith("FT/PSK"))
                    ? "WPA2/WPA3-Personal transition" : "WPA3-Personal (SAE)");
        }
        if (akms.contains("OWE")) modes.add("OWE (Enhanced Open)");
        return new Summary(List.copyOf(profiles.values()), akms, List.copyOf(modes),
                rsn == null ? null : rsn.groupManagementCipher(), rsnxeFeatures(ies.first(244)),
                Dot11InformationElements.capabilityBit(ies.first(127), 84),
                rsn != null && (rsn.capabilities() & 0x4000) != 0);
    }

    private static List<String> rsnxeFeatures(byte[] ie) {
        if (ie.length == 0 || (ie[0] & 0x0f) + 1 > ie.length) return List.of();
        var features = new ArrayList<String>(3);
        if ((ie[0] & 0x20) != 0) features.add("SAE H2E");
        if ((ie[0] & 0x40) != 0) features.add("SAE-PK");
        if ((ie[0] & 0x10) != 0) features.add("Protected TWT");
        return List.copyOf(features);
    }

    private static ParsedSecurity addSecurity(Map<String, Profile> security, String protocol, byte[] ie, int start) {
        var parsed = securitySuites(protocol, ie, start);
        if (parsed == null) security.put(protocol, new Profile(protocol, protocol, null, List.of(), List.of(), null));
        else security.put(parsed.profile().key(), parsed.profile());
        return parsed;
    }

    private static ParsedSecurity securitySuites(String protocol, byte[] ie, int start) {
        if (ie.length - start < 10 || u16(ie, start) != 1) return null;
        int pos = start + 6;
        String group = HexFormat.of().formatHex(ie, start + 2, pos);
        var parts = new ArrayList<TreeSet<String>>();
        for (int list = 0; list < 2; list++) {
            if (ie.length - pos < 2) return null;
            int count = u16(ie, pos);
            pos += 2;
            if (count == 0 || count > (ie.length - pos) / 4) return null;
            var suites = new TreeSet<String>();
            for (int i = 0; i < count; i++, pos += 4) suites.add(HexFormat.of().formatHex(ie, pos, pos + 4));
            parts.add(suites);
        }
        String key = protocol + "[" + group + ";" + String.join(",", parts.get(0)) + ";"
                + String.join(",", parts.get(1)) + "]";
        String pmf = null;
        int capabilities = 0;
        String groupManagementCipher = null;
        if (protocol.equals("RSN") && ie.length - pos >= 2) {
            capabilities = u16(ie, pos);
            pmf = (capabilities & 0x40) != 0 ? "Required" : (capabilities & 0x80) != 0 ? "Capable" : "Disabled";
            groupManagementCipher = groupManagementCipher(ie, pos + 2);
        }
        var profile = new Profile(key, protocol, cipher(group),
                parts.get(0).stream().map(SecurityDecoder::cipher).toList(),
                parts.get(1).stream().map(SecurityDecoder::authentication).toList(), pmf);
        return new ParsedSecurity(profile, capabilities, groupManagementCipher);
    }

    private static String groupManagementCipher(byte[] ie, int pos) {
        if (ie.length - pos < 2) return null;
        int pmkidCount = u16(ie, pos);
        pos += 2;
        if (pmkidCount > (ie.length - pos) / 16) return null;
        pos += 16 * pmkidCount;
        return ie.length - pos >= 4 ? cipher(HexFormat.of().formatHex(ie, pos, pos + 4)) : null;
    }

    private static String cipher(String suite) {
        int type = suiteType(suite, 5);
        return switch (type) {
            case 0 -> "Use group cipher";
            case 1 -> "WEP-40";
            case 2 -> "TKIP";
            case 4 -> "CCMP-128";
            case 5 -> "WEP-104";
            case 6 -> "BIP-CMAC-128";
            case 8 -> "GCMP-128";
            case 9 -> "GCMP-256";
            case 10 -> "CCMP-256";
            case 11 -> "BIP-GMAC-128";
            case 12 -> "BIP-GMAC-256";
            case 13 -> "BIP-CMAC-256";
            default -> "0x" + suite;
        };
    }

    private static String authentication(String suite) {
        if (suite.equals("506f9a02")) return "DPP";
        if (suite.equals("00409600")) return "CCKM";
        return switch (suiteType(suite, 2)) {
            case 1 -> "802.1X";
            case 2 -> "PSK";
            case 3 -> "FT/802.1X";
            case 4 -> "FT/PSK";
            case 5 -> "802.1X/SHA-256";
            case 6 -> "PSK/SHA-256";
            case 8 -> "SAE";
            case 9 -> "FT/SAE";
            case 11 -> "802.1X Suite B";
            case 12 -> "802.1X Suite B 192-bit";
            case 13 -> "FT/802.1X/SHA-384";
            case 14 -> "FILS/SHA-256";
            case 15 -> "FILS/SHA-384";
            case 16 -> "FT/FILS/SHA-256";
            case 17 -> "FT/FILS/SHA-384";
            case 18 -> "OWE";
            case 19 -> "FT/PSK/SHA-384";
            case 20 -> "PSK/SHA-384";
            case 21 -> "PASN";
            case 22 -> "FT/802.1X/SHA-384 unrestricted";
            case 23 -> "802.1X/SHA-384";
            case 24 -> "SAE Extended Key";
            case 25 -> "FT/SAE Extended Key";
            default -> "0x" + suite;
        };
    }

    private static int suiteType(String suite, int legacyMax) {
        int type = Integer.parseInt(suite.substring(6), 16);
        return suite.startsWith("000fac") || (suite.startsWith("0050f2") && type <= legacyMax) ? type : -1;
    }

    private static int u16(byte[] data, int offset) {
        return (data[offset] & 0xff) | (data[offset + 1] & 0xff) << 8;
    }
}
