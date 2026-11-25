package ewave.decoder;

import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;

/** Decodes nontransmitted profiles carried by a transmitting AP's advertisement. */
public final class MultipleBssidDecoder {
    private static final HexFormat MAC = HexFormat.ofDelimiter(":");

    private MultipleBssidDecoder() { }

    public record Profile(String bssid, Dot11InformationElements ies, int capability,
                          SecurityDecoder.Summary security) { }

    public static List<Profile> decode(Dot11Frame frame) {
        if (!frame.apAdvertisement() || !frame.addr2().equals(frame.addr3()) || (frame.capability() & 1) == 0)
            return List.of();
        var parent = frame.ies();
        if (parent == null || !parent.has(71)) return List.of();
        var parentSecurity = SecurityDecoder.decode(parent);
        byte[] address = MAC.parseHex(frame.addr2());
        var profiles = new LinkedHashMap<String, Profile>();
        for (var element : parent.elements()) {
            if (element.id() != 71 || element.size() < 1) continue;
            byte[] value = element.value();
            int n = value[0] & 0xff;
            if (n < 1 || n > 8) continue;
            for (int pos = 1; value.length - pos >= 2;) {
                int subId = value[pos++] & 0xff;
                int length = value[pos++] & 0xff;
                if (length > value.length - pos) break;
                if (subId == 0) {
                    var profile = decodeProfile(value, pos, pos + length, address, (1 << n) - 1,
                            frame.capability(), parentSecurity);
                    if (profile != null) profiles.putIfAbsent(profile.bssid(), profile);
                }
                pos += length;
            }
        }
        return List.copyOf(profiles.values());
    }

    private static Profile decodeProfile(byte[] value, int start, int end, byte[] address, int mask,
                                         int parentCapability, SecurityDecoder.Summary parentSecurity) {
        var ies = Dot11InformationElements.parse(value, start, end);
        if (ies == null) return null;
        byte[] index = ies.first(85);
        if (index.length == 0) return null;
        int offset = index[0] & 0xff;
        if (offset == 0 || offset > mask) return null;
        byte[] derived = address.clone();
        int lsb = address[5] & 0xff;
        derived[5] = (byte) ((lsb & ~mask) | ((lsb + offset) & mask));

        byte[] capabilities = ies.first(83);
        int capability = capabilities.length == 2
                ? (capabilities[0] & 0xff) | (capabilities[1] & 0xff) << 8 : parentCapability;
        var security = SecurityDecoder.decode(ies);
        if (security.profiles().isEmpty()) {
            byte[] nonInheritance = ies.extension(56);
            if (excludesRsn(nonInheritance)) {
                var inheritedWpa = new ArrayList<SecurityDecoder.Profile>();
                for (var profile : parentSecurity.profiles()) {
                    if (profile.protocol().equals("WPA")) inheritedWpa.add(profile);
                }
                security = new SecurityDecoder.Summary(List.copyOf(inheritedWpa), List.of(), security.modes());
            } else {
                security = parentSecurity;
            }
        }
        return new Profile(MAC.formatHex(derived), ies, capability, security);
    }

    private static boolean excludesRsn(byte[] value) {
        if (value.length < 3) return false;
        int count = value[1] & 0xff;
        int extensions = 2 + count;
        if (extensions >= value.length || (value[extensions] & 0xff) != value.length - extensions - 1)
            return false;
        for (int i = 2; i < extensions; i++) {
            if ((value[i] & 0xff) == 48) return true;
        }
        return false;
    }
}
