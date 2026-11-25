package ewave.decoder;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.TreeSet;

public final class IeSignature {
    private IeSignature() { }

    /** Requires an IE whose capability bytes contribute to the fingerprint. */
    public static boolean hasCapabilityEvidence(Dot11InformationElements ies) {
        return ies.elements().stream().anyMatch(element -> switch (element.id()) {
            case 1, 50, 127 -> element.size() > 0;
            case 45 -> element.size() >= 26;
            case 191 -> element.size() >= 12;
            case 255 -> element.extension() == 35 && element.size() >= 22
                    || element.extension() == 108 && element.size() >= 15;
            default -> false;
        });
    }

    /** Hashes frame-independent capabilities. Vendor bytes beyond OUI/type are excluded. */
    public static String of(Dot11InformationElements ies) {
        MessageDigest hash = sha256();
        var vendors = new TreeSet<String>();
        for (var element : ies.elements()) {
            int id = element.id(), ext = element.extension();
            if (id == 0 || id == 3 || id == 5) continue;
            hash.update((byte) id);
            if (id == 255) hash.update((byte) ext);
            byte[] value = element.value();
            if (id == 1 || id == 50 || id == 45 || id == 191 || id == 127 || ext == 35 || ext == 108) {
                hash.update((byte) value.length);
                hash.update(value);
            }
            if (element.vendorKey() != null) vendors.add(element.vendorKey());
        }
        hash.update((byte) 0);
        for (String vendor : vendors) hash.update(HexFormat.of().parseHex(vendor));
        return HexFormat.of().formatHex(hash.digest(), 0, 8);
    }

    /**
     * Hashes frame-type-invariant IEEE capability tags in canonical order, excluding vendor tags (221)
     * and frame-specific IEs (RSNE/MDIE) so Probe Requests and Association Requests match on one band.
     */
    public static String capabilityCohortOf(Dot11InformationElements ies) {
        if (ies == null || !hasCapabilityEvidence(ies)) return null;
        MessageDigest hash = sha256();
        for (int targetId : new int[]{1, 45, 50, 127, 191}) {
            for (var element : ies.elements()) {
                if (element.id() == targetId) {
                    byte[] value = element.value();
                    hash.update((byte) targetId);
                    hash.update((byte) value.length);
                    hash.update(value);
                }
            }
        }
        for (int targetExt : new int[]{35, 108}) {
            for (var element : ies.elements()) {
                if (element.id() == 255 && element.extension() == targetExt) {
                    byte[] value = element.value();
                    hash.update((byte) 255);
                    hash.update((byte) targetExt);
                    hash.update((byte) value.length);
                    hash.update(value);
                }
            }
        }
        return HexFormat.of().formatHex(hash.digest(), 0, 8);
    }

    /**
     * Hashes station capability octets that remain invariant across 2.4 GHz and 5/6 GHz associations
     * (HT RX MCS mask, Extended Capabilities, and HE/EHT capability tags).
     */
    public static String bandInvariantCohortOf(Dot11InformationElements ies) {
        if (ies == null) return null;
        MessageDigest hash = sha256();
        boolean any = false;
        for (var element : ies.elements()) {
            if (element.id() == 45 && element.size() >= 7) {
                byte[] value = element.value();
                hash.update((byte) 45);
                hash.update(value, 3, 4);
                any = true;
            }
        }
        for (var element : ies.elements()) {
            if (element.id() == 127 && element.size() > 0) {
                byte[] value = element.value();
                hash.update((byte) 127);
                hash.update((byte) value.length);
                hash.update(value);
                any = true;
            }
        }
        for (int targetExt : new int[]{35, 108}) {
            int minSize = targetExt == 35 ? 22 : 15;
            for (var element : ies.elements()) {
                if (element.id() == 255 && element.extension() == targetExt && element.size() >= minSize) {
                    byte[] value = element.value();
                    hash.update((byte) 255);
                    hash.update((byte) targetExt);
                    hash.update((byte) value.length);
                    hash.update(value);
                    any = true;
                }
            }
        }
        return any ? HexFormat.of().formatHex(hash.digest(), 0, 8) : null;
    }

    private static MessageDigest sha256() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
}
