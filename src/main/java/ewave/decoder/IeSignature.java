package ewave.decoder;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.TreeSet;

public final class IeSignature {
    private IeSignature() { }

    /** Hashes frame-independent capabilities. Vendor bytes beyond OUI/type are excluded. */
    public static String of(Dot11InformationElements ies) {
        MessageDigest hash;
        try { hash = MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
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
}
