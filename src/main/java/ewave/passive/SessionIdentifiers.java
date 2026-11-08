package ewave.passive;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.HexFormat;

/** A different secret per capture session, with distinct namespaces for addresses and names. */
final class SessionIdentifiers {
    private final Mac hash;

    SessionIdentifiers() {
        byte[] secret = new byte[32];
        new SecureRandom().nextBytes(secret);
        try {
            hash = Mac.getInstance("HmacSHA256");
            hash.init(new SecretKeySpec(secret, "HmacSHA256"));
        } catch (GeneralSecurityException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    String id(String domain, String value) { return id(domain, value.getBytes(StandardCharsets.UTF_8)); }

    synchronized String id(String domain, byte[] value) {
        hash.update(domain.getBytes(StandardCharsets.US_ASCII));
        hash.update((byte) 0);
        return HexFormat.of().formatHex(hash.doFinal(value), 0, 12);
    }
}
