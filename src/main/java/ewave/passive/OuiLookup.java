package ewave.passive;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.HexFormat;
import java.util.Optional;
import java.util.regex.Pattern;

/** Offline longest-prefix lookup of 24-, 28-, and 36-bit manufacturer prefixes. A registration is not a device identity. */
public final class OuiLookup {
    private final HashMap<String, String> vendors = new HashMap<>();

    private static final Pattern PREFIX = Pattern.compile(
            "(?i)(?:[0-9a-f]{2}(?::[0-9a-f]{2}){2}|[0-9a-f]{2}(?::[0-9a-f]{2}){3}/28"
                    + "|[0-9a-f]{2}(?::[0-9a-f]{2}){4}/36)");

    public OuiLookup() {
        this(OuiLookup.class.getResourceAsStream("/oui.txt"));
        load(OuiLookup.class.getResourceAsStream("/oui-specific.txt"));
    }

    // Package seam for small, deterministic manufacturer tables in tests.
    OuiLookup(InputStream input) { load(input); }

    private void load(InputStream input) {
        if (input == null) return;
        try (var reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.strip();
                if (line.isEmpty() || line.startsWith("#")) continue;
                String[] fields = line.split("\\s+", 2);
                if (fields.length != 2 || !PREFIX.matcher(fields[0]).matches()) continue;
                // Wireshark separates its short and full names by tabs or multiple spaces.
                String[] names = fields[1].strip().split("\\t+| {2,}", 2);
                String vendor = names[names.length - 1].strip();
                String[] prefix = fields[0].split("/");
                String hex = prefix[0].replace(":", "").toUpperCase(Locale.ROOT);
                int digits = prefix.length == 1 ? 6 : Integer.parseInt(prefix[1]) / 4;
                if (!vendor.isEmpty()) vendors.put(hex.substring(0, digits), vendor);
            }
        } catch (IOException failure) {
            throw new UncheckedIOException("Unable to read bundled OUI data", failure);
        }
    }

    public String lookup(String mac) { return registration(mac).map(Registration::vendor).orElse("Unknown"); }

    public record Registration(String prefix, String vendor) { }

    public Optional<Registration> registration(String mac) {
        if (mac == null || !mac.strip().matches("(?i)[0-9a-f]{2}(:[0-9a-f]{2}){2,5}")) return Optional.empty();
        return registration(HexFormat.ofDelimiter(":").parseHex(mac.strip()));
    }

    public Optional<String> lookupAddress(byte[] address) { return registration(address).map(Registration::vendor); }

    private Optional<Registration> registration(byte[] address) {
        if (address == null || address.length < 3 || isLocallyAdministered(address) || isMulticast(address))
            return Optional.empty();
        String hex = HexFormat.of().withUpperCase().formatHex(address);
        for (int digits : new int[]{9, 7, 6}) {
            if (hex.length() < digits) continue;
            String prefix = hex.substring(0, digits);
            String vendor = vendors.get(prefix);
            if (vendor != null) return Optional.of(new Registration(prefix + "/" + digits * 4, vendor));
        }
        return Optional.empty();
    }

    public static boolean isLocallyAdministered(byte[] address) { return (address[0] & 2) != 0; }
    public static boolean isMulticast(byte[] address) { return (address[0] & 1) != 0; }
}
