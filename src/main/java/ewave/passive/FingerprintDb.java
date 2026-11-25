package ewave.passive;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * IE-signature lookup combining the bundled (or {@code rf.fingerprints}) table with operator-saved
 * My Network reference samples. Saved samples take precedence over table rows for the same signature.
 */
final class FingerprintDb {
    record Finding(String family, String osHint, double confidence, String basis) { }

    /** Confidence of a signature whose saved samples all agree on one device class. */
    static final double SAMPLE_CONFIDENCE = 0.95;

    private final Map<String, Finding> findings;
    private volatile Map<String, Finding> samples = Map.of();

    FingerprintDb() throws IOException {
        String custom = System.getProperty("rf.fingerprints");
        InputStream source = custom == null ? getClass().getResourceAsStream("/fingerprints.csv")
                : Files.newInputStream(Path.of(custom));
        var parsed = new HashMap<String, Finding>();
        try (var reader = new BufferedReader(new InputStreamReader(source, StandardCharsets.UTF_8))) {
            for (String line; (line = reader.readLine()) != null;) {
                if (line.isBlank() || line.startsWith("#") || line.startsWith("hash,")) continue;
                String[] fields = line.split(",", -1);
                if (fields.length != 4 || !fields[0].matches("[0-9a-f]{16}") || fields[1].isBlank())
                    throw new IOException("Invalid fingerprint table row");
                double confidence;
                try { confidence = Double.parseDouble(fields[3]); }
                catch (NumberFormatException invalid) { throw new IOException("Invalid fingerprint confidence", invalid); }
                if (!Double.isFinite(confidence) || confidence < 0 || confidence > 1)
                    throw new IOException("Fingerprint confidence must be in 0..1");
                parsed.put(fields[0], new Finding(fields[1], fields[2], confidence, "SIGNATURE_TABLE"));
            }
        }
        findings = Map.copyOf(parsed);
    }

    /** Replaces the operator reference samples; conflicting labels for one signature lower its confidence. */
    void useSamples(List<MyNetworkProfile.FingerprintSample> saved) {
        var grouped = new LinkedHashMap<String, List<MyNetworkProfile.FingerprintSample>>();
        for (var sample : saved == null ? List.<MyNetworkProfile.FingerprintSample>of() : saved)
            grouped.computeIfAbsent(sample.evidence().hash(), key -> new java.util.ArrayList<>()).add(sample);
        var parsed = new HashMap<String, Finding>();
        grouped.forEach((hash, group) -> parsed.put(hash, consensus(group)));
        samples = Map.copyOf(parsed);
    }

    private static Finding consensus(List<MyNetworkProfile.FingerprintSample> group) {
        var families = new LinkedHashMap<String, Integer>();
        for (var sample : group) families.merge(sample.family(), 1, Integer::sum);
        var family = families.entrySet().stream().max(Map.Entry.comparingByValue()).orElseThrow();
        var hints = new LinkedHashMap<String, Integer>();
        for (var sample : group)
            if (sample.family().equals(family.getKey()) && !sample.osHint().isEmpty())
                hints.merge(sample.osHint(), 1, Integer::sum);
        String osHint = hints.entrySet().stream().max(Map.Entry.comparingByValue()).map(Map.Entry::getKey).orElse("");
        return new Finding(family.getKey(), osHint, SAMPLE_CONFIDENCE * family.getValue() / group.size(), "SAVED_SAMPLE");
    }

    Finding get(String signature) {
        if (signature == null) return null;
        Finding saved = samples.get(signature);
        return saved != null ? saved : findings.get(signature);
    }
}
