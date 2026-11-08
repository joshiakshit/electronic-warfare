package ewave.passive;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

final class FingerprintDb {
    record Finding(String family, String osHint, double confidence) { }

    private final Map<String, Finding> findings;

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
                parsed.put(fields[0], new Finding(fields[1], fields[2], confidence));
            }
        }
        findings = Map.copyOf(parsed);
    }

    Finding get(String signature) { return signature == null ? null : findings.get(signature); }
}
