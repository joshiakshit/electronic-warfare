package ewave.passive;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/** Counts observed transmitter addresses within the audit window without correlating addresses. */
public final class ProbeAuditAggregator {
    private static final int LIMIT = 65_536;
    private enum Exposure { PERSONAL_NAME_PATTERN, ROUTER_DEFAULT_PATTERN, CORPORATE, OTHER }
    private record Probe(long time, String id, boolean local, boolean directed, boolean uuidE, String signature) { }
    private record Name(long time, String hash, Exposure exposure, String reveal, String device) { }
    public record ProbeDevice(String id, long lastSeen) { }
    public record Ssid(String id, String name, String exposure, Integer deviceCount, long firstSeen, long lastSeen,
                       List<ProbeDevice> devices, List<Integer> timeline) { }
    public record Report(int windowMinutes, int totalObservedAddresses, int totalProbes,
                         double locallyAdministeredPct, double directedPct,
                         int distinctDirectedSsids, Map<String, Integer> directedPerAddress,
                         double wpsUuidEPct, int distinctSignaturesAmongLocalAddresses,
                         Map<String, Long> ssidExposureCounts, Map<String, List<String>> ssidTokens,
                         boolean sampleLimitReached, boolean deviceDetailsEnabled, List<Ssid> corpus,
                         long timelineStart, List<Integer> timeline) { }

    private final int minutes = RfSettings.integer("audit.windowMinutes", 15, 1, 1440);
    private final boolean deviceDetails = Boolean.getBoolean("audit.deviceDetails");
    private final boolean reveal = Boolean.getBoolean("audit.revealSsids");
    private final Set<String> corporate = Stream.of(System.getProperty("audit.corporateSsids", "").split(","))
            .map(String::strip).filter(s -> !s.isEmpty()).collect(Collectors.toUnmodifiableSet());
    private final Pattern personal;
    private final Pattern router;
    private final ArrayDeque<Probe> probes = new ArrayDeque<>();
    private final ArrayDeque<Name> names = new ArrayDeque<>();
    private long overflow = -1;

    ProbeAuditAggregator() throws IOException {
        var rules = new Properties();
        try (var source = new InputStreamReader(getClass().getResourceAsStream("/ssid-patterns.properties"),
                StandardCharsets.UTF_8)) { rules.load(source); }
        personal = Pattern.compile(rules.getProperty("personal"));
        router = Pattern.compile(rules.getProperty("router"));
    }

    void clear() {
        probes.clear();
        names.clear();
        overflow = -1;
    }

    void observe(long time, String id, boolean local, String signature, boolean wps, byte[] ssid,
                 boolean directed, SessionIdentifiers identifiers) {
        if (probes.size() == LIMIT) overflow = Math.max(overflow, probes.removeFirst().time);
        probes.addLast(new Probe(time, id, local, directed, wps, signature));
        if (!directed) return;
        if (names.size() == LIMIT) overflow = Math.max(overflow, names.removeFirst().time);
        String name = new String(ssid, StandardCharsets.UTF_8);
        Exposure kind = corporate.contains(name) ? Exposure.CORPORATE
                : personal.matcher(name).matches() ? Exposure.PERSONAL_NAME_PATTERN
                : router.matcher(name).matches() ? Exposure.ROUTER_DEFAULT_PATTERN : Exposure.OTHER;
        names.addLast(new Name(time, identifiers.id("ssid", ssid), kind, reveal ? name : null, deviceDetails ? id : null));
    }

    private long cutoff(long now, long retention) { return now - Math.min(retention, TimeUnit.MINUTES.toMillis(minutes)); }

    void purge(long now, long retention) {
        long cutoff = cutoff(now, retention);
        probes.removeIf(probe -> probe.time < cutoff);
        names.removeIf(name -> name.time < cutoff);
    }

    Report snapshot(long now, long retention) {
        purge(now, retention);
        var local = new HashSet<String>();
        var signatures = new HashSet<String>();
        var directed = new HashMap<String, Integer>();
        int wps = 0;
        for (Probe probe : probes) {
            directed.merge(probe.id, probe.directed ? 1 : 0, Integer::sum);
            if (probe.local) {
                local.add(probe.id);
                signatures.add(probe.signature);
            }
            if (probe.uuidE) wps++;
        }
        var histogram = new LinkedHashMap<>(Map.of("0", 0, "1", 0, "2-3", 0, "4-9", 0, "10+", 0));
        for (int count : directed.values())
            histogram.merge(count < 2 ? Integer.toString(count) : count < 4 ? "2-3" : count < 10 ? "4-9" : "10+", 1, Integer::sum);
        var distinct = new HashMap<String, Name>();
        for (Name name : names) distinct.put(name.hash, name);
        var counts = new LinkedHashMap<String, Long>();
        var tokens = new LinkedHashMap<String, List<String>>();
        for (Exposure kind : Exposure.values()) {
            var group = distinct.values().stream().filter(name -> name.exposure == kind)
                    .map(name -> name.reveal == null ? name.hash : name.reveal).sorted().toList();
            counts.put(kind.name(), (long) group.size());
            tokens.put(kind.name(), group);
        }
        long timelineStart = Math.floorDiv(now, 30_000) * 30_000 - 19 * 30_000;
        int[] timeline = new int[20];
        for (Probe probe : probes) count(timeline, timelineStart, probe.time);
        List<Ssid> corpus = corpus(timelineStart);
        int total = directed.size();
        return new Report(minutes, total, probes.size(), percent(local.size(), total),
                percent(total - histogram.get("0"), total), distinct.size(), Map.copyOf(histogram),
                percent(wps, probes.size()), signatures.size(), Map.copyOf(counts), Map.copyOf(tokens),
                overflow >= 0 && overflow >= cutoff(now, retention), deviceDetails, corpus, timelineStart, boxed(timeline));
    }

    private List<Ssid> corpus(long timelineStart) {
        var entries = new HashMap<String, SsidSamples>();
        for (Name name : names) entries.computeIfAbsent(name.hash, key -> new SsidSamples(name)).add(name, timelineStart);
        return entries.values().stream().sorted(Comparator.comparingLong((SsidSamples row) -> row.last).reversed()
                        .thenComparing(row -> row.sample.hash)).limit(512)
                .map(row -> new Ssid(row.sample.hash, row.sample.reveal, row.sample.exposure.name(),
                        deviceDetails ? row.devices.size() : null, row.first, row.last,
                        row.devices.entrySet().stream().map(item -> new ProbeDevice(item.getKey(), item.getValue()))
                                .sorted(Comparator.comparingLong(ProbeDevice::lastSeen).reversed().thenComparing(ProbeDevice::id))
                                .limit(512).toList(), boxed(row.timeline))).toList();
    }

    private static void count(int[] timeline, long start, long time) {
        if (time < start) return;
        long bucket = (time - start) / 30_000;
        if (bucket < timeline.length) timeline[(int) bucket]++;
    }

    private static List<Integer> boxed(int[] timeline) { return Arrays.stream(timeline).boxed().toList(); }

    private static final class SsidSamples {
        final Name sample;
        final Map<String, Long> devices = new HashMap<>();
        final int[] timeline = new int[20];
        long first = Long.MAX_VALUE, last;

        SsidSamples(Name sample) { this.sample = sample; }

        void add(Name name, long timelineStart) {
            first = Math.min(first, name.time);
            last = Math.max(last, name.time);
            if (name.device != null) devices.merge(name.device, name.time, Math::max);
            count(timeline, timelineStart, name.time);
        }
    }

    private static double percent(int n, int total) { return total == 0 ? 0 : 100.0 * n / total; }
}
