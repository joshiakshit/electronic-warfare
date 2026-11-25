package ewave.passive;

import ewave.decoder.Dot11ChannelSwitchDecoder;
import ewave.decoder.Dot11InformationElements;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/** Counts observed probe requests and network disclosures in the retained audit window. */
public final class ProbeAuditAggregator {
    private static final int LIMIT = 65_536;
    private static final int NAME_LOOKUP_LIMIT = 4096;
    private static final long RETRY_WINDOW_MS = 1000;
    private enum Exposure { PERSONAL_NAME_PATTERN, ROUTER_DEFAULT_PATTERN, CORPORATE, OTHER, SHORT_SSID_HASH }
    public enum Source { PLAINTEXT_SSID, SSID_LIST, SHORT_SSID_MATCH, SHORT_SSID_HASH }
    private record Network(String id, String label, Exposure exposure, int crc) { }
    private record Target(Network network, Source source) { }
    private record KnownName(Network network, long time) { }
    private record RetryKey(String sender, int sequenceControl) { }
    private record Probe(long time, String id, boolean local, String signature, String wpsUuidToken,
                         boolean passpoint, String p2pName, List<Target> plaintext, List<Integer> shortSsids) { }
    public record ProbeDevice(String id, long lastSeen) { }
    public record Ssid(String id, String name, String exposure, int deviceCount, long firstSeen, long lastSeen,
                       List<ProbeDevice> devices, List<Integer> timeline, Source source, List<Source> sources) { }
    public record Report(int windowMinutes, int totalObservedAddresses, int totalProbes, int directedProbes,
                         double locallyAdministeredPct, double directedPct,
                         int distinctDirectedSsids, Map<String, Integer> directedPerAddress,
                         double wpsUuidEPct, int distinctSignaturesAmongLocalAddresses,
                         Map<String, Long> ssidExposureCounts, Map<String, List<String>> ssidTokens,
                         boolean sampleLimitReached, boolean deviceDetailsEnabled, List<Ssid> corpus,
                         long timelineStart, List<Integer> timeline, int distinctWpsUuids, int wpsMultiAddressCount,
                         double passpointPct, int p2pNamedProbes, Map<String, String> p2pDeviceNames,
                         int correlatedClusterCount) { }

    private final int minutes = RfSettings.integer("audit.windowMinutes", 15, 1, 1440);
    private final Set<String> corporate = Stream.of(System.getProperty("audit.corporateSsids", "").split(","))
            .map(String::strip).filter(s -> !s.isEmpty()).collect(Collectors.toUnmodifiableSet());
    private final SessionIdentifiers ids;
    private final Pattern personal;
    private final Pattern router;
    private final Pattern enterprise;
    private final ArrayDeque<Probe> probes = new ArrayDeque<>();
    private final LinkedHashMap<String, KnownName> knownNames = new LinkedHashMap<>(16, .75f, true);
    private final LinkedHashMap<RetryKey, Long> recent = new LinkedHashMap<>(16, .75f, true);
    private long overflow = -1;

    ProbeAuditAggregator(SessionIdentifiers ids) throws IOException {
        this.ids = ids;
        var rules = new Properties();
        try (var source = new InputStreamReader(getClass().getResourceAsStream("/ssid-patterns.properties"),
                StandardCharsets.UTF_8)) { rules.load(source); }
        personal = Pattern.compile(rules.getProperty("personal"));
        router = Pattern.compile(rules.getProperty("router"));
        enterprise = Pattern.compile(rules.getProperty("corporate"));
    }

    void clear() {
        probes.clear();
        knownNames.clear();
        recent.clear();
        overflow = -1;
    }

    boolean duplicate(long time, String id, int sequenceControl, boolean retry) {
        var key = new RetryKey(id, sequenceControl);
        Long seen = recent.get(key);
        recent.put(key, seen == null ? time : Math.max(time, seen));
        if (recent.size() > LIMIT) recent.pollFirstEntry();
        return retry && seen != null && Math.abs(time - seen) <= RETRY_WINDOW_MS;
    }

    void observeAdvertisement(byte[] ssid, long time) {
        if (!Dot11InformationElements.hidden(ssid)) remember(ssid, time);
    }

    private Network remember(byte[] ssid, long time) {
        String id = ids.id("ssid", ssid);
        var previous = knownNames.get(id);
        Network network = previous == null ? describe(id, ssid) : previous.network;
        if (previous == null || time > previous.time) knownNames.put(id, new KnownName(network, time));
        if (knownNames.size() > NAME_LOOKUP_LIMIT) knownNames.pollFirstEntry();
        return network;
    }

    void observe(long time, String id, boolean local, String signature, String wpsUuidToken, byte[] ssid,
                 List<byte[]> ssidList, List<Integer> shortSsids, boolean passpoint, String p2pName) {
        var targets = Stream.<Target>builder();
        if (!Dot11InformationElements.hidden(ssid)) targets.add(new Target(remember(ssid, time), Source.PLAINTEXT_SSID));
        for (byte[] name : ssidList) targets.add(new Target(remember(name, time), Source.SSID_LIST));
        if (probes.size() == LIMIT) overflow = Math.max(overflow, probes.removeFirst().time);
        probes.addLast(new Probe(time, id, local, signature, wpsUuidToken, passpoint, p2pName,
                targets.build().distinct().toList(), shortSsids.stream().distinct().toList()));
    }

    private Network describe(String id, byte[] ssid) {
        String label = Dot11InformationElements.ssidLabel(ssid);
        Exposure exposure = corporate.contains(label) || enterprise.matcher(label).matches() ? Exposure.CORPORATE
                : personal.matcher(label).matches() ? Exposure.PERSONAL_NAME_PATTERN
                : router.matcher(label).matches() ? Exposure.ROUTER_DEFAULT_PATTERN : Exposure.OTHER;
        return new Network(id, label, exposure, Dot11ChannelSwitchDecoder.shortSsidCrc32(ssid));
    }

    private long cutoff(long now, long retention) { return now - Math.min(retention, TimeUnit.MINUTES.toMillis(minutes)); }

    void purge(long now, long retention) {
        long cutoff = cutoff(now, retention);
        probes.removeIf(probe -> probe.time < cutoff);
        knownNames.values().removeIf(name -> name.time < now - retention);
        recent.values().removeIf(time -> time < cutoff - RETRY_WINDOW_MS);
    }

    PendingReport prepareSnapshot(long now, long retention, int correlatedClusterCount) {
        purge(now, retention);
        return new PendingReport(minutes, now, overflow >= 0 && overflow >= cutoff(now, retention),
                List.copyOf(probes), knownNames.values().stream().map(KnownName::network).toList(),
                correlatedClusterCount);
    }

    record PendingReport(int minutes, long now, boolean sampleLimitReached, List<Probe> probes,
                         List<Network> knownNames, int correlatedClusterCount) {
        Report build() {
            var resolved = shortSsidLookup();
            var local = new HashSet<String>();
            var signatures = new HashSet<String>();
            var perAddress = new HashMap<String, Set<String>>();
            var wpsAddresses = new HashMap<String, Set<String>>();
            var namedP2p = new HashMap<String, Probe>();
            var networks = new HashMap<String, SsidSamples>();
            long timelineStart = Math.floorDiv(now, 30_000) * 30_000 - 19 * 30_000;
            int[] timeline = new int[20];
            int directed = 0, wps = 0, passpoint = 0, p2p = 0;
            for (Probe probe : probes) {
                var names = perAddress.computeIfAbsent(probe.id, key -> new HashSet<>());
                if (!probe.plaintext.isEmpty() || !probe.shortSsids.isEmpty()) directed++;
                for (Target target : probe.plaintext) addTarget(networks, target, probe, names, timelineStart);
                for (int crc : probe.shortSsids) {
                    var target = resolved.computeIfAbsent(crc, PendingReport::unresolved);
                    addTarget(networks, target, probe, names, timelineStart);
                }
                if (probe.local) {
                    local.add(probe.id);
                    if (probe.signature != null) signatures.add(probe.signature);
                }
                if (probe.wpsUuidToken != null) {
                    wps++;
                    wpsAddresses.computeIfAbsent(probe.wpsUuidToken, key -> new HashSet<>()).add(probe.id);
                }
                if (probe.passpoint) passpoint++;
                if (probe.p2pName != null) {
                    p2p++;
                    namedP2p.merge(probe.id, probe, (previous, next) -> next.time >= previous.time ? next : previous);
                }
                count(timeline, timelineStart, probe.time);
            }
            var histogram = new LinkedHashMap<>(Map.of("0", 0, "1", 0, "2-3", 0, "4-9", 0, "10+", 0));
            for (var names : perAddress.values()) {
                int size = names.size();
                histogram.merge(size < 2 ? Integer.toString(size) : size < 4 ? "2-3" : size < 10 ? "4-9" : "10+",
                        1, Integer::sum);
            }
            var counts = new LinkedHashMap<String, Long>();
            var tokens = new LinkedHashMap<String, List<String>>();
            for (Exposure kind : Exposure.values()) {
                var group = networks.values().stream().map(row -> row.network).filter(network -> network.exposure == kind)
                        .map(Network::label).sorted().toList();
                counts.put(kind.name(), (long) group.size());
                tokens.put(kind.name(), group);
            }
            var corpus = networks.values().stream().sorted(Comparator.comparingLong((SsidSamples row) -> row.last).reversed()
                            .thenComparing(row -> row.network.id)).limit(512).map(SsidSamples::row).toList();
            int total = perAddress.size();
            int sharedWps = (int) wpsAddresses.values().stream().filter(addresses -> addresses.size() >= 2).count();
            var p2pNames = namedP2p.entrySet().stream()
                    .collect(Collectors.toUnmodifiableMap(Map.Entry::getKey, entry -> entry.getValue().p2pName));
            return new Report(minutes, total, probes.size(), directed, percent(local.size(), total),
                    percent(total - histogram.get("0"), total), networks.size(), Map.copyOf(histogram),
                    percent(wps, probes.size()), signatures.size(), Map.copyOf(counts), Map.copyOf(tokens),
                    sampleLimitReached, true, corpus, timelineStart, boxed(timeline), wpsAddresses.size(), sharedWps,
                    percent(passpoint, probes.size()), p2p, p2pNames, correlatedClusterCount);
        }

        private Map<Integer, Target> shortSsidLookup() {
            var resolved = new HashMap<Integer, Target>();
            Stream.concat(knownNames.stream(), probes.stream().flatMap(probe -> probe.plaintext.stream()).map(Target::network))
                    .forEach(network -> resolved.merge(network.crc, new Target(network, Source.SHORT_SSID_MATCH),
                            (left, right) -> left.equals(right) ? left : unresolved(network.crc)));
            return resolved;
        }

        private static Target unresolved(int crc) {
            String hex = HexFormat.of().toHexDigits(crc);
            return new Target(new Network("short-ssid-" + hex, "Short-SSID 0x" + hex, Exposure.SHORT_SSID_HASH, crc),
                    Source.SHORT_SSID_HASH);
        }
    }

    private static void addTarget(Map<String, SsidSamples> rows, Target target, Probe probe,
                                  Set<String> names, long timelineStart) {
        names.add(target.network.id);
        rows.computeIfAbsent(target.network.id, key -> new SsidSamples(target.network)).add(target, probe, timelineStart);
    }

    private static void count(int[] timeline, long start, long time) {
        if (time < start) return;
        long bucket = (time - start) / 30_000;
        if (bucket < timeline.length) timeline[(int) bucket]++;
    }

    private static List<Integer> boxed(int[] timeline) { return Arrays.stream(timeline).boxed().toList(); }

    private static final class SsidSamples {
        final Network network;
        final Map<String, Long> devices = new HashMap<>();
        final Set<Source> sources = EnumSet.noneOf(Source.class);
        final int[] timeline = new int[20];
        long first = Long.MAX_VALUE, last;
        Probe lastProbe;

        SsidSamples(Network network) { this.network = network; }

        void add(Target target, Probe probe, long timelineStart) {
            sources.add(target.source);
            if (lastProbe == probe) return;
            lastProbe = probe;
            first = Math.min(first, probe.time);
            last = Math.max(last, probe.time);
            devices.merge(probe.id, probe.time, Math::max);
            count(timeline, timelineStart, probe.time);
        }

        Ssid row() {
            var deviceRows = devices.entrySet().stream().map(item -> new ProbeDevice(item.getKey(), item.getValue()))
                    .sorted(Comparator.comparingLong(ProbeDevice::lastSeen).reversed().thenComparing(ProbeDevice::id))
                    .toList();
            var orderedSources = List.copyOf(sources);
            return new Ssid(network.id, network.label, network.exposure.name(), devices.size(),
                    first, last, deviceRows, boxed(timeline), orderedSources.getFirst(), orderedSources);
        }
    }

    private static double percent(int n, int total) { return total == 0 ? 0 : 100.0 * n / total; }
}
