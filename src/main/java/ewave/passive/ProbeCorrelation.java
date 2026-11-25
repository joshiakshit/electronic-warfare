package ewave.passive;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.function.Function;

/** Bounded, session-local correlations between locally administered station addresses. */
public final class ProbeCorrelation {
    private static final int ADDRESS_LIMIT = 1024;
    private static final int PROBE_LIMIT = 16;
    private static final int MAX_GAP_MS = 2000;
    private static final int CLOSE_GAP_MS = 250;
    private static final int MAX_ASSOC_GAP_MS = 15_000;
    private static final int MAX_PROFILE_GAP_MS = 60_000;
    private static final int MAX_SEQUENCE_STEP = 16;
    private static final String INFERENCE = "Probabilistic inferred correlation";

    public record Evidence(String fromId, String toId, int sequenceStep, long gapMs,
                           int sharedDirectedSsidCount, double confidence, String basis) {
        public Evidence(String fromId, String toId, int sequenceStep, long gapMs,
                        int sharedDirectedSsidCount, double confidence) {
            this(fromId, toId, sequenceStep, gapMs, sharedDirectedSsidCount, confidence, "SEQUENCE_HANDOFF");
        }
    }
    public record Reference(String id, String inference, double confidence, int memberCount) { }
    public record Cluster(String id, String inference, double confidence, List<String> memberIds,
                          List<Evidence> evidence) {
        Reference reference() { return new Reference(id, inference, confidence, memberIds.size()); }
    }

    private record Sample(long time, int sequence, String fingerprint, String capabilityCohort,
                          String bandInvariantCohort, List<String> ssidTokens, boolean association) { }
    private record Sighting(String id, long time, int sequence) { }
    private record Track(String id, Sample first, Sample last, List<Sample> samples, Map<String, Sighting> wps) {
        long firstSeen() {
            long firstProbe = first != null ? first.time() : Long.MAX_VALUE;
            return Math.min(firstProbe, wps.values().stream().mapToLong(Sighting::time).min().orElse(Long.MAX_VALUE));
        }
        boolean hasAssociation() { return samples.stream().anyMatch(Sample::association); }
        Sample firstAssociation() {
            return samples.stream().filter(Sample::association).findFirst().orElse(null);
        }
    }
    private record Choice(Evidence edge, boolean ambiguous) {
        Choice consider(Choice candidate) {
            int candidateRank = basisRank(candidate.edge.basis());
            int currentRank = basisRank(edge.basis());
            if (candidateRank > currentRank) return candidate;
            if (candidateRank < currentRank) return this;
            if ("SEQUENCE_HANDOFF".equals(edge.basis())) {
                if (candidate.edge.sequenceStep() < edge.sequenceStep()) return candidate;
                if (candidate.edge.sequenceStep() == edge.sequenceStep()) return new Choice(edge, true);
                return this;
            }
            return new Choice(edge, true);
        }
    }
    private static int basisRank(String basis) {
        return switch (basis) {
            case "SEQUENCE_HANDOFF" -> 3;
            case "PROBE_TO_ASSOC" -> 2;
            default -> 1;
        };
    }
    private static final Comparator<Sample> SAMPLE_ORDER = Comparator.comparingLong(Sample::time)
            .thenComparingInt(Sample::sequence)
            .thenComparing(Sample::association)
            .thenComparing(Sample::fingerprint, Comparator.nullsFirst(Comparator.naturalOrder()))
            .thenComparing(Sample::capabilityCohort, Comparator.nullsFirst(Comparator.naturalOrder()))
            .thenComparing(Sample::bandInvariantCohort, Comparator.nullsFirst(Comparator.naturalOrder()))
            .thenComparing(sample -> String.join(",", sample.ssidTokens()));

    private static final class AddressSamples {
        final TreeSet<Sample> probes = new TreeSet<>(SAMPLE_ORDER);
        final LinkedHashMap<String, Sighting> wps = new LinkedHashMap<>(16, .75f, true);
    }

    private final SessionIdentifiers ids;
    private final LinkedHashMap<String, AddressSamples> tracks = new LinkedHashMap<>(16, .75f, true);

    ProbeCorrelation(SessionIdentifiers ids) { this.ids = ids; }

    void observe(String id, long time, int sequence, String fingerprint, String ssidToken) {
        observe(id, time, sequence, fingerprint, fingerprint, ssidToken, false);
    }

    void observe(String id, long time, int sequence, String fingerprint, String capabilityCohort,
                 String ssidToken, boolean association) {
        observe(id, time, sequence, fingerprint, capabilityCohort,
                ssidToken == null ? List.of() : List.of(ssidToken), association);
    }

    void observe(String id, long time, int sequence, String fingerprint, String capabilityCohort,
                 List<String> ssidTokens, boolean association) {
        observe(id, time, sequence, fingerprint, capabilityCohort, null, ssidTokens, association);
    }

    void observe(String id, long time, int sequence, String fingerprint, String capabilityCohort,
                 String bandInvariantCohort, List<String> ssidTokens, boolean association) {
        var samples = tracks.computeIfAbsent(id, key -> new AddressSamples()).probes;
        samples.add(new Sample(time, sequence, fingerprint, capabilityCohort, bandInvariantCohort, ssidTokens, association));
        if (samples.size() > PROBE_LIMIT) samples.pollFirst();
        if (tracks.size() > ADDRESS_LIMIT) tracks.pollFirstEntry();
    }

    void observeWps(String id, long time, int sequence, String uuidToken) {
        var wps = tracks.computeIfAbsent(id, key -> new AddressSamples()).wps;
        wps.merge(uuidToken, new Sighting(id, time, sequence),
                (left, right) -> right.time() >= left.time() ? right : left);
        if (wps.size() > PROBE_LIMIT) wps.pollFirstEntry();
        if (tracks.size() > ADDRESS_LIMIT) tracks.pollFirstEntry();
    }

    void remove(String id) { tracks.remove(id); }
    void clear() { tracks.clear(); }

    void purge(long cutoff) {
        tracks.values().removeIf(samples -> {
            var probes = samples.probes;
            while (!probes.isEmpty() && probes.getFirst().time() < cutoff) probes.pollFirst();
            samples.wps.values().removeIf(sighting -> sighting.time() < cutoff);
            return probes.isEmpty() && samples.wps.isEmpty();
        });
    }

    Map<String, Cluster> snapshot() {
        var ordered = tracks.entrySet().stream()
                .map(row -> {
                    var samples = row.getValue();
                    return new Track(row.getKey(), samples.probes.isEmpty() ? null : samples.probes.getFirst(),
                            samples.probes.isEmpty() ? null : samples.probes.getLast(), List.copyOf(samples.probes),
                            samples.wps);
                })
                .sorted(Comparator.comparingLong(Track::firstSeen).thenComparing(Track::id))
                .toList();
        var eligible = ordered.stream().filter(track -> track.first() != null)
                .sorted(Comparator.comparingLong((Track track) -> track.first().time()).thenComparing(Track::id)).toList();
        var outgoing = new HashMap<String, Choice>();
        var incoming = new HashMap<String, Choice>();
        for (int i = 0; i < eligible.size(); i++) {
            var from = eligible.get(i);
            for (int j = i + 1; j < eligible.size(); j++) {
                var to = eligible.get(j);
                long gap = to.first().time() - from.last().time();
                if (gap > MAX_PROFILE_GAP_MS) break;
                if (gap <= 0) continue;
                var evidence = evaluateTransition(from, to, gap);
                if (evidence == null) continue;
                var candidate = new Choice(evidence, false);
                outgoing.merge(from.id(), candidate, Choice::consider);
                incoming.merge(to.id(), candidate, Choice::consider);
            }
        }
        // Keep mutually preferred heuristic transitions. Shared UUIDs also link overlapping tracks.
        var links = new ArrayList<>(wpsEvidence(ordered));
        var wpsClusters = clusters(ordered, links);
        outgoing.forEach((id, choice) -> {
            var edge = choice.edge();
            if (!choice.ambiguous() && choice.equals(incoming.get(edge.toId()))
                    && (wpsClusters.get(id) == null || wpsClusters.get(id) != wpsClusters.get(edge.toId()))) links.add(edge);
        });
        return clusters(ordered, links);
    }

    private static List<Evidence> wpsEvidence(List<Track> ordered) {
        var sightings = new HashMap<String, List<Sighting>>();
        for (Track track : ordered)
            track.wps().forEach((token, seen) -> sightings.computeIfAbsent(token, key -> new ArrayList<>()).add(seen));
        var links = new LinkedHashMap<List<String>, Evidence>();
        for (var addresses : sightings.values()) {
            if (addresses.size() < 2) continue;
            var orderedSightings = addresses.stream()
                    .sorted(Comparator.comparingLong(Sighting::time).thenComparing(Sighting::id))
                    .toList();
            var first = orderedSightings.getFirst();
            for (var next : orderedSightings.subList(1, orderedSightings.size())) {
                int step = (next.sequence() - first.sequence()) & 0xfff;
                long gap = next.time() - first.time();
                var evidence = new Evidence(first.id(), next.id(), step, gap, 0, 0.95, "WPS_UUID_E");
                links.merge(List.of(first.id(), next.id()), evidence,
                        (left, right) -> left.gapMs() <= right.gapMs() ? left : right);
            }
        }
        return List.copyOf(links.values());
    }

    private Map<String, Cluster> clusters(List<Track> ordered, List<Evidence> links) {
        if (links.isEmpty()) return Map.of();
        var position = new HashMap<String, Integer>();
        for (int index = 0; index < ordered.size(); index++) position.put(ordered.get(index).id(), index);
        var adjacent = new HashMap<String, List<Evidence>>();
        for (var edge : links) {
            adjacent.computeIfAbsent(edge.fromId(), key -> new ArrayList<>()).add(edge);
            adjacent.computeIfAbsent(edge.toId(), key -> new ArrayList<>()).add(edge);
        }
        var byMember = new HashMap<String, Cluster>();
        for (var track : ordered) {
            if (!adjacent.containsKey(track.id()) || byMember.containsKey(track.id())) continue;
            var members = new HashSet<String>();
            var evidence = new HashSet<Evidence>();
            var pending = new ArrayDeque<String>();
            pending.add(track.id());
            while (!pending.isEmpty()) {
                String id = pending.removeFirst();
                if (!members.add(id)) continue;
                for (var edge : adjacent.get(id)) {
                    evidence.add(edge);
                    pending.add(edge.fromId().equals(id) ? edge.toId() : edge.fromId());
                }
            }
            var basis = evidence.stream()
                    .sorted(Comparator.comparingInt((Evidence edge) -> position.get(edge.fromId()))
                            .thenComparingInt(edge -> position.get(edge.toId()))
                            .thenComparing(Evidence::basis).thenComparingLong(Evidence::gapMs)).toList();
            double confidence = basis.stream().mapToDouble(Evidence::confidence).min().orElseThrow();
            var cluster = new Cluster(ids.id("probe-correlation", track.id()), INFERENCE, confidence,
                    members.stream().sorted(Comparator.comparingInt(position::get)).toList(), basis);
            members.forEach(id -> byMember.put(id, cluster));
        }
        return byMember;
    }

    private static Evidence evaluateTransition(Track from, Track to, long gap) {
        if (from.hasAssociation()) return null;
        if (to.hasAssociation()) return compareProbeToAssociation(from, to);
        if (gap <= MAX_GAP_MS && from.last().fingerprint() != null
                && from.last().fingerprint().equals(to.first().fingerprint())) {
            Evidence handoff = compare(from, to, gap);
            if (handoff != null) return handoff;
        }
        return comparePnlProfile(from, to, gap);
    }

    private static Evidence compare(Track from, Track to, long gap) {
        int step = (to.first().sequence() - from.last().sequence()) & 0xfff;
        if (step == 0 || step > MAX_SEQUENCE_STEP) return null;
        String fingerprint = from.last().fingerprint();
        var fromNames = directedNames(from, fingerprint);
        var toNames = directedNames(to, fingerprint);
        var shared = new HashSet<>(fromNames);
        shared.retainAll(toNames);
        if (shared.isEmpty()) {
            if (!fromNames.isEmpty() && !toNames.isEmpty()) return null;
            if (gap > CLOSE_GAP_MS || step > 4 || !repeated(from, fingerprint) || !repeated(to, fingerprint)) return null;
        }
        // Weighted evidence score, deliberately capped below 1. It is not a calibrated probability.
        int points = 40 + (step <= 4 ? 25 : 15) + (gap <= CLOSE_GAP_MS ? 15 : 10) + (shared.isEmpty() ? 0 : 10);
        return new Evidence(from.id(), to.id(), step, gap, shared.size(), points / 100.0, "SEQUENCE_HANDOFF");
    }

    private static Evidence compareProbeToAssociation(Track from, Track to) {
        Sample assoc = to.firstAssociation();
        if (assoc == null || assoc.ssidTokens().isEmpty()) return null;
        long gap = assoc.time() - from.last().time();
        if (gap > MAX_ASSOC_GAP_MS) return null;
        boolean exact = sameFingerprint(from.last().capabilityCohort(), assoc.capabilityCohort());
        Function<Sample, String> cohortKey = exact ? Sample::capabilityCohort : Sample::bandInvariantCohort;
        String cohort = cohortKey.apply(from.last());
        if (!sameFingerprint(cohort, cohortKey.apply(assoc))) return null;
        boolean probedSsid = from.samples().stream().anyMatch(sample ->
                !sample.association() && cohort.equals(cohortKey.apply(sample))
                        && sample.ssidTokens().contains(assoc.ssidTokens().getFirst()));
        if (!probedSsid) return null;
        int step = (assoc.sequence() - from.last().sequence()) & 0xfff;
        boolean close = step > 0 && step <= 32 && gap <= MAX_GAP_MS;
        double confidence = exact ? (close ? 0.82 : 0.72) : (close ? 0.78 : 0.70);
        return new Evidence(from.id(), to.id(), step, gap, 1, confidence, "PROBE_TO_ASSOC");
    }

    private static Evidence comparePnlProfile(Track from, Track to, long gap) {
        if (gap > MAX_PROFILE_GAP_MS) return null;
        boolean exact = sameFingerprint(from.last().fingerprint(), to.first().fingerprint());
        Function<Sample, String> cohortKey = exact ? Sample::fingerprint : Sample::bandInvariantCohort;
        String cohort = cohortKey.apply(from.last());
        if (!sameFingerprint(cohort, cohortKey.apply(to.first()))) return null;
        var fromNames = directedNames(from, cohort, cohortKey);
        var toNames = directedNames(to, cohort, cohortKey);
        if (fromNames.size() < 2 || !fromNames.equals(toNames)) return null;
        int step = (to.first().sequence() - from.last().sequence()) & 0xfff;
        double confidence = exact ? Math.min(0.78, 0.58 + 0.05 * fromNames.size())
                : Math.min(0.70, 0.54 + 0.05 * fromNames.size());
        return new Evidence(from.id(), to.id(), step, gap, fromNames.size(), confidence, "PNL_PROFILE");
    }

    private static HashSet<String> directedNames(Track track, String fingerprint) {
        return directedNames(track, fingerprint, Sample::fingerprint);
    }

    private static HashSet<String> directedNames(Track track, String cohort,
                                                 Function<Sample, String> cohortKey) {
        var names = new HashSet<String>();
        for (var sample : track.samples()) {
            if (cohort.equals(cohortKey.apply(sample))) names.addAll(sample.ssidTokens());
        }
        return names;
    }

    private static boolean sameFingerprint(String left, String right) {
        return left != null && left.equals(right);
    }

    private static boolean repeated(Track track, String fingerprint) {
        return track.samples().stream().filter(sample -> fingerprint.equals(sample.fingerprint()))
                .map(Sample::sequence).distinct().limit(2).count() == 2;
    }
}
