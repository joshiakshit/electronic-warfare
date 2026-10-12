package ewave;

import java.util.*;

/** Only the period-fitting path reachable from the phase scheduler. */
final class PeriodFit {
    record Sample(long tick, boolean detection) {}

    static final class History {
        private final Sample[] buffer;
        private int cursor, size;
        History(int capacity) { buffer = new Sample[capacity]; }
        void append(long tick, boolean detection) {
            buffer[cursor] = new Sample(tick, detection);
            cursor = (cursor + 1) % buffer.length;
            size = Math.min(size + 1, buffer.length);
        }
        List<Sample> recent() {
            var result = new ArrayList<Sample>(size);
            int start = size == buffer.length ? cursor : 0;
            for (int i = 0; i < size; i++) result.add(buffer[(start + i) % buffer.length]);
            return result;
        }
    }

    // Integer Beta(1,10) parameters permit log-factorials instead of lgamma.
    static double likelihood(List<Sample> samples, int period) {
        int[] observations = new int[period], hits = new int[period];
        for (var sample : samples) {
            int phase = (int)(sample.tick() % period);
            observations[phase]++;
            if (sample.detection()) hits[phase]++;
        }
        double[] factorial = new double[samples.size() + 11];
        for (int i = 2; i < factorial.length; i++) factorial[i] = factorial[i - 1] + Math.log(i);
        double prior = factorial[9] - factorial[10], score = 0;
        for (int phase = 0; phase < period; phase++) {
            int n = observations[phase], h = hits[phase];
            if (n > 0) score += factorial[h] + factorial[9 + n - h] - factorial[10 + n] - prior;
        }
        return score;
    }

    static Set<Integer> gapCandidates(List<Sample> samples, int maxPeriod) {
        List<Long> hits = samples.stream().filter(Sample::detection).map(Sample::tick).toList();
        // LinkedHashMap preserves the Python count dictionary's insertion order on ties.
        Map<Integer, Integer> counts = new LinkedHashMap<>();
        for (int i = 0; i < hits.size(); i++) {
            for (int j = i + 1; j < Math.min(i + Math.min(hits.size(), 30), hits.size()); j++) {
                long gap = hits.get(j) - hits.get(i);
                if (gap < 2) continue;
                if (gap <= maxPeriod) add(counts, gap, maxPeriod);
                // Divisors above maxPeriod cannot contribute. Check quotients as well.
                for (long d = 2; d <= gap / d && d <= maxPeriod; d++) {
                    if (gap % d == 0) { add(counts, d, maxPeriod); add(counts, gap / d, maxPeriod); }
                }
            }
        }
        var ranked = counts.keySet().stream().sorted((a,b) -> Integer.compare(counts.get(b), counts.get(a))).limit(48).toList();
        Set<Integer> result = new TreeSet<>(ranked);
        for (int p : ranked.stream().limit(12).toList()) {
            for (int delta : new int[]{-2,-1,1,2}) if (p + delta >= 2 && p + delta <= maxPeriod) result.add(p + delta);
        }
        return result;
    }
    private static void add(Map<Integer,Integer> counts, long period, int max) {
        if (period >= 2 && period <= max) counts.merge((int)period, 1, Integer::sum);
    }

    static int fit(List<Sample> samples, int minHits, int maxPeriod) {
        int hits = (int)samples.stream().filter(Sample::detection).count();
        if (hits < minHits || samples.size() < 10 || hits / (double)samples.size() > .8) return 0;
        int highest = (int)Math.min(maxPeriod, (samples.getLast().tick() - samples.getFirst().tick() + 1) / 3);
        if (highest < 2) return 0;
        double nullScore = likelihood(samples, 1), best = Double.NEGATIVE_INFINITY, second = best;
        int period = 0;
        for (int candidate : gapCandidates(samples, highest)) {
            double margin = likelihood(samples, candidate) - nullScore;
            if (margin > best) { second = best; best = margin; period = candidate; }
            else if (margin > second) second = margin;
        }
        return best < 3.5 || best - second < .5 ? 0 : period;
    }

    /** Exact sparse form of the centered binary series' direct autocorrelation.
     * Missing ticks are zeros, matching the reference FFT input. No span-sized allocation.
     */
    static int[] autocorrelationCandidates(List<Sample> samples, int maxPeriod) {
        long first = samples.getFirst().tick(), span = samples.getLast().tick() - first + 1;
        int highest = (int)Math.min(maxPeriod, span / 3);
        if (span < 12 || highest < 2) return new int[0];
        Set<Long> hits = new HashSet<>();
        for (var s : samples) if (s.detection()) hits.add(s.tick() - first);
        double mean = hits.size() / (double)span;
        double[] correlation = new double[highest + 1];
        List<Integer> lags = new ArrayList<>();
        for (int lag = 2; lag <= highest; lag++) {
            int pairs = 0, left = 0, right = 0;
            for (long hit : hits) {
                if (hit < span - lag) left++;
                if (hit >= lag) right++;
                if (hits.contains(hit + lag)) pairs++;
            }
            correlation[lag] = pairs - mean * (left + right) + (span - lag) * mean * mean;
            lags.add(lag);
        }
        // FFT roundoff can reorder exactly equal peaks; choose the larger lag on exact ties.
        lags.sort((a,b) -> { int c = Double.compare(correlation[b], correlation[a]); return c != 0 ? c : Integer.compare(b,a); });
        Set<Integer> candidates = new TreeSet<>();
        for (int lag : lags.stream().limit(4).toList()) {
            candidates.add(lag);
            if (lag % 2 == 0 && lag / 2 >= 2) candidates.add(lag / 2);
        }
        return candidates.stream().mapToInt(Integer::intValue).toArray();
    }
}
