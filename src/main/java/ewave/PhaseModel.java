package ewave;

import java.util.*;

/** Phase occupancy, adjacent-state recency, Wilson exploration and coupled inference. */
final class PhaseModel {
    private final AdaptiveScanner.Config config;
    private final PeriodFit.History[] history;
    private final long[] counts, hits, sinceRefit, lastTick;
    private final boolean[] lastDetection;
    private final double[] n00, n01, n11, n10;
    private final int[] periods;
    private final double[][] phaseObservations, phaseHits;
    private final int[][] longCandidates;
    private int coupledPeriod;
    private int[] members = new int[0];
    private double[][] coupledLogLikelihood;
    private long[] coupledEvidence, surveyCounts;

    PhaseModel(AdaptiveScanner.Config config) {
        this.config = config;
        int n = config.bands();
        history = new PeriodFit.History[n];
        for (int b = 0; b < n; b++) history[b] = new PeriodFit.History(config.capacity());
        counts = new long[n]; hits = new long[n]; sinceRefit = new long[n]; lastTick = new long[n];
        Arrays.fill(lastTick, -1);
        lastDetection = new boolean[n];
        n00 = filled(n,9); n01 = filled(n,1); n11 = filled(n,9); n10 = filled(n,1);
        periods = new int[n]; phaseObservations = new double[n][]; phaseHits = new double[n][];
        longCandidates = new int[n][];
        Arrays.setAll(longCandidates, b -> new int[0]);
    }
    private static double[] filled(int n, double value) { double[] a = new double[n]; Arrays.fill(a,value); return a; }

    void observe(int band, long tick, boolean detection) {
        history[band].append(tick,detection);
        counts[band]++;
        if (detection) hits[band]++;
        if (tick - lastTick[band] == 1) {
            double[] target = lastDetection[band] ? (detection ? n11 : n10) : (detection ? n01 : n00);
            target[band]++;
        }
        lastTick[band] = tick; lastDetection[band] = detection;
        if (periods[band] != 0) {
            int phase = (int)(tick % periods[band]);
            phaseObservations[band][phase]++;
            if (detection) phaseHits[band][phase]++;
        }
        sinceRefit[band]++;
        boolean rebuilt = false;
        if (sinceRefit[band] >= Math.max(config.refitInterval(), counts[band] / 4) && hits[band] >= config.minHits()) {
            refit(band);
            rebuilt = refreshCoupledGroup();
        }
        if (!rebuilt) updateCoupled(band,tick,detection);
    }

    private void refit(int band) {
        sinceRefit[band] = 0;
        var samples = history[band].recent();
        int period = PeriodFit.fit(samples,config.minHits(),config.maxPeriod());
        int[] candidates = PeriodFit.autocorrelationCandidates(samples,Math.max(280,config.maxPeriod()));
        longCandidates[band] = Arrays.stream(candidates).filter(p -> p >= 201).toArray();
        double nullScore = PeriodFit.likelihood(samples,1), bestMargin = Double.NEGATIVE_INFINITY;
        int best = 0;
        for (int p : candidates) if (p <= config.maxPeriod()) {
            double margin = PeriodFit.likelihood(samples,p) - nullScore;
            if (margin > bestMargin) { bestMargin = margin; best = p; }
        }
        double standing = period == 0 ? Double.NEGATIVE_INFINITY : PeriodFit.likelihood(samples,period) - nullScore;
        if (bestMargin > Math.max(standing,3.5)) period = best;
        periods[band] = period;
        phaseObservations[band] = period == 0 ? null : new double[period];
        phaseHits[band] = period == 0 ? null : new double[period];
        if (period != 0) for (var sample : samples) {
            int phase = (int)(sample.tick() % period);
            phaseObservations[band][phase]++;
            if (sample.detection()) phaseHits[band][phase]++;
        }
    }

    private int[] compatibleMembers(int seed, int period) {
        List<Set<Integer>> supports = new ArrayList<>();
        for (var h : history) {
            Set<Integer> support = new HashSet<>();
            for (var s : h.recent()) if (s.detection()) support.add((int)(s.tick() % period));
            supports.add(support);
        }
        List<Integer> selected = new ArrayList<>(List.of(seed)), candidates = new ArrayList<>();
        for (int b = 0; b < history.length; b++) if (b != seed) candidates.add(b);
        candidates.sort((a,b) -> Long.compare(hits[b],hits[a]));
        for (int b : candidates) {
            double rate = hits[b] / (double)counts[b];
            if (counts[b] < 8 || hits[b] == 0 || rate < .05 || rate > .6) continue;
            int fitted = periods[b];
            if (fitted != 0 && period % fitted != 0 && fitted % period != 0) continue;
            if (selected.stream().anyMatch(member -> !Collections.disjoint(supports.get(b),supports.get(member)))) continue;
            selected.add(b);
        }
        double rate = selected.stream().mapToDouble(b -> hits[b] / (double)counts[b]).sum();
        if (selected.size() < 3 || rate < .45 || rate > 1.35) return new int[0];
        return selected.stream().sorted().mapToInt(Integer::intValue).toArray();
    }
    private boolean refreshCoupledGroup() {
        double bestMargin = Double.NEGATIVE_INFINITY;
        int bestPeriod = 0;
        int[] bestMembers = new int[0];
        for (int seed = 0; seed < history.length; seed++) {
            Set<Integer> proposals = new TreeSet<>();
            for (int p : longCandidates[seed]) proposals.add(p);
            if (periods[seed] >= 201) proposals.add(periods[seed]);
            for (int p : proposals) {
                int[] group = compatibleMembers(seed,p);
                if (group.length == 0) continue;
                double margin = coupledMargin(group,p);
                // Python max orders tuples by margin, period, then member tuple.
                if (margin > bestMargin || margin == bestMargin && (p > bestPeriod || p == bestPeriod && Arrays.compare(group,bestMembers) > 0)) {
                    bestMargin = margin; bestPeriod = p; bestMembers = group;
                }
            }
        }
        if (bestMargin < 10 || bestPeriod == coupledPeriod && Arrays.equals(bestMembers,members)) return false;
        if (coupledPeriod == 0) surveyCounts = counts.clone();
        coupledPeriod = bestPeriod; members = bestMembers;
        coupledLogLikelihood = new double[coupledPeriod][members.length];
        coupledEvidence = new long[coupledPeriod];
        for (int b : members) for (var s : history[b].recent()) updateCoupled(b,s.tick(),s.detection());
        return true;
    }
    private double coupledMargin(int[] group, int period) {
        double[] observations = new double[period], totalHits = new double[period];
        double[][] memberObservations = new double[group.length][period], memberHits = new double[group.length][period];
        double nullScore = 0;
        for (int i = 0; i < group.length; i++) {
            var samples = history[group[i]].recent();
            int h = 0;
            for (var s : samples) {
                int phase = (int)(s.tick() % period);
                observations[phase]++; memberObservations[i][phase]++;
                if (s.detection()) { totalHits[phase]++; memberHits[i][phase]++; h++; }
            }
            double rate = (h + .5) / (samples.size() + 1.0);
            nullScore += h * Math.log(rate) + (samples.size() - h) * Math.log(1 - rate);
        }
        double hitDelta = log(config.pd()) - log(config.pfa());
        double missDelta = log(1 - config.pd()) - log(1 - config.pfa());
        double score = 0;
        for (int phase = 0; phase < period; phase++) if (observations[phase] > 0) {
            double base = totalHits[phase] * log(config.pfa()) + (observations[phase] - totalHits[phase]) * log(1 - config.pfa());
            double[] row = new double[group.length];
            for (int i = 0; i < row.length; i++) row[i] = base + memberHits[i][phase] * hitDelta + (memberObservations[i][phase] - memberHits[i][phase]) * missDelta;
            double max = Arrays.stream(row).max().orElseThrow(), sum = 0;
            for (double v : row) sum += Math.exp(v - max);
            score += max + Math.log(sum) - Math.log(group.length);
        }
        return score - nullScore;
    }
    private static double log(double value) { return Math.log(Math.max(value,1e-12)); }
    private void updateCoupled(int band, long tick, boolean detection) {
        int index = Arrays.binarySearch(members,band);
        if (coupledPeriod == 0 || index < 0) return;
        int phase = (int)(tick % coupledPeriod);
        double other = log(detection ? config.pfa() : 1 - config.pfa());
        double selected = log(detection ? config.pd() : 1 - config.pd());
        for (int i = 0; i < members.length; i++) coupledLogLikelihood[phase][i] += other;
        coupledLogLikelihood[phase][index] += selected - other;
        coupledEvidence[phase]++;
    }
    private double[] coupledPosterior(int band, long tick) {
        int index = Arrays.binarySearch(members,band);
        if (coupledPeriod == 0 || index < 0) return null;
        int phase = (int)(tick % coupledPeriod);
        double[] row = coupledLogLikelihood[phase];
        double max = Arrays.stream(row).max().orElseThrow(), sum = 0;
        for (double value : row) sum += Math.exp(value - max);
        double holder = Math.exp(row[index] - max) / sum;
        double mean = holder * config.pd() + (1 - holder) * config.pfa();
        return new double[]{mean, Math.sqrt(mean * (1 - mean) / (coupledEvidence[phase] + 1.0))};
    }

    private double[] phaseEvidence(int band, long tick) {
        int period = periods[band];
        if (period == 0) return new double[]{hits[band],counts[band]};
        int phase = (int)(tick % period);
        if (phaseObservations[band][phase] > 0) return new double[]{phaseHits[band][phase],phaseObservations[band][phase]};
        int width = Math.min(config.smoothing(),(period - 1) / 2);
        double h = 0, n = 0;
        for (int delta = -width; width > 0 && delta <= width; delta++) {
            int p = Math.floorMod(phase + delta,period);
            h += phaseHits[band][p]; n += phaseObservations[band][p];
        }
        return new double[]{h,n};
    }
    double[] posterior(int band, long tick) {
        double[] coupled = coupledPosterior(band,tick);
        if (coupled != null) return coupled;
        double marginal = (hits[band] + .5) / (counts[band] + 1.0);
        double[] evidence = phaseEvidence(band,tick);
        double mean = (evidence[0] + config.priorStrength() * marginal) / (evidence[1] + config.priorStrength());
        double spread = Math.sqrt(mean * (1 - mean) / (evidence[1] + 1));
        long gap = tick - lastTick[band];
        double decay = 1 - n01[band] / (n00[band] + n01[band]) - n10[band] / (n11[band] + n10[band]);
        if (periods[band] != 0 || lastTick[band] < 0 || gap < 1 || decay <= 0) return new double[]{mean,spread};
        double weight = Math.pow(decay,gap);
        if (weight <= 0) return new double[]{mean,spread};
        double span = config.pd() - config.pfa();
        double prior = span > 1e-12 ? Math.min(1,Math.max(0,(mean - config.pfa()) / span)) : mean;
        double on = lastDetection[band] ? config.pd() : 1 - config.pd();
        double off = lastDetection[band] ? config.pfa() : 1 - config.pfa();
        double denominator = on * prior + off * (1 - prior);
        double posterior = denominator > 1e-12 ? on * prior / denominator : prior;
        double now = prior + (posterior - prior) * weight;
        return new double[]{now * config.pd() + (1 - now) * config.pfa(),spread};
    }
    double score(int band, long tick) {
        double[] coupled = coupledPosterior(band,tick);
        if (coupled != null) return coupled[0] + config.optimism() * coupled[1];
        double[] evidence = phaseEvidence(band,tick);
        double h = evidence[0], n = evidence[1], z = config.optimism();
        if (n <= 0) return 1;
        double wilson = z / (n + z*z) * Math.sqrt(h * (n - h) / n + .25*z*z);
        double survey = hits[band] > 0 ? 0 : config.surveyWeight() * Math.pow(1 - config.surveyDuty(),counts[band]);
        if (surveyCounts != null && hits[band] == 0 && counts[band] <= surveyCounts[band]) return 2;
        return posterior(band,tick)[0] + wilson + survey;
    }
    int period(int band) { return periods[band]; }
    int coupledPeriod() { return coupledPeriod; }
    int[] members() { return members.clone(); }
    long[] counts() { return counts.clone(); }
    double likelihood(int band) { return PeriodFit.likelihood(history[band].recent(),Math.max(1,periods[band])); }
}
