package ewave;

import java.util.*;

/** Embeddable single-threaded scheduler. Inputs contain receiver observations only.
 * Ticks represent a caller-defined fixed elapsed-time cadence, never request counts.
 */
public final class AdaptiveScanner {
    public record Config(int bands, int capacity, int refitInterval, int minHits,
                         int smoothing, double priorStrength, int maxPeriod,
                         double pd, double pfa, double surveyWeight, double surveyDuty,
                         double optimism, long seed) {
        public Config {
            if (bands <= 0 || capacity < 10 || refitInterval <= 0 || minHits < 3 || minHits > capacity
                    || smoothing < 0 || maxPeriod < 2) throw new IllegalArgumentException("Invalid dimensions or fitting parameters");
            if (!Double.isFinite(priorStrength) || priorStrength <= 0
                    || !probability(pd) || !probability(pfa) || pd <= pfa
                    || !Double.isFinite(surveyWeight) || surveyWeight < 0 || !probability(surveyDuty)
                    || !Double.isFinite(optimism) || optimism < 0) throw new IllegalArgumentException("Invalid detector or model assumptions");
        }
        private static boolean probability(double v) { return Double.isFinite(v) && v >= 0 && v <= 1; }
        public static Config defaults(int bands, int capacity, long seed) {
            return new Config(bands,capacity,48,6,1,4,200,.9,.01,.3,.03,1,seed);
        }
    }
    /** Scores include optimism and may exceed one; they are not probabilities. Zero period means no fit. */
    public record Snapshot(long tick, double[] means, double[] spreads, double[] scores,
                           int[] periods, long[] counts, int coupledPeriod, int[] coupledMembers) {
        public Snapshot {
            means = means.clone(); spreads = spreads.clone(); scores = scores.clone();
            periods = periods.clone(); counts = counts.clone(); coupledMembers = coupledMembers.clone();
        }
        @Override public double[] means() { return means.clone(); }
        @Override public double[] spreads() { return spreads.clone(); }
        @Override public double[] scores() { return scores.clone(); }
        @Override public int[] periods() { return periods.clone(); }
        @Override public long[] counts() { return counts.clone(); }
        @Override public int[] coupledMembers() { return coupledMembers.clone(); }
    }
    public record Decision(long tick, int[] bands, Snapshot snapshot) {
        public Decision { bands = bands.clone(); }
        @Override public int[] bands() { return bands.clone(); }
    }

    private final Config config;
    private PhaseModel model;
    private Random random;
    private long latestTick;
    private final long[] feedbackTicks;
    public AdaptiveScanner(Config config) {
        this.config = Objects.requireNonNull(config);
        feedbackTicks = new long[config.bands()];
        reset();
    }
    /** Start a new independent session, including a fresh seeded tie-breaking stream. */
    public void reset() {
        model = new PhaseModel(config); random = new Random(config.seed()); latestTick = -1;
        Arrays.fill(feedbackTicks,-1);
    }
    public Config config() { return config; }
    public void observe(int band, long tick, boolean detection) { observe(band,tick,detection,true); }
    /** Unavailable measurements advance feedback chronology but never become negative detections. */
    public void observe(int band, long tick, boolean detection, boolean valid) {
        if (band < 0 || band >= config.bands()) throw new IllegalArgumentException("Unknown band: " + band);
        checkTick(tick);
        if (tick < latestTick || tick <= feedbackTicks[band]) throw new IllegalArgumentException("Stale or duplicate feedback");
        if (valid) model.observe(band,tick,detection);
        feedbackTicks[band] = tick; latestTick = tick;
    }
    public Snapshot snapshot(long tick) {
        checkTick(tick);
        double[] means = new double[config.bands()], spreads = means.clone(), scores = means.clone();
        int[] periods = new int[config.bands()];
        for (int band = 0; band < config.bands(); band++) {
            double[] posterior = model.posterior(band,tick);
            means[band] = posterior[0]; spreads[band] = posterior[1];
            scores[band] = model.score(band,tick); periods[band] = model.period(band);
        }
        return new Snapshot(tick,means,spreads,scores,periods,model.counts(),model.coupledPeriod(),model.members());
    }
    /** Select distinct bands in rank order. Near ties use uniform seeded Java randomness.
     * Same seed numbers do not reproduce NumPy's random stream.
     */
    public Decision choose(long tick, int k) {
        return choose(tick,k,null);
    }
    /** Optional receiver-visible priority weights, with the reference's 0.1 floor.
     * Null uses uniform unit weights, removing only the reference's common 0.1 scale.
     */
    public Decision choose(long tick, int k, double[] priorityWeights) {
        checkTick(tick);
        if (tick <= latestTick) throw new IllegalArgumentException("Selection tick must follow feedback");
        if (k < 1 || k > config.bands()) throw new IllegalArgumentException("Invalid selection count");
        Snapshot snapshot = snapshot(tick);
        double[] scores = snapshot.scores();
        if (priorityWeights != null) {
            if (priorityWeights.length != config.bands()) throw new IllegalArgumentException("Priority weight count must match bands");
            double[] weights = priorityWeights.clone();
            for (int b = 0; b < weights.length; b++) {
                if (!Double.isFinite(weights[b]) || weights[b] < 0) throw new IllegalArgumentException("Priority weights must be finite and nonnegative");
                scores[b] *= Math.max(.1,weights[b]);
                if (!Double.isFinite(scores[b])) throw new IllegalArgumentException("Weighted score overflow");
            }
            snapshot = new Snapshot(tick,snapshot.means(),snapshot.spreads(),scores,snapshot.periods(),snapshot.counts(),snapshot.coupledPeriod(),snapshot.coupledMembers());
        }
        int[] selected = new int[k];
        for (int i = 0; i < k; i++) {
            double max = Arrays.stream(scores).max().orElseThrow();
            List<Integer> ties = new ArrayList<>();
            for (int b = 0; b < scores.length; b++) if (Double.isFinite(scores[b]) && Math.abs(scores[b] - max) <= 1e-12 + 1e-12 * Math.abs(max)) ties.add(b);
            int pick = ties.size() == 1 ? ties.getFirst() : ties.get(random.nextInt(ties.size()));
            selected[i] = pick; scores[pick] = Double.NEGATIVE_INFINITY;
        }
        return new Decision(tick,selected,snapshot);
    }
    private static void checkTick(long tick) {
        if (tick < 0 || tick == Long.MAX_VALUE) throw new IllegalArgumentException("Tick must be nonnegative and leave room for the next tick");
    }
    // Package-private diagnostic used to verify the numerical fitting gate.
    double likelihood(int band) { return model.likelihood(band); }
}
