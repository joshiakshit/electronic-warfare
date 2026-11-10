package ewave.core;

import java.util.List;

final class PeriodFingerprinter {
    private PeriodFingerprinter() {}

    static String hint(int periodTicks, double millis) {
        if (periodTicks == 0) return "Transient / mobile";
        if (millis >= 85 && millis <= 115) return "802.11 AP (beacon cycle)";
        if (millis >= 200 && millis <= 210) return "802.11 AP (long interval)";
        if (millis >= 5000 && millis <= 8000) return "IoT sensor / sleeping device";
        if (millis > 0 && millis < 50) return "Active client / high-frequency beacon";
        return "Unclassified";
    }

    /** Normalize the fit's likelihood against the constant-occupancy model. */
    static double confidence(List<PeriodFit.Sample> samples, int period) {
        double gain = PeriodFit.likelihood(samples, period) - PeriodFit.likelihood(samples, 1);
        return 1 / (1 + Math.exp(-gain));
    }
}
