package ewave.core;

import java.util.List;

final class PeriodFingerprinter {
    private PeriodFingerprinter() {}

    static String hint(int periodTicks, double millis) {
        if (periodTicks == 0) return "Transient / mobile";
        if (millis > 0 && millis < 50) return "Active client / high-frequency beacon";
        if (millis >= 80 && millis <= 125) return "802.11 AP (beacon cycle)";
        if (millis >= 195 && millis <= 220) return "802.11 AP (long interval)";
        if (millis >= 290 && millis <= 330) return "802.11 AP / IoT (300 TU cycle)";
        if (millis >= 980 && millis <= 1060) return "IoT / DTIM sleep cycle (1s)";
        if (millis >= 2000 && millis <= 8000) return "IoT sensor / sleeping device";
        return "Unclassified";
    }

    /** Normalize the fit's likelihood against the constant-occupancy model. */
    static double confidence(List<PeriodFit.Sample> samples, int period) {
        double gain = PeriodFit.likelihood(samples, period) - PeriodFit.likelihood(samples, 1);
        return 1 / (1 + Math.exp(-gain));
    }
}
