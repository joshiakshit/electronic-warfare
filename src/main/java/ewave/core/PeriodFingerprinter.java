package ewave.core;

import java.util.List;

final class PeriodFingerprinter {
    private PeriodFingerprinter() {}

    static String hint(int periodTicks, double millis) {
        if (periodTicks == 0) return "Transient / mobile";
        // Wi-Fi beacon intervals take precedence where they overlap the BLE range.
        if (millis >= 85 && millis <= 115) return "802.11 AP (beacon cycle)";
        if (millis >= 200 && millis <= 210) return "802.11 AP (long interval)";
        if (millis >= 1200 && millis <= 1300) return "Apple background scan";
        if (millis >= 5000 && millis <= 8000) return "IoT sensor / sleeping device";
        if (millis >= 100 && millis <= 200) return "BLE advertiser";
        if (millis > 0 && millis < 50) return "Active client / high-frequency beacon";
        return "Unclassified";
    }

    /** Normalize the fit's likelihood against the constant-occupancy model. */
    static double confidence(List<PeriodFit.Sample> samples, int period) {
        double gain = PeriodFit.likelihood(samples, period) - PeriodFit.likelihood(samples, 1);
        return 1 / (1 + Math.exp(-gain));
    }
}
