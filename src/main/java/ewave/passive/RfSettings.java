package ewave.passive;

import java.util.concurrent.TimeUnit;

final class RfSettings {
    private RfSettings() { }

    static int integer(String property, int fallback, int min, int max) {
        int value = Integer.parseInt(System.getProperty(property, Integer.toString(fallback)));
        if (value < min || value > max) throw new IllegalArgumentException(property + " must be in " + min + ".." + max);
        return value;
    }

    static long retentionMillis() {
        return TimeUnit.HOURS.toMillis(integer("audit.retentionHours", 24, 1, 168));
    }
}
