package ewave.core;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class AnomalyClockTest {
    private static final Instant FIXED = Instant.parse("2025-01-02T03:04:05Z");

    private static Clock fixedClock() {
        return Clock.fixed(FIXED, ZoneOffset.UTC);
    }

    @Test void detectorStampsPeriodBreakFromInjectedClock() {
        var detector = new AnomalyDetector(60, fixedClock());
        detector.observe(1, false, 10, 0);
        assertNotNull(detector.active());
        assertEquals("PERIOD_BROKEN", detector.active().reason());
        assertEquals(FIXED, detector.active().detectedAt());
    }

    @Test void detectorStampsNewActivityFromInjectedClock() {
        var detector = new AnomalyDetector(60, fixedClock());
        for (int i = 0; i < 30; i++) detector.observe(1, false, 10, 10);
        detector.observe(1, true, 10, 10);
        assertNotNull(detector.active());
        assertEquals("NEW_ACTIVITY", detector.active().reason());
        assertEquals(FIXED, detector.active().detectedAt());
    }

    @Test void scannerReportsAnomaliesAtInjectedClockTime() {
        var scanner = new AdaptiveScanner(AdaptiveScanner.Config.defaults(13, 128, 7), 60, fixedClock());
        for (int tick = 0; tick < 60; tick++) scanner.observe(0, tick, false);
        scanner.observe(0, 60, true);
        var flag = scanner.snapshot(60).anomalies().get(1);
        assertNotNull(flag);
        assertEquals(FIXED, flag.detectedAt());
    }
}
