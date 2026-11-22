package ewave.capture;

import ewave.decoder.Dot11Frame;
import ewave.decoder.Dot11FrameDecoder;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/** Monitor capture counters. Packet content is never retained. */
public final class CaptureHealth {
    private static final int WINDOW_SECONDS = 10;
    private static final int DIAGNOSTIC_LIMIT = 200;
    private static final String[] TYPES = {"management", "control", "data", "other", "unclassified"};
    private static final Pattern DROPS = Pattern.compile("(?:^|\\s)([0-9]+) packets? dropped by kernel");
    private static final Pattern ROUTINE = Pattern.compile(
            "(?i)^(?:tcpdump:\\s*)?(?:listening on\\b|verbose output suppressed\\b|[0-9]+ packets? (?:captured|received by filter)\\b)");
    private final long[] totals = new long[TYPES.length];
    private final long[][] buckets = new long[WINDOW_SECONDS][TYPES.length];
    private final long[] bucketTimes = new long[WINDOW_SECONDS];
    private long decoded, rejected, unsupported, truncated;
    private Long lastPacketAt, lastReceivedAt, kernelDrops, dropStatsAt;
    private int observedFrequencyMhz;
    private RadioStatus.Settings radio;
    private String diagnosticError;

    public record Report(String mode, String source, boolean running, String replayState, String error,
                         Long referenceTime, Long lastPacketAt, Long sinceLastFrameMs, RadioStatus.Settings radio,
                         int observedFrequencyMhz, int observedChannel, int rateWindowSeconds,
                         Map<String, Long> frameCounts, Map<String, Double> framesPerSecond,
                         long decoded, long rejected, long unsupported, long truncated,
                         Long kernelDrops, Long dropStatsAt) { }

    CaptureHealth() { Arrays.fill(bucketTimes, Long.MIN_VALUE); }

    void record(int control, boolean complete, Dot11Frame frame, long capturedAt, long receivedAt, long rateTime) {
        int type = control < 0 ? 4 : (control >>> 2) & 3;
        totals[type]++;
        long second = Math.floorDiv(rateTime, 1000);
        int bucket = Math.floorMod(second, WINDOW_SECONDS);
        if (bucketTimes[bucket] < second) {
            Arrays.fill(buckets[bucket], 0);
            bucketTimes[bucket] = second;
        }
        if (bucketTimes[bucket] == second) buckets[bucket][type]++;
        if (lastPacketAt == null || capturedAt >= lastPacketAt) {
            lastPacketAt = capturedAt;
            if (frame != null && frame.frequencyMhz() > 0) observedFrequencyMhz = frame.frequencyMhz();
        }
        lastReceivedAt = receivedAt;
        if (!complete) truncated++;
        else if (frame != null) decoded++;
        else if (control >= 0 && !Dot11FrameDecoder.supportedFrameControl(control)) unsupported++;
        else rejected++;
    }

    void updateRadio(RadioStatus.Settings value) { radio = value; }
    int observedChannel() { return Dot11FrameDecoder.channel(observedFrequencyMhz); }
    int observedFrequencyMhz() { return observedFrequencyMhz; }
    String diagnosticError() { return diagnosticError; }
    boolean diagnostics(String line, long now) {
        var matcher = DROPS.matcher(line);
        if (matcher.find()) {
            try {
                kernelDrops = Long.parseLong(matcher.group(1));
                dropStatsAt = now;
            } catch (NumberFormatException ignored) { /* Leave the previous sample intact. */ }
            return true;
        }
        String cleaned = sanitize(line);
        if (!cleaned.isEmpty() && !ROUTINE.matcher(cleaned).find() && diagnosticError == null) {
            diagnosticError = cleaned.length() > DIAGNOSTIC_LIMIT
                    ? cleaned.substring(0, DIAGNOSTIC_LIMIT) + "…"
                    : cleaned;
        }
        return false;
    }

    private static String sanitize(String line) {
        if (line == null) return "";
        var text = new StringBuilder(line.length());
        for (int i = 0; i < line.length(); i++) {
            char ch = line.charAt(i);
            if (!Character.isISOControl(ch)) text.append(ch);
        }
        return text.toString().strip();
    }

    Report snapshot(String mode, String source, boolean running, String replayState, String error,
                    Long referenceTime, long now, long rateTime) {
        long second = Math.floorDiv(rateTime, 1000);
        var counts = new LinkedHashMap<String, Long>();
        var rates = new LinkedHashMap<String, Double>();
        for (int type = 0; type < TYPES.length; type++) {
            counts.put(TYPES[type], totals[type]);
            long recent = 0;
            for (int i = 0; i < WINDOW_SECONDS; i++)
                if (bucketTimes[i] > second - WINDOW_SECONDS && bucketTimes[i] <= second) recent += buckets[i][type];
            rates.put(TYPES[type], recent / (double) WINDOW_SECONDS);
        }
        return new Report(mode, source, running, replayState, error, referenceTime, lastPacketAt,
                lastReceivedAt == null || referenceTime != null ? null : Math.max(0, now - lastReceivedAt),
                radio, observedFrequencyMhz, observedChannel(), WINDOW_SECONDS,
                Map.copyOf(counts), Map.copyOf(rates), decoded, rejected, unsupported, truncated, kernelDrops, dropStatsAt);
    }
}
