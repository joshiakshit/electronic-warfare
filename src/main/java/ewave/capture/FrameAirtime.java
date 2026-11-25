package ewave.capture;

import ewave.decoder.Dot11Frame;
import ewave.decoder.Radiotap;

import java.util.Objects;

/** Estimates airtime from captured frame lengths and available PHY parameters. */
final class FrameAirtime {
    private static final double[] BITS_PER_SUBCARRIER = {
            0.5, 1, 1.5, 2, 3, 4, 4.5, 5, 6, 20.0 / 3, 7.5, 25.0 / 3
    };

    private FrameAirtime() {}

    static long estimateMicros(Dot11Frame frame) {
        return Math.clamp(Math.round(frame.frameLength() * 8.0 / estimatedPhyRateMbps(frame)) + 44L, 20L, 15_000L);
    }

    private static double estimatedPhyRateMbps(Dot11Frame frame) {
        Radiotap radio = frame.radiotap();
        if (radio != null) {
            Double legacy = radio.legacyRateMbps();
            if (legacy != null && legacy > 0 && Double.isFinite(legacy)) return legacy;
            Radiotap.HtRate ht = radio.ht();
            if (ht != null && ht.mcs() != null && ht.mcs() >= 0 && ht.mcs() < 32) {
                int mcs = ht.mcs();
                int tones = "40 MHz".equals(ht.bandwidth()) ? 108 : 52;
                return tones * BITS_PER_SUBCARRIER[mcs % 8] * (mcs / 8 + 1)
                        / (Boolean.TRUE.equals(ht.shortGuardInterval()) ? 3.6 : 4.0);
            }
            Radiotap.HeRate he = radio.he();
            if (he != null && he.mcs() != null && he.mcs() >= 0 && he.mcs() < BITS_PER_SUBCARRIER.length) {
                int tones = switch (Objects.requireNonNullElse(he.bandwidthOrRu(), "")) {
                    case "26-tone RU" -> 24;
                    case "52-tone RU" -> 48;
                    case "106-tone RU" -> 102;
                    case "40 MHz", "484-tone RU" -> 468;
                    case "80 MHz", "996-tone RU" -> 980;
                    case "160/80+80 MHz", "2×996-tone RU" -> 1960;
                    default -> 234;
                };
                int streams = Objects.requireNonNullElse(he.spaceTimeStreams(), 1);
                double symbolMicros = 12.8 + Objects.requireNonNullElse(he.guardIntervalUs(), 3.2);
                double rate = tones * BITS_PER_SUBCARRIER[he.mcs()] * streams / symbolMicros;
                return Boolean.TRUE.equals(he.dualCarrierModulation()) ? rate / 2 : rate;
            }
        }
        return frame.type() == 2 ? 24.0 : 6.0;
    }
}
