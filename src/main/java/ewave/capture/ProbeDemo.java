package ewave.capture;

import ewave.decoder.Dot11FrameDecoder;
import ewave.decoder.Dot11InformationElements;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;

/** Two synthetic observations decoded by the same parser as monitor capture. */
public final class ProbeDemo {
    // Radiotap and the probe header from the synthetic probe-requests.pcap fixture.
    private static final String HEADER =
            "00000d00280000008509a000d140000000ffffffffffff021122334455ffffffffffff1000";

    public record Observation(int elapsedMs, int channel, String networkName) { }

    private ProbeDemo() { }

    public static List<Observation> replay() {
        return List.of(decode(0, "000b4c61622028677565737429"), decode(1000, "0000"));
    }

    private static Observation decode(int elapsedMs, String ssidElement) {
        var frame = Dot11FrameDecoder.decodeAny(HexFormat.of().parseHex(HEADER + ssidElement), 127, elapsedMs);
        if (frame == null || !frame.probe()) throw new IllegalStateException("Invalid synthetic probe");
        byte[] ssid = frame.ies().first(0);
        String name = Dot11InformationElements.hidden(ssid) ? null : new String(ssid, StandardCharsets.UTF_8);
        return new Observation(elapsedMs, Dot11FrameDecoder.channel(frame.frequencyMhz()), name);
    }
}
