package ewave.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serial;
import java.io.Serializable;

/** A captured frame summary with an epoch-millisecond timestamp. */
public record PacketEvent(
        @JsonProperty("srcMac") String srcMac,
        @JsonProperty("dstMac") String dstMac,
        @JsonProperty("channel") int channel,
        @JsonProperty("rssi") double rssi,
        @JsonProperty("length") int length,
        @JsonProperty("protocol") String protocol,
        @JsonProperty("timestamp") long timestamp,
        @JsonProperty("rawSummary") String rawSummary
) implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;
}
