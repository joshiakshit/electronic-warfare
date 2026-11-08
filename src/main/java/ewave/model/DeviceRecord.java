package ewave.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serial;
import java.io.Serializable;
import java.util.List;
import java.util.Map;

/** An observed unicast MAC endpoint, not a verified physical device.
 * First/last seen times are epoch milliseconds.
 */
public record DeviceRecord(
        @JsonProperty("mac") String mac,
        @JsonProperty("vendor") String vendor,
        @JsonProperty("hostname") String hostname,
        @JsonProperty("type") DeviceType type,
        @JsonProperty("rssi") double rssi,
        @JsonProperty("firstSeen") long firstSeen,
        @JsonProperty("lastSeen") long lastSeen,
        @JsonProperty("probedSsids") List<String> probedSsids,
        @JsonProperty("metadata") Map<String, String> metadata
) implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    /** Collections are immutable snapshots; missing collections become empty. */
    public DeviceRecord {
        probedSsids = probedSsids == null ? List.of() : List.copyOf(probedSsids);
        metadata = metadata == null ? Map.of() : Map.copyOf(metadata);
    }

    public enum DeviceType {
        PHONE, LAPTOP, TV, ROUTER, IOT, UNKNOWN
    }
}
