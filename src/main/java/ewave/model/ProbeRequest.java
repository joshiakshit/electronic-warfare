package ewave.model;

import java.io.Serial;
import java.io.Serializable;
import java.util.List;

/** One passively observed probe request. For binary captures, SSID hex preserves the exact octets;
 * ssid is a display string with control characters and backslashes escaped.
 * An empty SSID is a wildcard request, not a disclosed network name.
 * Channel/frequency 0 and RSSI NaN mean unavailable capture metadata.
 * Tcpdump text capture leaves SSID hex empty, destination/BSSID null and frame length 0
 * because those fields are unavailable; its timestamp is the local receipt time.
 */
public record ProbeRequest(String sourceMac, String destinationMac, String bssid,
                           String ssid, String ssidHex, boolean wildcard,
                           boolean locallyAdministered, int channel, int frequencyMhz,
                           double rssi, long timestamp, int frameLength,
                           List<Double> supportedRatesMbps, List<String> vendorOuis)
        implements Serializable {
    @Serial private static final long serialVersionUID = 1L;

    public ProbeRequest {
        supportedRatesMbps = List.copyOf(supportedRatesMbps);
        vendorOuis = List.copyOf(vendorOuis);
    }
}
