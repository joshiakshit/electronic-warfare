package ewave.model;

import java.time.Instant;
import java.util.List;

public record HandshakeResult(boolean handshakeDetected, String capFilePath, String apBssid,
                              String clientMac, String captureOutput, Instant timestamp,
                              int frequencyMhz, Outcome outcome, List<Integer> messages) {
    public enum Outcome { COMPLETE, PARTIAL, NO_EAPOL, TARGET_NOT_SEEN, CAPTURE_ENDED }

    public HandshakeResult {
        messages = List.copyOf(messages);
    }
}
