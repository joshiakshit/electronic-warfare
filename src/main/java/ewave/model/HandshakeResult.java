package ewave.model;

import java.time.Instant;
import java.util.List;

public record HandshakeResult(boolean handshakeDetected, String capFilePath, String apBssid,
                              String clientMac, String captureOutput, Instant timestamp,
                              int frequencyMhz, Outcome outcome, List<Integer> messages,
                              boolean verifiable, String verifiablePair) {
    public enum Outcome { COMPLETE, PARTIAL, NO_EAPOL, TARGET_NOT_SEEN, CAPTURE_ENDED }

    public HandshakeResult {
        messages = List.copyOf(messages);
    }

    public HandshakeResult(boolean handshakeDetected, String capFilePath, String apBssid,
                           String clientMac, String captureOutput, Instant timestamp,
                           int frequencyMhz, Outcome outcome, List<Integer> messages) {
        this(handshakeDetected, capFilePath, apBssid, clientMac, captureOutput, timestamp,
                frequencyMhz, outcome, messages, handshakeDetected, handshakeDetected ? "M1_M2_M3_M4" : null);
    }
}
