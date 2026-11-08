package ewave.model;

import java.time.Instant;

/** A wordlist miss is limited to the supplied dictionary, not a password-strength guarantee. */
public record PskVerificationResult(boolean vulnerable, String psk, String fullOutput, Instant timestamp) {}
