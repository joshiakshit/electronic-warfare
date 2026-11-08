package ewave.model;

import java.io.Serializable;
import java.time.Instant;

/** Process outcome only; a successful injection does not establish MFP compliance. */
public record AttackResult(boolean success, String attackType, String command,
                           String output, long durationMs, Instant timestamp) implements Serializable {}
