package ewave.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;

/**
 * WebSocket envelope with an epoch-millisecond timestamp.
 * Payloads must also implement Serializable when using Java object streams.
 */
public record EwaveEvent(
        @JsonProperty("type") String type,
        @JsonProperty("timestamp") long timestamp,
        @JsonProperty("payload") Object payload
) implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    public static final String DEVICE_APPEARED = "DEVICE_APPEARED";
    public static final String DEVICE_UPDATED = "DEVICE_UPDATED";
    public static final String PACKET_SEEN = "PACKET_SEEN";
    public static final String PROBE_REQUEST = "PROBE_REQUEST";
    public static final String BLE_ADVERTISEMENT = "BLE_ADVERTISEMENT";
    public static final String BLE_DEVICE_UPDATED = "BLE_DEVICE_UPDATED";
    public static final String BLE_DEVICE_REMOVED = "BLE_DEVICE_REMOVED";
    public static final String ATTACK_STARTED = "ATTACK_STARTED";
    public static final String ATTACK_RESULT = "ATTACK_RESULT";
    public static final String CHANNEL_SCORED = "CHANNEL_SCORED";

    public static EwaveEvent deviceAppeared(DeviceRecord device) {
        return now(DEVICE_APPEARED, device);
    }

    public static EwaveEvent deviceUpdated(DeviceRecord device) {
        return now(DEVICE_UPDATED, device);
    }

    public static EwaveEvent packetSeen(PacketEvent packet) {
        return now(PACKET_SEEN, packet);
    }

    public static EwaveEvent probeRequest(ProbeRequest probe) {
        return now(PROBE_REQUEST, probe);
    }

    public static EwaveEvent bleAdvertisement(BleAdvertisement advertisement) {
        return now(BLE_ADVERTISEMENT, advertisement);
    }
    public static EwaveEvent bleDeviceUpdated(BleDevice device) { return now(BLE_DEVICE_UPDATED, device); }
    public static EwaveEvent bleDeviceRemoved(String id) { return now(BLE_DEVICE_REMOVED, id); }

    public static EwaveEvent attackStarted(Object payload) {
        return now(ATTACK_STARTED, payload);
    }

    public static EwaveEvent attackResult(AttackResult result) {
        return now(ATTACK_RESULT, result);
    }

    public static EwaveEvent channelScored(Object payload) {
        return now(CHANNEL_SCORED, payload);
    }

    private static EwaveEvent now(String type, Object payload) {
        return new EwaveEvent(type, Instant.now().toEpochMilli(), payload);
    }
}
