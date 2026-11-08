package ewave.model;

import java.io.Serializable;

/** One complete HCI advertising report. Nullable numeric fields mean unavailable.
 * Device IDs include the address type; no Wi-Fi/BLE or rotating-address correlation.
 */
public record BleAdvertisement(String deviceId, String address, String addressType,
                               boolean scanResponse, boolean extended, Integer advertisingSid,
                               Integer rssi, Integer txPower, long timestamp,
                               String rawHex, BlePayload payload, int hciEventType) implements Serializable {
    public BleAdvertisement(String deviceId, String address, String addressType, boolean scanResponse,
                            boolean extended, Integer advertisingSid, Integer rssi, Integer txPower,
                            long timestamp, String rawHex, BlePayload payload) {
        this(deviceId, address, addressType, scanResponse, extended, advertisingSid, rssi, txPower, timestamp,
                rawHex, payload, -1);
    }

    public boolean connectable() {
        return hciEventType >= 0 && (extended ? (hciEventType & 1) != 0 : hciEventType <= 1);
    }

    public boolean scannable() {
        return hciEventType >= 0 && (extended ? (hciEventType & 2) != 0 : hciEventType == 0 || hciEventType == 3);
    }

    public boolean directed() {
        return hciEventType >= 0 && (extended ? (hciEventType & 4) != 0 : hciEventType == 1);
    }
}
