package ewave.model;

import java.io.Serializable;

/** Last observed name and newest complete report for a BLE address/type pair. */
public record BleDevice(String id, String address, String addressType, String lastAdvertisedName,
                        long firstSeen, long lastSeen, long advertisementCount,
                        BleAdvertisement latest) implements Serializable { }
