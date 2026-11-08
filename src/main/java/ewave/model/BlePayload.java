package ewave.model;

import java.io.Serializable;
import java.util.List;

/** Decoded Advertising Data (AD). Raw structures preserve unknown and repeated fields. */
public record BlePayload(String localName, boolean completeName, Integer flags,
                         Integer txPower, Integer appearance, List<String> serviceUuids,
                         List<ManufacturerData> manufacturerData, List<ServiceData> serviceData,
                         List<Structure> structures, List<String> warnings) implements Serializable {
    public BlePayload {
        serviceUuids = List.copyOf(serviceUuids);
        manufacturerData = List.copyOf(manufacturerData);
        serviceData = List.copyOf(serviceData);
        structures = List.copyOf(structures);
        warnings = List.copyOf(warnings);
    }
    public record ManufacturerData(int companyId, String dataHex) implements Serializable { }
    public record ServiceData(String uuid, String dataHex) implements Serializable { }
    public record Structure(int type, String dataHex) implements Serializable { }
}
