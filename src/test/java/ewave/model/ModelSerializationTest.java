package ewave.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ModelSerializationTest {
    private final ObjectMapper mapper = new ObjectMapper().findAndRegisterModules();

    private DeviceRecord device(List<String> ssids, Map<String, String> metadata) {
        return new DeviceRecord("02:00:00:00:00:01", "Lab", "sensor",
                DeviceRecord.DeviceType.IOT, -52.5, 1_700_000_000_000L,
                1_700_000_000_100L, ssids, metadata);
    }

    @Test void recordsRoundTripThroughJacksonAndJavaSerialization() throws Exception {
        var device = device(List.of("lab"), Map.of("ip", "192.0.2.1"));
        var packet = new PacketEvent(device.mac(), "ff:ff:ff:ff:ff:ff", 6,
                -52.5, 128, "802.11", device.lastSeen(), "probe request");
        var result = new AttackResult(true, "deauth", "sudo aireplay-ng", "done", 250, Instant.now());
        var event = new EwaveEvent(EwaveEvent.ATTACK_STARTED,
                device.lastSeen(), Map.of("targetMac", device.mac()));
        var probe = new ProbeRequest(device.mac(), "ff:ff:ff:ff:ff:ff", "ff:ff:ff:ff:ff:ff", "Lab",
                "4c6162", false, true, 6, 2437, -47, device.lastSeen(), 43, List.of(1.0), List.of("00:11:22"));
        for (Object value : List.of(device, packet,
                result, event, probe,
                EwaveEvent.probeRequest(probe), EwaveEvent.deviceAppeared(device))) {
            String json = mapper.writeValueAsString(value);
            Object decoded = mapper.readValue(json, value.getClass());
            // Object payloads deserialize to JSON maps; their JSON shape remains stable.
            assertEquals(mapper.readTree(json), mapper.readTree(mapper.writeValueAsString(decoded)));
            if (!(value instanceof EwaveEvent)) assertEquals(value, decoded);

            var bytes = new ByteArrayOutputStream();
            try (var output = new ObjectOutputStream(bytes)) {
                output.writeObject(value);
            }
            try (var input = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
                assertEquals(value, input.readObject());
            }
        }

        var json = mapper.valueToTree(EwaveEvent.deviceAppeared(device));
        assertEquals(3, json.size());
        assertEquals("DEVICE_APPEARED", json.get("type").asText());
        assertEquals("IOT", json.at("/payload/type").asText());
        assertEquals(device.firstSeen(), json.at("/payload/firstSeen").asLong());
        long before = Instant.now().toEpochMilli();
        var generated = EwaveEvent.packetSeen(packet);
        assertTrue(generated.timestamp() >= before);
        assertTrue(generated.timestamp() <= Instant.now().toEpochMilli());
    }

    @Test void collectionSnapshotsCannotChangeAfterPublication() {
        var ssids = new ArrayList<>(List.of("lab"));
        var metadata = new HashMap<>(Map.of("ip", "192.0.2.1"));
        var device = device(ssids, metadata);
        ssids.clear();
        metadata.clear();

        assertEquals(List.of("lab"), device.probedSsids());
        assertEquals(Map.of("ip", "192.0.2.1"), device.metadata());
        assertThrows(UnsupportedOperationException.class, () -> device.probedSsids().add("other"));
        assertThrows(UnsupportedOperationException.class, () -> device.metadata().clear());
        assertTrue(device(null, null).probedSsids().isEmpty());
        assertTrue(device(null, null).metadata().isEmpty());
    }
}
