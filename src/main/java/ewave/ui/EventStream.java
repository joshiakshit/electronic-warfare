package ewave.ui;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import ewave.capture.PacketBridge;
import ewave.model.EwaveEvent;
import io.javalin.websocket.WsContext;
import org.eclipse.jetty.websocket.api.WriteCallback;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/** Coalesces report invalidations and gives each connection one ordered sequence. */
final class EventStream {
    private static final List<String> MODULES = List.of("status", "overview", "sniper", "spotter",
            "whistleblower", "decloaker", "inspector", "profiler", "tracker", "lookout", "settings");

    private final ObjectMapper mapper;
    private final Map<WsContext, Long> clients = new HashMap<>();
    private PacketBridge.ReportProgress last;

    EventStream(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    synchronized void connect(WsContext client, PacketBridge.ReportProgress progress) {
        client.session.getRemote().setMaxOutgoingFrames(32);
        clients.put(client, 0L);
        if (clients.size() == 1) last = progress;
        send(client, mapper.valueToTree(report(EwaveEvent.SUMMARY, MODULES)), progress.sessionId());
    }

    synchronized void disconnect(WsContext client) {
        clients.remove(client);
    }

    synchronized boolean isEmpty() {
        return clients.isEmpty();
    }

    synchronized void clear() {
        clients.clear();
        last = null;
    }

    synchronized void flush(PacketBridge.ReportProgress current) {
        var previous = last;
        last = current;
        if (clients.isEmpty()) return;
        if (previous == null || !Objects.equals(previous.sessionId(), current.sessionId())) {
            publish(report(EwaveEvent.SUMMARY, MODULES), current.sessionId());
            return;
        }
        List<String> changed = new ArrayList<>();
        boolean settings = previous.settings() != current.settings();
        boolean topology = previous.topology() != current.topology() || settings;
        boolean inventory = previous.inventory() != current.inventory() || settings;
        if (previous.frames() != current.frames() || !previous.status().equals(current.status()))
            changed.add("status");
        if (!previous.sniper().equals(current.sniper())) changed.add("sniper");
        if (topology) changed.addAll(List.of("overview", "inspector", "whistleblower"));
        if (inventory || topology) changed.add("profiler");
        if (topology || inventory) changed.addAll(List.of("spotter", "tracker"));
        if (previous.probes() != current.probes() || settings) changed.add("decloaker");
        if (settings) changed.add("settings");
        // Quiet dwell changes occupancy too, even when no frames arrive.
        if (attached(previous) || attached(current)) changed.add("lookout");
        if (!changed.isEmpty()) publish(report(EwaveEvent.DELTA, changed), current.sessionId());
    }

    private static boolean attached(PacketBridge.ReportProgress progress) {
        return Boolean.TRUE.equals(progress.status().get("scannerAttached"));
    }

    synchronized void publish(Object event, UUID sessionId) {
        if (clients.isEmpty()) return;
        ObjectNode message = mapper.valueToTree(event);
        if (!message.has("timestamp")) message.put("timestamp", System.currentTimeMillis());
        for (var client : List.copyOf(clients.keySet())) send(client, message, sessionId);
    }

    private static EwaveEvent report(String type, List<String> modules) {
        return new EwaveEvent(type, System.currentTimeMillis(), new EwaveEvent.ReportChanges(modules));
    }

    private void send(WsContext client, ObjectNode message, UUID sessionId) {
        Long previous = clients.get(client);
        if (previous == null) return;
        if (!client.session.isOpen()) {
            disconnect(client);
            return;
        }
        long seq = previous + 1;
        message.put("seq", seq);
        message.put("sessionId", sessionId == null ? null : sessionId.toString());
        clients.put(client, seq);
        try {
            client.session.getRemote().sendString(message.toString(), new WriteCallback() {
                @Override public void writeFailed(Throwable failure) {
                    fail(client);
                }
            });
        } catch (RuntimeException failure) {
            fail(client);
        }
    }

    private void fail(WsContext client) {
        disconnect(client);
        client.closeSession(1011, "Event stream interrupted");
    }
}
