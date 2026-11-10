package ewave.ui;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import ewave.active.FrameInjector;
import ewave.active.HandshakeAnalyzer;
import ewave.active.LanScanner;
import ewave.active.WifiAccessPoints;
import ewave.capture.PacketBridge;
import ewave.capture.BleBridge;
import ewave.core.ScannerDemo;
import ewave.model.EwaveEvent;
import ewave.passive.TopologyBuilder;
import ewave.passive.MyNetworkProfile;
import io.javalin.http.Context;
import io.javalin.http.ForbiddenResponse;
import io.javalin.http.NotFoundResponse;
import io.javalin.Javalin;
import io.javalin.http.staticfiles.Location;
import io.javalin.json.JavalinJackson;
import io.javalin.websocket.WsContext;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import java.util.regex.Pattern;

/** Loopback dashboard for RF capture and opt-in lab operations. */
public final class PassiveRfServer implements AutoCloseable {
    public static final int PORT = 7070;
    private static final System.Logger LOG = System.getLogger(PassiveRfServer.class.getName());
    private static final ScannerDemo.Comparison SCANNER_DEMO = ScannerDemo.compare();
    private static final Pattern MAC = Pattern.compile("(?i)(?:[0-9a-f]{2}:){5}[0-9a-f]{2}");

    private final ObjectMapper mapper = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private final Set<WsContext> clients = ConcurrentHashMap.newKeySet();
    private final BlockingQueue<EwaveEvent> events;
    private static final Pattern LOOPBACK_HOST = Pattern.compile("(?i)(?:127\\.0\\.0\\.1|localhost)(?::[0-9]{1,5})?");
    private final PacketBridge wifi;
    private final BleBridge ble;
    private final boolean operations;
    private final Function<String, FrameInjector> injectorFactory;
    private final LanScanner lanScanner;
    private final WifiAccessPoints accessPoints;
    private final Function<HandshakeSettings, HandshakeAnalyzer> handshakeFactory;
    private final long startedAt = System.currentTimeMillis();
    private final Javalin app;
    private final Object injectionLock = new Object();
    private FrameInjector activeInjector;
    private HandshakeAnalyzer activeHandshake;
    private volatile HandshakeAnalyzer latestHandshake;
    private volatile FrameInjector latestInjector;
    private boolean closing;
    private Thread eventThread;

    public record HandshakeSettings(String monitorInterface, String apBssid, String clientMac, int channel, String ssid,
                                    int frequencyMhz) {
        public HandshakeSettings(String monitorInterface, String apBssid, String clientMac, int channel) {
            this(monitorInterface, apBssid, clientMac, channel, null, HandshakeAnalyzer.frequencyMhz(channel));
        }
    }

    public PassiveRfServer(PacketBridge bridge, BleBridge ble) {
        this(bridge, ble, false);
    }

    public PassiveRfServer(PacketBridge bridge, BleBridge ble, boolean operations) {
        this(bridge, ble, operations, FrameInjector::new, new LanScanner(), new WifiAccessPoints());
    }

    /** Injectable boundaries for tests using fixture streams and cached neighbors. */
    public PassiveRfServer(PacketBridge bridge, BleBridge ble, boolean operations,
                           Function<String, FrameInjector> injectorFactory, LanScanner lanScanner,
                           WifiAccessPoints accessPoints) {
        this(bridge, ble, operations, injectorFactory, lanScanner, accessPoints,
                settings -> new HandshakeAnalyzer(settings.monitorInterface(), settings.apBssid(), settings.clientMac(),
                        settings.channel(), settings.frequencyMhz()));
    }

    public PassiveRfServer(PacketBridge bridge, BleBridge ble, boolean operations,
                           Function<String, FrameInjector> injectorFactory, LanScanner lanScanner,
                           WifiAccessPoints accessPoints, Function<HandshakeSettings, HandshakeAnalyzer> handshakeFactory) {
        wifi = Objects.requireNonNull(bridge);
        this.ble = Objects.requireNonNull(ble);
        this.operations = operations;
        this.injectorFactory = Objects.requireNonNull(injectorFactory);
        this.lanScanner = Objects.requireNonNull(lanScanner);
        this.accessPoints = Objects.requireNonNull(accessPoints);
        this.handshakeFactory = Objects.requireNonNull(handshakeFactory);
        events = bridge.getEventQueue();
        app = Javalin.create(config -> {
            config.jsonMapper(new JavalinJackson(mapper, false));
            config.staticFiles.add("/web", Location.CLASSPATH);
        });
        app.before(ctx -> {
            ctx.header("Cache-Control", "no-store");
            if (!isLocal(ctx.header("Host"), ctx.header("Origin")))
                throw new ForbiddenResponse("Same-origin loopback access required");
            if (!operations && ctx.path().startsWith("/api/attack/"))
                throw new NotFoundResponse("Lab operations are disabled");
        });
        registerReports();
        registerOperations();
        app.ws("/ws/events", ws -> {
            ws.onConnect(ctx -> {
                if (isLocal(ctx.header("Host"), ctx.header("Origin"))) clients.add(ctx);
                else ctx.closeSession(1008, "Same-origin loopback access required");
            });
            ws.onClose(clients::remove);
            ws.onError(clients::remove);
        });
    }

    private static boolean isLocal(String host, String origin) {
        return host != null && LOOPBACK_HOST.matcher(host).matches()
                && (origin == null || origin.equalsIgnoreCase("http://" + host));
    }

    private void registerReports() {
        app.get("/api/status", ctx -> ctx.json(Map.of("wifi", wifi.getCaptureStatus(), "ble", ble.getStatus(),
                "startedAt", startedAt, "operationsEnabled", operations)));
        app.get("/api/capture-health", ctx -> {
            var health = wifi.getCaptureHealth();
            if (health == null) ctx.status(503).json(Map.of("error", "Wi-Fi monitor capture or replay is unavailable"));
            else ctx.json(health);
        });
        app.get("/api/my-network", ctx -> {
            try {
                ctx.json(wifi.myNetwork());
            } catch (java.io.IOException failure) {
                LOG.log(System.Logger.Level.WARNING, "Could not read My Network profile", failure);
                ctx.status(500).json(Map.of("error", "Could not read the local My Network profile"));
            }
        });
        app.post("/api/my-network", ctx -> {
            final MyNetworkProfile.Change change;
            try {
                change = mapper.readValue(ctx.body(), MyNetworkProfile.Change.class);
            } catch (JsonProcessingException invalid) {
                ctx.status(400).json(Map.of("error", "Invalid My Network setup request"));
                return;
            }
            try {
                ctx.json(wifi.changeMyNetwork(change));
            } catch (IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", invalid.getMessage()));
            } catch (java.io.IOException failure) {
                LOG.log(System.Logger.Level.WARNING, "Could not save My Network profile", failure);
                ctx.status(500).json(Map.of("error", "Could not save the local My Network profile"));
            }
        });
        app.post("/api/my-network/find", ctx -> {
            var session = wifi.getPassiveWifi();
            if (session == null) {
                unavailable(ctx, "Wi-Fi");
                return;
            }
            try {
                var body = mapper.readTree(ctx.body());
                if (body == null || !body.isObject()) throw new IllegalArgumentException("Expected a network name");
                var name = body.path("ssid");
                ctx.json(session.findAccessPoints(name.isTextual() ? name.textValue() : null));
            } catch (JsonProcessingException | IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", "Enter a network name of 1–32 Wi-Fi bytes"));
            }
        });
        app.get("/api/inventory", ctx -> {
            var session = wifi.getPassiveWifi();
            if (session != null) ctx.json(session.inventory());
            else if (operations) ctx.json(wifi.getProfiler().all());
            else unavailable(ctx, "Wi-Fi");
        });
        app.get("/api/inventory/{id}/details", ctx -> {
            var detail = wifi.inventoryDetail(ctx.pathParam("id"));
            if (detail == null) throw new NotFoundResponse("No retained Wi-Fi device matches this ID");
            ctx.json(detail);
        });
        app.get("/api/fingerprint-samples", ctx -> ctx.json(wifi.fingerprintSamples()));
        app.post("/api/fingerprint-samples", ctx -> {
            try {
                var change = mapper.readValue(ctx.body(), MyNetworkProfile.SampleChange.class);
                ctx.json(wifi.saveFingerprintSample(change));
            } catch (JsonProcessingException invalid) {
                ctx.status(400).json(Map.of("error", "Invalid fingerprint sample request"));
            } catch (IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", invalid.getMessage()));
            }
        });
        app.delete("/api/fingerprint-samples/{id}", ctx -> {
            try {
                ctx.json(wifi.removeFingerprintSample(UUID.fromString(ctx.pathParam("id"))));
            } catch (IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", "Invalid fingerprint sample ID"));
            }
        });
        app.get("/api/probe-audit", ctx -> {
            var session = wifi.getPassiveWifi();
            if (session == null) unavailable(ctx, "Wi-Fi"); else ctx.json(session.audit());
        });
        app.get("/api/topology", ctx -> {
            var session = wifi.getPassiveWifi();
            if (session == null) unavailable(ctx, "Wi-Fi"); else ctx.json(session.topology());
        });
        app.get("/api/topology.dot", ctx -> {
            var session = wifi.getPassiveWifi();
            if (session == null) unavailable(ctx, "Wi-Fi"); else ctx.contentType("text/vnd.graphviz").result(
                    TopologyBuilder.dot(session.topology()));
        });
        app.get("/api/ble/summary", ctx -> {
            var session = ble.getPassiveBle();
            if (session == null) unavailable(ctx, "BLE"); else ctx.json(session.snapshot());
        });
        app.get("/api/channels/watch", ctx -> ctx.json(wifi.apWatchState()));
        app.post("/api/channels/watch", ctx -> {
            try {
                var body = mapper.readTree(ctx.body());
                var ap = body == null ? null : body.get("apId");
                if (ap == null || !ap.isTextual()) throw new IllegalArgumentException("Choose an access point.");
                ctx.json(wifi.startApWatch(ap.textValue()));
            } catch (JsonProcessingException | IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", Objects.toString(invalid.getMessage(), "Invalid watch request.")));
            } catch (IllegalStateException unavailable) {
                ctx.status(409).json(Map.of("error", unavailable.getMessage()));
            }
        });
        app.delete("/api/channels/watch/{id}", ctx -> {
            try {
                ctx.json(wifi.stopApWatch(UUID.fromString(ctx.pathParam("id"))));
            } catch (IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", "The watch run has changed."));
            }
        });
        app.get("/api/channels/demo", ctx -> ctx.json(SCANNER_DEMO));
        app.get("/api/channels", ctx -> {
            var state = wifi.getChannelSnapshot();
            if (state == null) {
                ctx.status(503).json(Map.of("error", "no scanner attached"));
            } else {
                ctx.json(channelResponse(state));
            }
        });
        if (operations) {
            app.get("/api/devices", ctx -> ctx.json(wifi.getDevices()));
            app.get("/api/profiles", ctx -> ctx.json(wifi.getProfiler().all()));
            app.get("/api/probes", ctx -> ctx.json(wifi.getProbeRequests()));
            app.get("/api/ble/status", ctx -> ctx.json(ble.getStatus()));
            app.get("/api/ble/devices", ctx -> ctx.json(ble.getDevices()));
            app.get("/api/ble/advertisements", ctx -> ctx.json(ble.getAdvertisements()));
        }
    }

    private record ChannelDetails(int channel, int freqMhz, double score, double occupancyMean,
                                  double fittedPeriodMs, double fitConfidence, String deviceHint,
                                  List<Integer> coupledWith, ChannelAnomaly anomaly) {}

    private record ChannelAnomaly(double deviation, Instant detectedAt, String reason, long durationMs) {}

    private ObjectNode channelResponse(PacketBridge.ChannelSnapshot state) {
        var snapshot = state.scanner();
        double[] scores = snapshot.scores(), means = snapshot.means();
        int[] coupledMembers = snapshot.coupledMembers();
        var channels = new ArrayList<ChannelDetails>();
        for (int band = 0; band < Math.min(13, scores.length); band++) {
            int channel = band + 1;
            var fingerprint = snapshot.fingerprints().get(band);
            List<Integer> coupledWith = Arrays.binarySearch(coupledMembers, band) < 0 ? List.of()
                    : Arrays.stream(coupledMembers).map(index -> index + 1)
                            .filter(peer -> peer != channel && peer <= 13).boxed().toList();
            var flag = snapshot.anomalies().get(channel);
            var anomaly = flag == null ? null : new ChannelAnomaly(flag.deviation(), flag.detectedAt(),
                    flag.reason(), flag.durationMillis(state.timestamp()));
            channels.add(new ChannelDetails(channel, PacketBridge.channelFrequencyMhz(channel), scores[band],
                    means[band], fingerprint.fittedPeriodMs(), fingerprint.fitConfidence(), fingerprint.deviceHint(),
                    coupledWith, anomaly));
        }

        // Preserve the score arrays consumed by the bundled spectrum dashboard.
        ObjectNode response = mapper.valueToTree(snapshot);
        response.put("tickMs", wifi.getTickMs());
        response.set("radio", mapper.valueToTree(state.radio()));
        response.put("activeChannel", state.activeChannel());
        response.put("lastChosen", state.lastChosen());
        response.put("lastChosenFreqMhz", state.lastChosen() == null ? null
                : PacketBridge.channelFrequencyMhz(state.lastChosen()));
        response.put("timestamp", state.timestamp().toString());
        response.set("channels", mapper.valueToTree(channels));
        return response;
    }

    private void registerOperations() {
        app.post("/api/attack/stop", ctx -> {
            synchronized (injectionLock) {
                if (activeInjector != null) activeInjector.terminate();
                if (activeHandshake != null) activeHandshake.terminate();
            }
            ctx.json(Map.of("stopped", true));
        });
        app.get("/api/attack/targets", ctx -> {
            var session = wifi.getPassiveWifi();
            ctx.json(wifi.getProfiler().all().stream().map(profile -> Map.of(
                    "id", session == null ? profile.mac() : session.addressId(profile.mac()),
                    "mac", profile.mac(), "type", profile.guessedType(),
                    "label", profile.guessedType() + " · " + profile.vendor(),
                    "rssi", profile.lastRssi())).toList());
        });
        app.get("/api/attack/aps", ctx -> {
            try {
                ctx.json(accessPoints.all());
            } catch (java.nio.file.NoSuchFileException missing) {
                ctx.status(404).json(Map.of("error", "No Wi-Fi AP cache found. Restore Wi-Fi with ./scripts/stop-ewave.sh, reconnect, then run ./scripts/start-ewave.sh."));
            } catch (java.io.IOException failure) {
                ctx.status(500).json(Map.of("error", "Cannot read Wi-Fi AP cache: " + failure.getMessage()));
            }
        });
        app.get("/api/attack/scan-lan", ctx -> {
            try {
                ctx.json(lanScanner.scan());
            } catch (java.nio.file.NoSuchFileException missing) {
                ctx.status(404).json(Map.of("error", "No LAN cache found. Restart ewave with ./scripts/start-ewave.sh to populate."));
            } catch (java.io.IOException failure) {
                ctx.status(500).json(Map.of("error", "Cannot read LAN cache: " + failure.getMessage()));
            }
        });
        app.get("/api/attack/status", ctx -> {
            FrameInjector latest = latestInjector;
            ctx.json(latest == null ? new FrameInjector.Status(false, "", "", null) : latest.status());
        });
        app.post("/api/attack/deauth", ctx -> {
            final String ap, client, monitor;
            final int count;
            final int frequencyMhz;
            final FrameInjector injector;
            try {
                var body = mapper.readTree(ctx.body());
                if (body == null || !body.isObject()) throw new IllegalArgumentException("Expected a JSON object");
                var apNode = body.path("apBssid");
                var clientNode = body.path("clientMac");
                var countNode = body.path("count");
                var interfaceNode = body.path("interface");
                if (!apNode.isTextual() || !MAC.matcher(apNode.textValue()).matches())
                    throw new IllegalArgumentException("apBssid must be a MAC address");
                if (!clientNode.isMissingNode() && !clientNode.isNull()
                        && (!clientNode.isTextual() || !MAC.matcher(clientNode.textValue()).matches()))
                    throw new IllegalArgumentException("clientMac must be a MAC address or null for broadcast");
                if (!countNode.isIntegralNumber() || !countNode.canConvertToInt() || countNode.intValue() < 0)
                    throw new IllegalArgumentException("count must be a nonnegative integer");
                if (!interfaceNode.isTextual()) throw new IllegalArgumentException("interface is required");
                ap = apNode.textValue();
                client = clientNode.isTextual() ? clientNode.textValue() : null;
                count = countNode.intValue();
                monitor = interfaceNode.textValue();
                injector = injectorFactory.apply(monitor);
            } catch (JsonProcessingException | IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", invalid.getMessage()));
                return;
            }
            try {
                var target = accessPoints.all().stream().filter(point -> point.bssid().equalsIgnoreCase(ap)).findFirst();
                if (target.isEmpty()) {
                    ctx.status(400).json(Map.of("error", "Select an actual Wi-Fi BSSID from the cached AP list"));
                    return;
                }
                frequencyMhz = target.get().frequencyMhz();
            } catch (java.io.IOException failure) {
                ctx.status(400).json(Map.of("error", "Wi-Fi AP cache unavailable. Restore Wi-Fi, reconnect, then restart with ./scripts/start-ewave.sh."));
                return;
            }
            synchronized (injectionLock) {
                if (closing || activeInjector != null || activeHandshake != null) {
                    ctx.status(409).json(Map.of("error", "An injection is already running or the server is stopping"));
                    return;
                }
                activeInjector = injector;
                latestInjector = injector;
            }
            try {
                ctx.json(injector.sendDeauthFrames(ap, client, count, frequencyMhz));
            } finally {
                synchronized (injectionLock) { activeInjector = null; }
            }
        });
        app.get("/api/attack/handshake/status", ctx -> {
            HandshakeAnalyzer latest = latestHandshake;
            ctx.json(latest == null ? new HandshakeAnalyzer.Status(false, "Ready") : latest.status());
        });
        app.post("/api/attack/handshake", ctx -> {
            final HandshakeAnalyzer analyzer;
            try {
                var body = mapper.readTree(ctx.body());
                if (body == null || !body.isObject()) throw new IllegalArgumentException("Expected a JSON object");
                String ap = requiredText(body, "apBssid");
                var clientNode = body.path("clientMac");
                String client = clientNode.isMissingNode() || clientNode.isNull() ? null : requiredText(body, "clientMac");
                var channelNode = body.path("channel");
                if (!channelNode.isMissingNode() && !channelNode.isNull()
                        && (!channelNode.isIntegralNumber() || !channelNode.canConvertToInt()))
                    throw new IllegalArgumentException("channel must be an integer in 1–233");
                int channel = HandshakeAnalyzer.normalizeChannel(channelNode.asInt(6));
                HandshakeAnalyzer.validateTarget(ap, client, channel);
                var ssidNode = body.path("ssid");
                if (!ssidNode.isMissingNode() && !ssidNode.isNull() && !ssidNode.isTextual())
                    throw new IllegalArgumentException("ssid must be a string");
                String ssid = ssidNode.isTextual() ? ssidNode.textValue() : null;
                var frequencyNode = body.path("frequencyMhz");
                Integer requestedFrequency = null;
                if (!frequencyNode.isMissingNode() && !frequencyNode.isNull()) {
                    if (!frequencyNode.isIntegralNumber() || !frequencyNode.canConvertToInt())
                        throw new IllegalArgumentException("frequencyMhz must be an integer");
                    requestedFrequency = frequencyNode.intValue();
                    HandshakeAnalyzer.validateFrequency(requestedFrequency);
                }
                WifiAccessPoints.AccessPoint target = null;
                try {
                    target = accessPoints.all().stream().filter(point -> point.bssid().equalsIgnoreCase(ap)).findFirst().orElse(null);
                } catch (java.io.IOException ignored) { /* Explicit and legacy channel-only clients can supply a target. */ }
                int frequency;
                if (target != null) {
                    if (requestedFrequency != null && requestedFrequency != target.frequencyMhz())
                        throw new IllegalArgumentException("AP frequency changed. Select the AP again from the refreshed list.");
                    frequency = target.frequencyMhz();
                    channel = target.channel();
                    if (ssid == null) ssid = target.ssid();
                } else {
                    frequency = requestedFrequency == null ? HandshakeAnalyzer.frequencyMhz(channel) : requestedFrequency;
                }
                String monitor = body.has("interface") ? requiredText(body, "interface") : "wlo1";
                analyzer = handshakeFactory.apply(new HandshakeSettings(monitor, ap, client, channel, ssid, frequency));
            } catch (JsonProcessingException | IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", invalid.getMessage()));
                return;
            }
            runHandshake(ctx, analyzer, true, analyzer::capture);
        });
        app.post("/api/attack/handshake/verify", ctx -> {
            final HandshakeAnalyzer analyzer;
            final String cap, wordlist;
            try {
                var body = mapper.readTree(ctx.body());
                if (body == null || !body.isObject()) throw new IllegalArgumentException("Expected a JSON object");
                cap = requiredText(body, "capFilePath");
                wordlist = requiredText(body, "wordlistPath");
                // Check the dictionary first to preserve the actionable missing-wordlist response.
                HandshakeAnalyzer.readableFile(wordlist, HandshakeAnalyzer.WORDLIST_MISSING);
                HandshakeAnalyzer.readableFile(cap, "Capture file not found or unreadable");
                analyzer = handshakeFactory.apply(new HandshakeSettings("wlo1", null, null, 0));
            } catch (JsonProcessingException | IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", invalid.getMessage()));
                return;
            } catch (java.io.IOException missing) {
                ctx.status(404).json(Map.of("error", missing.getMessage()));
                return;
            }
            runHandshake(ctx, analyzer, false, () -> analyzer.verifyPsk(cap, wordlist));
        });
    }

    private static void unavailable(Context ctx, String radio) {
        ctx.status(404).json(Map.of("error", radio + " passive capture is disabled"));
    }

    private static String requiredText(com.fasterxml.jackson.databind.JsonNode body, String field) {
        var node = body.path(field);
        if (!node.isTextual() || node.textValue().isBlank())
            throw new IllegalArgumentException(field + " must be a nonempty string");
        return node.textValue();
    }

    private void runHandshake(io.javalin.http.Context ctx, HandshakeAnalyzer analyzer, boolean capture, Callable<?> operation) {
        synchronized (injectionLock) {
            if (closing || activeInjector != null || activeHandshake != null) {
                ctx.status(409).json(Map.of("error", "An active operation is already running or the server is stopping"));
                return;
            }
            activeHandshake = analyzer;
            if (capture) latestHandshake = analyzer;
        }
        var timedOut = new AtomicBoolean();
        ctx.async(config -> {
            // Allow time for tuning, the 90-second capture, and decoder shutdown.
            config.timeout = capture ? 110_000 : 310_000;
            config.onTimeout(context -> {
                timedOut.set(true);
                analyzer.terminate();
                context.status(504).json(Map.of("error", capture ? "Handshake capture timed out" : "PSK verification timed out"));
            });
        }, () -> {
            try {
                Object result = operation.call();
                if (!timedOut.get()) ctx.json(result);
            } catch (Exception failure) {
                if (failure instanceof InterruptedException) Thread.currentThread().interrupt();
                int status = failure instanceof TimeoutException ? 504
                        : failure instanceof CancellationException || failure instanceof InterruptedException ? 409 : 500;
                if (!timedOut.get()) ctx.status(status).json(Map.of("error", Objects.toString(failure.getMessage(), "Handshake operation failed")));
            } finally {
                synchronized (injectionLock) { activeHandshake = null; }
            }
        });
    }

    public PassiveRfServer start() { return start(PORT); }

    /** Port 0 selects an available port, useful for embedding and integration tests. */
    public synchronized PassiveRfServer start(int port) {
        if (eventThread != null) throw new IllegalStateException("UI server is already running");
        synchronized (injectionLock) { closing = false; }
        app.start("127.0.0.1", port);
        eventThread = new Thread(this::consumeEvents, "ewave-ui-events");
        eventThread.setDaemon(true);
        eventThread.start();
        return this;
    }

    public int port() { return app.port(); }

    /** Serialize once and isolate failed/disconnected clients from the rest. */
    public void broadcast(EwaveEvent event) {
        Objects.requireNonNull(event, "event");
        if (!operations && (event.payload() != null || !switch (event.type()) {
            case "WIFI_DEVICE_SEEN", "BLE_DEVICE_SEEN", "PROBE_RECEIVED" -> true;
            default -> false;
        })) return;
        final String json;
        try {
            json = mapper.writeValueAsString(event);
        } catch (JsonProcessingException failure) {
            throw new IllegalArgumentException("Cannot serialize EwaveEvent", failure);
        }
        for (WsContext client : clients) {
            try {
                synchronized (client.session) {
                    if (client.session.isOpen()) client.send(json);
                    else clients.remove(client);
                }
            } catch (Exception failure) {
                clients.remove(client);
                LOG.log(System.Logger.Level.DEBUG, "Removing failed WebSocket client", failure);
            }
        }
    }

    private void consumeEvents() {
        while (!Thread.currentThread().isInterrupted()) {
            try {
                EwaveEvent event = events.poll(1, TimeUnit.MINUTES);
                if (event != null) broadcast(event);
                else {
                    var session = ble.getPassiveBle();
                    if (session != null) session.purge();
                }
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            } catch (RuntimeException failure) {
                LOG.log(System.Logger.Level.WARNING, "Could not broadcast event", failure);
            }
        }
    }

    public synchronized void stop() {
        synchronized (injectionLock) {
            closing = true;
            if (activeInjector != null) activeInjector.terminate();
            if (activeHandshake != null) activeHandshake.terminate();
        }
        if (eventThread == null) return;
        eventThread.interrupt();
        try {
            app.stop();
            eventThread.join(2_000);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        } finally {
            clients.clear();
            eventThread = null;
        }
    }

    @Override public void close() { stop(); }
}
