package ewave.passive;

import ewave.decoder.Dot11Frame;
import ewave.decoder.Dot11FrameDecoder;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;

import static ewave.decoder.Dot11InformationElements.hidden;

public final class TopologyBuilder {
    private static final int AP_LIMIT = 2048, EDGE_LIMIT = 8192, ROAM_LIMIT = 1024;
    private static final long RETRY_MS = 1000;
    public record AccessPoint(String bssid, String ssidToken, boolean ssidHidden, String ssidRevealedVia,
                              int channel, String band, String security, int beaconIntervalTu, String mobilityDomain,
                              Integer stationCount, Integer channelUtilization, Integer availableAdmissionCapacity,
                              String country, String radioGroupId, String essId, Double rssiMedian,
                              String rssiBand, long lastSeen, List<String> clients,
                              List<AdvertisedSecurity> advertisedSecurity) { }
    public record AdvertisedSecurity(String protocol, String groupCipher, List<String> pairwiseCiphers,
                                     List<String> authentication, String managementFrameProtection) { }
    public record AssociationEdge(String clientId, String bssid, long firstSeen, long lastSeen, long evidenceCount,
                                  long uplink, long downlink, String source, Long lastDataSeen, Long associationSeen,
                                  long expiresAt, int channel, int frequencyMhz) { }
    public record RoamEvent(String clientId, String fromBssid, String toBssid, long time, String method) { }
    public record Snapshot(List<AccessPoint> accessPoints, Map<String, List<String>> essGroups,
                           List<AssociationEdge> edges, List<RoamEvent> roams) { }

    private record Link(String client, String ap) { }
    private record LastLink(String ap, long time) { }
    private record RetryKey(String transmitter, String receiver, int type, int tid, int sequence) { }
    private record ClockSample(long received, long offset) { }
    private record SecurityElement(String key, AdvertisedSecurity details) { }

    private final SessionIdentifiers ids;
    private final Predicate<String> allowsBssid;
    private final int minimum = RfSettings.integer("topology.minEvidence", 3, 1, 100);
    private final long edgeTtl = TimeUnit.MINUTES.toMillis(RfSettings.integer("topology.edgeTtlMin", 10, 1, 1440));
    private final long roamWindow = TimeUnit.SECONDS.toMillis(RfSettings.integer("topology.roamWindowSec", 5, 1, 300));
    private final LinkedHashMap<String, Ap> aps = new LinkedHashMap<>(16, 0.75f, true);
    private final LinkedHashMap<Link, Edge> edges = new LinkedHashMap<>(16, 0.75f, true);
    private final LinkedHashMap<RetryKey, Long> recent = new LinkedHashMap<>(16, 0.75f, true);
    private final LinkedHashMap<String, LastLink> memberships = new LinkedHashMap<>(16, 0.75f, true);
    private final ArrayDeque<RoamEvent> roams = new ArrayDeque<>();

    TopologyBuilder(SessionIdentifiers ids) { this(ids, bssid -> true); }

    TopologyBuilder(SessionIdentifiers ids, Predicate<String> allowsBssid) {
        this.ids = ids;
        this.allowsBssid = allowsBssid;
    }

    /** Returns the frame-local client address when this frame establishes observed membership. */
    String observe(Dot11Frame frame, String sender) {
        if (duplicate(frame, sender)) return null;
        if (frame.apAdvertisement()) {
            if (frame.addr3().equals(frame.addr2()) && (frame.capability() & 1) != 0)
                advertise(frame, sender);
            return null;
        }

        String client, bssid;
        boolean up, data = !frame.management();
        if (data) {
            if (frame.ds() != 1 && frame.ds() != 2) return null;
            up = frame.ds() == 1;
            client = up ? frame.addr2() : frame.addr1();
            bssid = up ? frame.addr1() : frame.addr2();
        } else {
            switch (frame.subtype()) {
                case 0, 2 -> up = true;
                case 1, 3 -> up = false;
                case 11 -> {
                    if (frame.status() != 0) return null;
                    up = !frame.addr2().equals(frame.addr3());
                }
                default -> { return null; }
            }
            client = up ? frame.addr2() : frame.addr1();
            bssid = frame.addr3();
            if (!(up ? frame.addr1() : frame.addr2()).equals(bssid)) return null;
            if (!up && frame.status() != 0) return null;
        }
        if (!unicast(client) || !unicast(bssid) || client.equals(bssid)) return null;
        String clientId = ids.id("wifi", client), apId = ids.id("wifi", bssid);
        long time = frame.timestamp();
        Ap ap = ap(apId, time);
        if (up && !data && (frame.subtype() == 0 || frame.subtype() == 2))
            name(ap, frame.ies().first(0), "ASSOC_REQ");
        if (!up) ap.signal(frame.rssi());

        if (!data && frame.subtype() == 2 && unicast(frame.currentAp())
                && allowsBssid.test(frame.currentAp()) && !frame.currentAp().equals(bssid))
            roam(clientId, ids.id("wifi", frame.currentAp()), apId, time, "REASSOC");
        LastLink previous = memberships.get(clientId);
        if (!data && frame.authenticationAlgorithm() == 2 && recentSwitch(previous, apId, time))
            roam(clientId, previous.ap, apId, time, "FT");

        var key = new Link(clientId, apId);
        Edge edge = edges.get(key);
        if (edge == null || time - edge.observedThrough() >= edgeTtl) {
            edge = new Edge();
            edges.put(key, edge);
        }
        if (edges.size() > EDGE_LIMIT) edges.pollFirstEntry();
        edge.first = Math.min(edge.first, time);
        edge.last = Math.max(edge.last, time);
        edge.count++;
        boolean association = !data && !up && (frame.subtype() == 1 || frame.subtype() == 3);
        if ((data || association) && frame.frequencyMhz() > 0
                && (edge.frequency == 0 || time >= edge.lastEvidence())) edge.frequency = frame.frequencyMhz();
        if (data) {
            edge.lastData = Math.max(edge.lastData, time);
            if (up) edge.up++; else edge.down++;
        }
        if (association && time >= edge.associationSeen) {
            edge.associationSeen = time;
            edge.associationType = frame.subtype() == 1 ? "ASSOC" : "REASSOC";
        }
        edge.confirmed = edge.associationSeen >= 0 || edge.up + edge.down >= minimum;
        if (!edge.confirmed || !(data || association)) return null;

        if (data && recentSwitch(previous, apId, time))
            roam(clientId, previous.ap, apId, time, "DATA_SWITCH");
        if (previous == null || time >= previous.time) memberships.put(clientId, new LastLink(apId, time));
        if (memberships.size() > EDGE_LIMIT) memberships.pollFirstEntry();
        return client;
    }

    void clear() {
        aps.clear();
        edges.clear();
        recent.clear();
        memberships.clear();
        roams.clear();
    }

    private boolean recentSwitch(LastLink previous, String ap, long time) {
        return previous != null && !previous.ap.equals(ap) && time >= previous.time && time - previous.time <= roamWindow;
    }

    private void roam(String client, String from, String to, long time, String method) {
        for (var event : roams.reversed()) {
            if (time - event.time > roamWindow) break;
            if (event.clientId.equals(client) && event.fromBssid.equals(from) && event.toBssid.equals(to)) return;
        }
        if (roams.size() == ROAM_LIMIT) roams.removeFirst();
        roams.addLast(new RoamEvent(client, from, to, time, method));
    }

    private boolean duplicate(Dot11Frame frame, String sender) {
        var key = new RetryKey(sender, ids.id("wifi", frame.addr1()), frame.type(), frame.tid(), frame.sequenceControl());
        Long seen = recent.put(key, frame.timestamp());
        if (recent.size() > EDGE_LIMIT) recent.pollFirstEntry();
        return frame.retry() && seen != null && frame.timestamp() - seen >= 0 && frame.timestamp() - seen <= RETRY_MS;
    }

    private Ap ap(String id, long time) {
        Ap ap = aps.computeIfAbsent(id, key -> new Ap());
        if (aps.size() > AP_LIMIT) aps.pollFirstEntry();
        ap.last = Math.max(ap.last, time);
        return ap;
    }

    private void advertise(Dot11Frame frame, String id) {
        Ap ap = ap(id, frame.timestamp());
        ap.signal(frame.rssi());
        var ies = frame.ies();
        byte[] ssid = ies.first(0);
        if (frame.subtype() == 8 && ies.has(0)) ap.hidden = hidden(ssid);
        name(ap, ssid, frame.subtype() == 5 ? "PROBE_RESP" : "BEACON");
        byte[] ds = ies.first(3), ht = ies.first(61), md = ies.first(54), load = ies.first(11), country = ies.first(7);
        int mhz = frame.frequencyMhz();
        int channel = Dot11FrameDecoder.channel(mhz);
        if ("2.4 GHz".equals(WifiInventory.band(mhz)) && ds.length == 1 && ds[0] > 0 && ds[0] <= 14)
            channel = ds[0];
        else if ("5 GHz".equals(WifiInventory.band(mhz)) && ht.length >= 22) channel = ht[0] & 0xff;
        if (channel == 0 && ds.length == 1) channel = ds[0] & 0xff;
        if (mhz != 0 && ap.frequency != mhz) ap.clocks.clear();
        if (mhz != 0) ap.frequency = mhz;
        if (channel != 0) ap.channel = channel;
        ap.interval = frame.beaconIntervalTu();
        ap.domain = md.length == 3 ? HexFormat.of().formatHex(md, 0, 2) : null;
        ap.country = country.length >= 3 && country[0] >= 'A' && country[0] <= 'Z'
                && country[1] >= 'A' && country[1] <= 'Z' ? new String(new char[]{(char) country[0], (char) country[1]}) : null;
        ap.stations = load.length == 5 ? u16(load, 0) : null;
        ap.utilization = load.length == 5 ? load[2] & 0xff : null;
        ap.admissionCapacity = load.length == 5 ? u16(load, 3) : null;
        byte[] rsn = ies.first(48);
        var security = new TreeMap<String, AdvertisedSecurity>();
        if (ies.has(48)) addSecurity(security, "RSN", rsn, 0);
        for (var ie : ies.elements()) {
            if ("0050f201".equals(ie.vendorKey())) addSecurity(security, "WPA", ie.value(), 4);
        }
        ap.security = security.isEmpty() ? (frame.capability() & 16) != 0 ? "Privacy bit set" : "Open"
                : String.join("+", security.keySet());
        ap.advertisedSecurity = List.copyOf(security.values());
        if (frame.subtype() == 8 && frame.radiotapTsft() != null && frame.beaconTsf() != null && ap.frequency != 0) {
            if (ap.clocks.size() == 16) ap.clocks.removeFirst();
            // Two's complement subtraction handles wrap in either 64-bit TSF timer.
            ap.clocks.addLast(new ClockSample(frame.timestamp(), frame.beaconTsf() - frame.radiotapTsft()));
        }
    }

    private static void addSecurity(Map<String, AdvertisedSecurity> security, String protocol, byte[] ie, int start) {
        var parsed = securitySuites(protocol, ie, start);
        if (parsed == null) security.put(protocol, new AdvertisedSecurity(protocol, null, List.of(), List.of(), null));
        else security.put(parsed.key, parsed.details);
    }

    private static SecurityElement securitySuites(String protocol, byte[] ie, int start) {
        if (ie.length - start < 10 || u16(ie, start) != 1) return null;
        int pos = start + 6;
        String group = HexFormat.of().formatHex(ie, start + 2, pos);
        var parts = new ArrayList<TreeSet<String>>();
        for (int list = 0; list < 2; list++) {
            if (ie.length - pos < 2) return null;
            int count = u16(ie, pos);
            pos += 2;
            if (count > (ie.length - pos) / 4) return null;
            var suites = new TreeSet<String>();
            for (int i = 0; i < count; i++, pos += 4) suites.add(HexFormat.of().formatHex(ie, pos, pos + 4));
            parts.add(suites);
        }
        String key = protocol + "[" + group + ";" + String.join(",", parts.get(0)) + ";"
                + String.join(",", parts.get(1)) + "]";
        String pmf = null;
        if (protocol.equals("RSN") && ie.length - pos >= 2) {
            int capabilities = u16(ie, pos);
            pmf = (capabilities & 0x40) != 0 ? "Required" : (capabilities & 0x80) != 0 ? "Capable" : "Disabled";
        }
        return new SecurityElement(key, new AdvertisedSecurity(protocol, cipher(group),
                parts.get(0).stream().map(TopologyBuilder::cipher).toList(),
                parts.get(1).stream().map(TopologyBuilder::authentication).toList(), pmf));
    }

    private static String cipher(String suite) {
        int type = suiteType(suite, 5);
        return switch (type) {
            case 0 -> "Use group cipher";
            case 1 -> "WEP-40";
            case 2 -> "TKIP";
            case 4 -> "CCMP-128";
            case 5 -> "WEP-104";
            case 6 -> "BIP-CMAC-128";
            case 8 -> "GCMP-128";
            case 9 -> "GCMP-256";
            case 10 -> "CCMP-256";
            case 11 -> "BIP-GMAC-128";
            case 12 -> "BIP-GMAC-256";
            case 13 -> "BIP-CMAC-256";
            default -> "0x" + suite;
        };
    }

    private static String authentication(String suite) {
        return switch (suiteType(suite, 2)) {
            case 1 -> "802.1X";
            case 2 -> "PSK";
            case 3 -> "FT/802.1X";
            case 4 -> "FT/PSK";
            case 5 -> "802.1X/SHA-256";
            case 6 -> "PSK/SHA-256";
            case 8 -> "SAE";
            case 9 -> "FT/SAE";
            case 11 -> "802.1X Suite B";
            case 12 -> "802.1X Suite B 192-bit";
            case 18 -> "OWE";
            default -> "0x" + suite;
        };
    }

    private static int suiteType(String suite, int legacyMax) {
        int type = Integer.parseInt(suite.substring(6), 16);
        return suite.startsWith("000fac") || (suite.startsWith("0050f2") && type <= legacyMax) ? type : -1;
    }

    private void name(Ap ap, byte[] ssid, String source) {
        if (hidden(ssid)) return;
        // Association requests can supply a name only when the AP has not supplied one.
        if (source.equals("ASSOC_REQ") && (ap.ssid != null || !ap.hidden)) return;
        ap.ssid = ids.id("topology-ssid", ssid);
        ap.nameSource = source.equals("BEACON") ? "NONE" : source;
    }

    void purge(long now, long retention) {
        aps.values().removeIf(ap -> ap.last < now - retention);
        edges.values().removeIf(edge -> edge.observedThrough() <= now - Math.min(edgeTtl, retention));
        roams.removeIf(event -> event.time < now - retention);
        memberships.values().removeIf(link -> link.time < now - roamWindow);
        recent.values().removeIf(time -> time < now - RETRY_MS);
    }

    Snapshot snapshot() { return snapshot(Long.MAX_VALUE); }

    Snapshot snapshot(long retention) {
        var links = new ArrayList<AssociationEdge>();
        var clients = new TreeMap<String, List<String>>();
        for (var row : edges.entrySet()) {
            Link key = row.getKey();
            Edge edge = row.getValue();
            if (!edge.confirmed || !aps.containsKey(key.ap)) continue;
            long lastEvidence = edge.lastEvidence();
            links.add(new AssociationEdge(key.client, key.ap, edge.first, lastEvidence, edge.count, edge.up, edge.down,
                    edge.associationSeen < 0 ? "DATA" : edge.associationType,
                    edge.lastData < 0 ? null : edge.lastData, edge.associationSeen < 0 ? null : edge.associationSeen,
                    lastEvidence + Math.min(edgeTtl, retention), Dot11FrameDecoder.channel(edge.frequency), edge.frequency));
            clients.computeIfAbsent(key.ap, id -> new ArrayList<>()).add(key.client);
        }
        links.sort(Comparator.comparing(AssociationEdge::bssid).thenComparing(AssociationEdge::clientId));
        var ess = new TreeMap<String, List<String>>();
        var output = new ArrayList<AccessPoint>();
        var radio = new TreeMap<String, String>();
        var clocks = new TreeMap<Integer, TreeMap<String, Ap>>();
        aps.forEach((key, ap) -> {
            if (ap.clocks.size() >= 5) clocks.computeIfAbsent(ap.frequency, freq -> new TreeMap<>()).put(key, ap);
        });
        for (var channel : clocks.values()) {
            for (var a : channel.entrySet()) {
                if (radio.containsKey(a.getKey())) continue;
                for (var b : channel.tailMap(a.getKey(), false).entrySet()) {
                    if (!radio.containsKey(b.getKey()) && sameClock(a.getValue(), b.getValue())) {
                        radio.putIfAbsent(a.getKey(), a.getKey());
                        radio.put(b.getKey(), a.getKey());
                    }
                }
            }
        }
        for (var row : new TreeMap<>(aps).entrySet()) {
            String key = row.getKey();
            Ap ap = row.getValue();
            String group = ap.ssid == null || ap.security == null ? null
                    : ids.id("ess", ap.ssid + ":" + ap.security + ":" + Objects.toString(ap.domain, ""));
            if (group != null) ess.computeIfAbsent(group, id -> new ArrayList<>()).add(key);
            Double median = ap.rssi.isEmpty() ? null : WifiInventory.median(ap.rssi.stream().sorted().toList());
            output.add(new AccessPoint(key, ap.ssid, ap.hidden, ap.hidden ? ap.nameSource : "NONE", ap.channel, WifiInventory.band(ap.frequency),
                    ap.security, ap.interval, ap.domain, ap.stations, ap.utilization, ap.admissionCapacity, ap.country,
                    radio.get(key), group, median, median == null ? null : median > -55 ? "STRONG" : median < -75 ? "WEAK" : "MEDIUM",
                    ap.last, clients.getOrDefault(key, List.of()).stream().sorted().toList(), ap.advertisedSecurity));
        }
        ess.replaceAll((key, values) -> List.copyOf(values));
        return new Snapshot(List.copyOf(output), Map.copyOf(ess), List.copyOf(links), List.copyOf(roams));
    }

    private static boolean sameClock(Ap a, Ap b) {
        // A shared clock yields nearly equal AP-minus-receiver TSF offsets. Pair nearby beacons
        // one to one so a single sample cannot establish a group, even at different beacon rates.
        var left = a.clocks.iterator();
        var right = b.clocks.iterator();
        ClockSample x = left.next(), y = right.next();
        int consistent = 0;
        while (true) {
            if (x.received - y.received > 150) {
                if (!right.hasNext()) break;
                y = right.next();
            } else if (y.received - x.received > 150) {
                if (!left.hasNext()) break;
                x = left.next();
            } else {
                long delta = x.offset - y.offset;
                if (delta < -300 || delta > 300) return false;
                if (++consistent >= 5) return true;
                if (!left.hasNext() || !right.hasNext()) break;
                x = left.next();
                y = right.next();
            }
        }
        return false;
    }

    public static String dot(Snapshot snapshot) {
        var text = new StringBuilder("graph passive_wifi {\n");
        for (var ap : snapshot.accessPoints) text.append("  ap_").append(ap.bssid).append(" [shape=box];\n");
        var clients = new TreeSet<String>();
        for (var edge : snapshot.edges) {
            if (clients.add(edge.clientId)) text.append("  client_").append(edge.clientId)
                    .append(" [shape=ellipse,label=\"").append(edge.clientId, 0, 8).append("\"];\n");
            text.append("  client_").append(edge.clientId).append(" -- ap_").append(edge.bssid)
                    .append(" [label=\"").append(edge.evidenceCount).append("\"];\n");
        }
        return text.append("}\n").toString();
    }

    private static boolean unicast(String mac) {
        return mac != null && (Integer.parseInt(mac.substring(0, 2), 16) & 1) == 0 && !mac.equals("00:00:00:00:00:00");
    }

    private static int u16(byte[] bytes, int offset) { return (bytes[offset] & 0xff) | (bytes[offset + 1] & 0xff) << 8; }

    private static final class Ap {
        final ArrayDeque<Double> rssi = new ArrayDeque<>();
        final ArrayDeque<ClockSample> clocks = new ArrayDeque<>();
        String ssid, security, domain, country, nameSource = "NONE";
        List<AdvertisedSecurity> advertisedSecurity = List.of();
        Integer stations, utilization, admissionCapacity;
        int frequency, channel, interval;
        boolean hidden;
        long last;

        void signal(double value) {
            if (!Double.isFinite(value)) return;
            if (rssi.size() == 64) rssi.removeFirst();
            rssi.addLast(value);
        }
    }

    private static final class Edge {
        long first = Long.MAX_VALUE, last, count, up, down;
        long lastData = -1, associationSeen = -1;
        int frequency;
        boolean confirmed;
        String associationType;

        long lastEvidence() { return Math.max(lastData, associationSeen); }
        long observedThrough() { return confirmed ? lastEvidence() : last; }
    }
}
