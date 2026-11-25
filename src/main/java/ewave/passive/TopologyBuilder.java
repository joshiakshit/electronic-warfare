package ewave.passive;

import ewave.decoder.ApHardwareDecoder;
import ewave.decoder.ApHardwareDecoder.WpsInfo;
import ewave.decoder.ApRadioDecoder;
import ewave.decoder.Dot11Frame;
import ewave.decoder.Dot11FrameDecoder;
import ewave.decoder.Dot11ChannelSwitchDecoder;
import ewave.decoder.Dot11InformationElements;
import ewave.decoder.CapabilityDecoder;
import ewave.decoder.IeSignature;
import ewave.decoder.MultipleBssidDecoder;
import ewave.decoder.SecurityDecoder;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;

import static ewave.decoder.Dot11InformationElements.hidden;
import static ewave.decoder.Dot11FrameDecoder.BTM_ACTION_REQUEST;
import static ewave.decoder.Dot11FrameDecoder.BTM_ACTION_RESPONSE;
import static ewave.decoder.Dot11FrameDecoder.FT_ACTION_REQUEST;
import static ewave.decoder.Dot11FrameDecoder.FT_ACTION_RESPONSE;

public final class TopologyBuilder {
    private static final int AP_LIMIT = 2048, EDGE_LIMIT = 8192, ROAM_LIMIT = 1024, MESH_LIMIT = 1024;
    private static final int SHORT_SSID_LIMIT = 4096;
    private static final int BTM_REJECTION_LIMIT = 256;
    private static final long RETRY_MS = 1000;
    private static final long PING_PONG_MS = 60_000, BTM_WINDOW_MS = 15_000;
    public record AccessPoint(String bssid, String ssid, String ssidToken, boolean ssidHidden, String ssidRevealedVia,
                              int channel, String band, String security, int beaconIntervalTu, String mobilityDomain,
                              Integer stationCount, Integer channelUtilization, Integer availableAdmissionCapacity,
                              String country, String radioGroupId, String essId, Double rssiMedian,
                              String rssiBand, long lastSeen, List<String> clients,
                              List<AdvertisedSecurity> advertisedSecurity, HiddenSsidEvidence hiddenSsidEvidence,
                              int frequencyMhz, List<String> securityModes,
                              CapabilityDecoder.ManagementFeatures managementFeatures,
                              Dot11Frame.RadioObservation radioObservation, boolean nonTransmitted, String mldId,
                              String concealmentMode, Integer maskedSsidLength, String revealConfidence,
                              String meshId, String hiddenRole, String owePeerBssid, List<String> coHostedVisibleSsids,
                              String vendor, String apHostname, WpsInfo wpsInfo, ApRadioSummary apRadio,
                              String groupManagementCipher, List<String> rsnxeFeatures, boolean beaconProtection,
                              boolean ocvc) {
        public AccessPoint(String bssid, String ssid, String ssidToken, boolean ssidHidden, String ssidRevealedVia,
                           int channel, String band, String security, int beaconIntervalTu, String mobilityDomain,
                           Integer stationCount, Integer channelUtilization, Integer availableAdmissionCapacity,
                           String country, String radioGroupId, String essId, Double rssiMedian, String rssiBand,
                           long lastSeen, List<String> clients, List<AdvertisedSecurity> advertisedSecurity,
                           HiddenSsidEvidence hiddenSsidEvidence, int frequencyMhz, List<String> securityModes,
                           CapabilityDecoder.ManagementFeatures managementFeatures, Dot11Frame.RadioObservation radioObservation,
                           boolean nonTransmitted, String mldId, String concealmentMode, Integer maskedSsidLength,
                           String revealConfidence, String meshId, String hiddenRole, String owePeerBssid,
                           List<String> coHostedVisibleSsids) {
            this(bssid, ssid, ssidToken, ssidHidden, ssidRevealedVia, channel, band, security, beaconIntervalTu,
                    mobilityDomain, stationCount, channelUtilization, availableAdmissionCapacity, country, radioGroupId,
                    essId, rssiMedian, rssiBand, lastSeen, clients, advertisedSecurity, hiddenSsidEvidence,
                    frequencyMhz, securityModes, managementFeatures, radioObservation, nonTransmitted, mldId,
                    concealmentMode, maskedSsidLength, revealConfidence, meshId, hiddenRole, owePeerBssid,
                    coHostedVisibleSsids, null, null, null, null, null, List.of(), false, false);
        }

        public AccessPoint(String bssid, String ssid, String ssidToken, boolean ssidHidden, String ssidRevealedVia,
                           int channel, String band, String security, int beaconIntervalTu, String mobilityDomain,
                           Integer stationCount, Integer channelUtilization, Integer availableAdmissionCapacity,
                           String country, String radioGroupId, String essId, Double rssiMedian,
                           String rssiBand, long lastSeen, List<String> clients, List<AdvertisedSecurity> advertisedSecurity,
                           HiddenSsidEvidence hiddenSsidEvidence, int frequencyMhz, List<String> securityModes,
                           CapabilityDecoder.ManagementFeatures managementFeatures, Dot11Frame.RadioObservation radioObservation,
                           boolean nonTransmitted, String mldId) {
            this(bssid, ssid, ssidToken, ssidHidden, ssidRevealedVia, channel, band, security, beaconIntervalTu,
                    mobilityDomain, stationCount, channelUtilization, availableAdmissionCapacity, country, radioGroupId,
                    essId, rssiMedian, rssiBand, lastSeen, clients, advertisedSecurity, hiddenSsidEvidence,
                    frequencyMhz, securityModes, managementFeatures, radioObservation, nonTransmitted, mldId,
                    null, null, null, null, null, null, List.of());
        }

        public AccessPoint(String bssid, String ssid, String ssidToken, boolean ssidHidden, String ssidRevealedVia,
                           int channel, String band, String security, int beaconIntervalTu, String mobilityDomain,
                           Integer stationCount, Integer channelUtilization, Integer availableAdmissionCapacity,
                           String country, String radioGroupId, String essId, Double rssiMedian,
                           String rssiBand, long lastSeen, List<String> clients, List<AdvertisedSecurity> advertisedSecurity,
                           HiddenSsidEvidence hiddenSsidEvidence, int frequencyMhz, List<String> securityModes,
                           CapabilityDecoder.ManagementFeatures managementFeatures, Dot11Frame.RadioObservation radioObservation) {
            this(bssid, ssid, ssidToken, ssidHidden, ssidRevealedVia, channel, band, security, beaconIntervalTu,
                    mobilityDomain, stationCount, channelUtilization, availableAdmissionCapacity, country, radioGroupId,
                    essId, rssiMedian, rssiBand, lastSeen, clients, advertisedSecurity, hiddenSsidEvidence,
                    frequencyMhz, securityModes, managementFeatures, radioObservation, false, null);
        }

        public AccessPoint(String bssid, String ssid, String ssidToken, boolean ssidHidden, String ssidRevealedVia,
                           int channel, String band, String security, int beaconIntervalTu, String mobilityDomain,
                           Integer stationCount, Integer channelUtilization, Integer availableAdmissionCapacity,
                           String country, String radioGroupId, String essId, Double rssiMedian, String rssiBand,
                           long lastSeen, List<String> clients, List<AdvertisedSecurity> advertisedSecurity,
                           HiddenSsidEvidence hiddenSsidEvidence) {
            this(bssid, ssid, ssidToken, ssidHidden, ssidRevealedVia, channel, band, security, beaconIntervalTu,
                    mobilityDomain, stationCount, channelUtilization, availableAdmissionCapacity, country, radioGroupId,
                    essId, rssiMedian, rssiBand, lastSeen, clients, advertisedSecurity, hiddenSsidEvidence, 0, List.of(), null, null);
        }
    }
    public record ApRadioSummary(String wifiGeneration, int operatingWidthMhz, int maxWidthMhz,
                                 int spatialStreams, Integer bssColor) { }
    public record HiddenSsidEvidence(String name, String source, Long observedAt, long beaconObservedAt) { }
    public record AdvertisedSecurity(String protocol, String groupCipher, List<String> pairwiseCiphers,
                                     List<String> authentication, String managementFrameProtection) { }
    public record AssociationEdge(String clientId, String bssid, long firstSeen, long lastSeen, long evidenceCount,
                                  long uplink, long downlink, String source, Long lastDataSeen, Long associationSeen,
                                  long expiresAt, int channel, int frequencyMhz, String state, long controlFrames,
                                  String clientMldId) {
        public AssociationEdge {
            if (state == null) state = "ACTIVE";
        }

        public AssociationEdge(String clientId, String bssid, long firstSeen, long lastSeen, long evidenceCount,
                               long uplink, long downlink, String source, Long lastDataSeen, Long associationSeen,
                               long expiresAt, int channel, int frequencyMhz) {
            this(clientId, bssid, firstSeen, lastSeen, evidenceCount, uplink, downlink, source, lastDataSeen,
                    associationSeen, expiresAt, channel, frequencyMhz, "ACTIVE", 0, null);
        }
    }
    public record RoamEvent(String clientId, String fromBssid, String toBssid, long time, String method,
                            boolean pingPong, Integer fromRssiDbm, Integer toRssiDbm, Long previousDwellMs,
                            String transitionType, Integer fromChannel, Integer toChannel, String fromBand,
                            String toBand, boolean btmSteered) {
        public RoamEvent(String clientId, String fromBssid, String toBssid, long time, String method) {
            this(clientId, fromBssid, toBssid, time, method, false, null, null, null, "INTER_AP_ROAM",
                    null, null, null, null, false);
        }
    }
    public record BtmRejection(String clientId, String apId, int statusCode, long time) { }
    public record Snapshot(List<AccessPoint> accessPoints, Map<String, List<String>> essGroups,
                           List<AssociationEdge> edges, List<RoamEvent> roams, List<MeshLink> meshLinks,
                           List<BtmRejection> btmRejections) {
        public Snapshot {
            if (meshLinks == null) meshLinks = List.of();
            if (btmRejections == null) btmRejections = List.of();
        }

        public Snapshot(List<AccessPoint> accessPoints, Map<String, List<String>> essGroups,
                        List<AssociationEdge> edges, List<RoamEvent> roams, List<MeshLink> meshLinks) {
            this(accessPoints, essGroups, edges, roams, meshLinks, List.of());
        }

        public Snapshot(List<AccessPoint> accessPoints, Map<String, List<String>> essGroups,
                        List<AssociationEdge> edges, List<RoamEvent> roams) {
            this(accessPoints, essGroups, edges, roams, List.of());
        }
    }
    public record MeshLink(String peerA, String peerB, long firstSeen, long lastSeen, long frameCount,
                           int channel, int frequencyMhz) { }

    private record Link(String client, String ap) { }
    private record LastLink(String ap, long time, long enteredAt) { }
    private record BtmExchange(String target, long time, boolean accepted) { }
    private record RetryKey(String transmitter, String receiver, int type, int tid, int sequence) { }
    private record ClockSample(long received, long offset) { }
    private record MeshPeers(String a, String b) { }
    private enum RevealConfidence { TENTATIVE_CLIENT, CONFIRMED_ASSOC, AP_AUTHORITATIVE }
    private record AssociationClaim(Link link, byte[] ssid, int subtype, long observedAt) {
        String source() { return subtype == 2 ? "REASSOC_REQ" : "ASSOC_REQ"; }

        boolean matchesResponse(int responseSubtype, long time) {
            return responseSubtype == subtype + 1 && time >= observedAt;
        }
    }
    private record SsidReveal(String label, String token, String source, long observedAt, RevealConfidence confidence,
                              int length, AssociationClaim association) { }
    private record ShortSsidMatch(byte[] ssid, long observedAt) { }
    private record OwePair(String peerId, byte[] ssid, long observedAt) { }

    private final SessionIdentifiers ids;
    private final Predicate<String> allowsBssid;
    private final boolean revealNames;
    private final OuiLookup oui;
    private final int minimum = RfSettings.integer("topology.minEvidence", 3, 1, 100);
    private final long edgeTtl = TimeUnit.MINUTES.toMillis(RfSettings.integer("topology.edgeTtlMin", 10, 1, 1440));
    private final long roamWindow = TimeUnit.SECONDS.toMillis(RfSettings.integer("topology.roamWindowSec", 30, 1, 300));
    private final LinkedHashMap<String, Ap> aps = new LinkedHashMap<>(16, 0.75f, true);
    private final LinkedHashMap<Link, Edge> edges = new LinkedHashMap<>(16, 0.75f, true);
    private final LinkedHashMap<MeshPeers, MeshLink> meshLinks = new LinkedHashMap<>(16, 0.75f, true);
    private final LinkedHashMap<RetryKey, Long> recent = new LinkedHashMap<>(16, 0.75f, true);
    private final LinkedHashMap<String, LastLink> memberships = new LinkedHashMap<>(16, 0.75f, true);
    private final LinkedHashMap<String, ClientTrack> clientTracks = new LinkedHashMap<>(16, 0.75f, true);
    private final LinkedHashMap<Link, LinkRadio> linkRadios = new LinkedHashMap<>(16, 0.75f, true);
    private final LinkedHashMap<Link, BtmExchange> btmExchanges = new LinkedHashMap<>(16, 0.75f, true);
    private final ArrayList<RoamEvent> roams = new ArrayList<>();
    private final ArrayDeque<BtmRejection> btmRejections = new ArrayDeque<>();
    private final Map<Integer, ShortSsidMatch> shortSsids = new HashMap<>();

    TopologyBuilder(SessionIdentifiers ids) { this(ids, bssid -> true, false); }

    TopologyBuilder(SessionIdentifiers ids, Predicate<String> allowsBssid, boolean revealNames) {
        this(ids, allowsBssid, revealNames, null);
    }

    TopologyBuilder(SessionIdentifiers ids, Predicate<String> allowsBssid, boolean revealNames, OuiLookup oui) {
        this.ids = ids;
        this.allowsBssid = allowsBssid;
        this.revealNames = revealNames;
        this.oui = oui;
    }

    /** Returns the frame-local client address when this frame establishes observed membership. */
    String observe(Dot11Frame frame, String sender) {
        return observe(frame, sender, MultipleBssidDecoder.decode(frame));
    }

    String observe(Dot11Frame frame, String sender, List<MultipleBssidDecoder.Profile> profiles) {
        if (frame.type() != 1 && duplicate(frame, sender)) return null;
        if (frame.apAdvertisement()) {
            if (unicast(frame.addr2()) && frame.addr2().equals(frame.addr3())
                    && ((frame.capability() & 1) != 0 || frame.subtype() == 8 && isMesh(frame.ies())))
                advertise(frame, sender, profiles);
            return null;
        }
        if (frame.probe()) {
            observeProbe(frame);
            return null;
        }
        if (frame.type() == 2 && frame.ds() == 3) {
            observeMesh(frame, sender);
            return null;
        }
        if (frame.management() && (frame.subtype() == 10 || frame.subtype() == 12)) {
            disconnect(frame);
            return null;
        }
        if (frame.management() && frame.subtype() == 13) {
            observeAction(frame);
            return null;
        }

        String client, bssid;
        boolean up, data = frame.type() == 2, control = frame.type() == 1;
        if (control) {
            switch (frame.subtype()) {
                case 10 -> up = true;
                case 8, 9 -> {
                    boolean apAtReceiver = unicast(frame.addr1()) && aps.containsKey(ids.id("wifi", frame.addr1()));
                    boolean apAtSender = aps.containsKey(sender);
                    if (apAtReceiver == apAtSender) return null;
                    up = apAtReceiver;
                }
                default -> { return null; }
            }
            client = up ? frame.addr2() : frame.addr1();
            bssid = up ? frame.addr1() : frame.addr2();
        } else if (data) {
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
        }
        if (!unicast(client) || !unicast(bssid) || client.equals(bssid) || !allowsBssid.test(bssid)) return null;
        String clientId = ids.id("wifi", client), apId = ids.id("wifi", bssid);
        long time = frame.timestamp();
        var key = new Link(clientId, apId);
        boolean association = frame.management() && !up && (frame.subtype() == 1 || frame.subtype() == 3);
        if (association && frame.status() != 0) {
            rejectAssociation(key, frame.subtype(), time);
            return null;
        }
        observeLinkRadio(key, frame, up);
        Ap ap = ap(apId, time);
        if (ap.ouiPrefix5 == null) ap.ouiPrefix5 = globalOuiPrefix5(bssid);
        AssociationClaim request = null;
        if (up && frame.management() && (frame.subtype() == 0 || frame.subtype() == 2) && frame.ies() != null) {
            request = new AssociationClaim(key, frame.ies().first(0), frame.subtype(), time);
            String mldId = mldId(frame.ies());
            if (mldId != null) {
                ClientTrack track = clientTrack(clientId);
                if (time >= track.mldSeen) {
                    track.mldId = mldId;
                    track.mldSeen = time;
                }
            }
            if (isLocallyAdministered(client)) {
                String cohort = IeSignature.capabilityCohortOf(frame.ies());
                if (cohort != null) {
                    ClientTrack track = clientTrack(clientId);
                    track.local = true;
                    track.cohort = cohort;
                    track.bandCohort = IeSignature.bandInvariantCohortOf(frame.ies());
                    String band = bandForAp(ap, frame.frequencyMhz());
                    if (band != null) track.band = band;
                }
            }
        }
        if (!up) ap.signal(frame.rssi());

        if (frame.management() && frame.subtype() == 2 && unicast(frame.currentAp())
                && allowsBssid.test(frame.currentAp()) && !frame.currentAp().equals(bssid))
            roam(clientId, ids.id("wifi", frame.currentAp()), apId, time, reassociationMethod(frame.ies()));
        LastLink previous = memberships.get(clientId);
        if (frame.management() && frame.authenticationAlgorithm() == 2 && recentSwitch(previous, apId, time))
            roam(clientId, previous.ap, apId, time, "FT");

        Edge edge = edges.get(key);
        if (edge == null || time - edge.observedThrough() >= edgeTtl) {
            edge = new Edge();
            edges.put(key, edge);
        }
        if (edges.size() > EDGE_LIMIT) edges.pollFirstEntry();
        edge.first = Math.min(edge.first, time);
        edge.last = Math.max(edge.last, time);
        edge.count++;
        if ((data || association || control) && frame.frequencyMhz() > 0
                && (edge.frequency == 0 || time >= edge.lastEvidence())) edge.frequency = frame.frequencyMhz();
        if (data || association) edge.observeAssociationEvidence(frame, association, edgeTtl);
        if (data) {
            edge.lastData = Math.max(edge.lastData, time);
            if (up) edge.up++; else edge.down++;
        }
        if (association && time >= edge.associationSeen) {
            edge.associationSeen = time;
            edge.associationType = frame.subtype() == 1 ? "ASSOC" : "REASSOC";
        }
        if (control) {
            edge.lastControl = Math.max(edge.lastControl, time);
            edge.control++;
            edge.psPollSeen |= frame.subtype() == 10;
        }
        edge.confirmed = edge.associationSeen >= 0 || (edge.up + edge.down + edge.control >= minimum
                && (edge.up + edge.down > 0 || edge.psPollSeen));
        if (request != null && (edge.nameClaim == null || time >= edge.nameClaim.observedAt())) {
            edge.nameClaim = request;
            reveal(ap, request.ssid(), request.source(), time, RevealConfidence.TENTATIVE_CLIENT, request);
        }
        var pending = edge.nameClaim;
        if (pending != null && edge.confirmed && (association ? pending.matchesResponse(frame.subtype(), time)
                : (data || control) && time >= pending.observedAt() && time >= edge.stateAt)) {
            edge.nameClaim = null;
            reveal(ap, pending.ssid(), pending.source(), pending.observedAt(), RevealConfidence.CONFIRMED_ASSOC, pending);
            if (!ap.hidden || matchesMaskedLength(ap, pending.ssid().length)) rememberShortSsid(pending.ssid(), time);
        }
        if (!edge.confirmed || !(data || association || control)) return null;

        if (time < edge.stateAt) return client;
        if (previous != null && time < previous.time) {
            if (!previous.ap.equals(apId) && !edge.state.equals("DISCONNECTED")) {
                edge.state = "ROAMED_AWAY";
                edge.stateAt = previous.time;
            }
            return client;
        }
        if (previous != null && !previous.ap.equals(apId)) {
            Edge old = edges.get(new Link(clientId, previous.ap));
            if (old != null && old.state.equals("ACTIVE")) {
                old.state = "ROAMED_AWAY";
                old.stateAt = time;
            }
        }
        edge.state = "ACTIVE";
        edge.stateAt = time;
        if (data && recentSwitch(previous, apId, time))
            roam(clientId, previous.ap, apId, time, "DATA_SWITCH");
        if (association && (previous == null || time - previous.time > roamWindow) && isLocallyAdministered(client))
            inferMacRotationRoam(clientId, apId, bandForAp(ap, frame.frequencyMhz()), time);
        long enteredAt = previous != null && previous.ap.equals(apId) ? previous.enteredAt : time;
        memberships.put(clientId, new LastLink(apId, time, enteredAt));
        if (memberships.size() > EDGE_LIMIT) memberships.pollFirstEntry();
        ClientTrack activeTrack = clientTracks.get(clientId);
        if (activeTrack != null) {
            activeTrack.apId = apId;
            activeTrack.lastSeen = Math.max(activeTrack.lastSeen, time);
            String activeBand = bandForAp(ap, frame.frequencyMhz());
            if (activeBand != null) activeTrack.band = activeBand;
        }
        return client;
    }

    private void disconnect(Dot11Frame frame) {
        String bssid = frame.addr3();
        if (!unicast(bssid) || !allowsBssid.test(bssid)) return;
        String client;
        if (bssid.equals(frame.addr2())) client = frame.addr1();
        else if (bssid.equals(frame.addr1())) client = frame.addr2();
        else return;
        if (!unicast(client) || client.equals(bssid)) return;
        String apId = ids.id("wifi", bssid), clientId = ids.id("wifi", client);
        Ap ap = aps.get(apId);
        Edge edge = edges.get(new Link(clientId, apId));
        if (ap == null || edge == null || !edge.confirmed || frame.timestamp() < edge.stateAt
                || frame.timestamp() - edge.lastEvidence() >= edgeTtl) return;
        if ((frame.flags() & 0x40) == 0 && ap.advertisedSecurity.stream()
                .anyMatch(profile -> "Required".equals(profile.managementFrameProtection()))) return;
        edge.state = "DISCONNECTED";
        edge.stateAt = frame.timestamp();
    }

    private void observeAction(Dot11Frame frame) {
        int action = frame.authenticationAlgorithm();
        boolean up = action == FT_ACTION_REQUEST || action == BTM_ACTION_RESPONSE;
        if (!up && action != FT_ACTION_RESPONSE && action != BTM_ACTION_REQUEST) return;
        String bssid = frame.addr3();
        String client = up ? frame.addr2() : frame.addr1();
        if (!unicast(bssid) || !bssid.equals(up ? frame.addr1() : frame.addr2()) || !allowsBssid.test(bssid)
                || !unicast(client) || client.equals(bssid)) return;

        var link = new Link(ids.id("wifi", client), ids.id("wifi", bssid));
        observeLinkRadio(link, frame, up);
        long time = frame.timestamp();
        String target = frame.currentAp();
        boolean validTarget = unicast(target) && !target.equals(bssid) && !target.equals(client)
                && allowsBssid.test(target);
        if (action == FT_ACTION_REQUEST || action == FT_ACTION_RESPONSE) {
            if (validTarget && (up || frame.status() == 0))
                roam(link.client, link.ap, ids.id("wifi", target), time, "FT_OVER_DS");
            return;
        }

        BtmExchange previous = btmExchanges.get(link);
        if (previous != null && time < previous.time) return;
        if (action == BTM_ACTION_REQUEST) {
            btmExchanges.put(link, new BtmExchange(null, time, false));
        } else if (frame.status() > 0) {
            btmExchanges.remove(link);
            if (btmRejections.size() == BTM_REJECTION_LIMIT) btmRejections.removeFirst();
            btmRejections.addLast(new BtmRejection(link.client, link.ap, frame.status(), time));
        } else if (frame.status() == 0 && (target == null || validTarget)) {
            // Either half of the exchange may be missing from a passive capture.
            btmExchanges.put(link, new BtmExchange(validTarget ? ids.id("wifi", target) : null, time, true));
        } else {
            btmExchanges.remove(link);
        }
        if (btmExchanges.size() > EDGE_LIMIT) btmExchanges.pollFirstEntry();
    }

    private void observeLinkRadio(Link link, Dot11Frame frame, boolean up) {
        boolean hasSignal = up && Double.isFinite(frame.rssi());
        if (!hasSignal && frame.frequencyMhz() <= 0) return;
        var radio = linkRadios.computeIfAbsent(link, ignored -> new LinkRadio());
        long time = frame.timestamp();
        if (hasSignal && time >= radio.signalAt) {
            radio.signal = (int) Math.round(frame.rssi());
            radio.signalAt = time;
        }
        if (frame.frequencyMhz() > 0 && time >= radio.frequencyAt) {
            radio.frequency = frame.frequencyMhz();
            radio.frequencyAt = time;
        }
        if (linkRadios.size() > EDGE_LIMIT) linkRadios.pollFirstEntry();
    }

    private static String reassociationMethod(Dot11InformationElements ies) {
        if (ies == null || !(ies.has(55) || (ies.has(54) && SecurityDecoder.decode(ies).rsnAkmSuites().stream()
                .anyMatch(suite -> suite.startsWith("FT/"))))) return "REASSOC";
        byte[] mdie = ies.first(54);
        return mdie.length == 3 && (mdie[2] & 1) != 0 ? "FT_OVER_DS" : "FT_REASSOC";
    }

    private void observeMesh(Dot11Frame frame, String sender) {
        if (!unicast(frame.addr1()) || !unicast(frame.addr2()) || frame.addr1().equals(frame.addr2())
                || !(allowsBssid.test(frame.addr1()) || allowsBssid.test(frame.addr2()))) return;
        String receiver = ids.id("wifi", frame.addr1());
        var key = receiver.compareTo(sender) < 0 ? new MeshPeers(receiver, sender) : new MeshPeers(sender, receiver);
        MeshLink previous = meshLinks.get(key);
        long time = frame.timestamp();
        if (previous != null && time - previous.lastSeen() >= edgeTtl) previous = null;
        int frequency = frame.frequencyMhz();
        if (previous == null) {
            meshLinks.put(key, new MeshLink(key.a, key.b, time, time, 1, Dot11FrameDecoder.channel(frequency), frequency));
        } else {
            if (frequency == 0 || (previous.frequencyMhz() > 0 && time < previous.lastSeen()))
                frequency = previous.frequencyMhz();
            meshLinks.put(key, new MeshLink(key.a, key.b, Math.min(time, previous.firstSeen()),
                    Math.max(time, previous.lastSeen()), previous.frameCount() + 1,
                    Dot11FrameDecoder.channel(frequency), frequency));
        }
        if (meshLinks.size() > MESH_LIMIT) meshLinks.pollFirstEntry();
    }

    private String mldId(Dot11InformationElements ies) {
        var multiLink = Dot11ChannelSwitchDecoder.decodeBasicMultiLink(ies);
        return multiLink != null && unicast(multiLink.mldMac()) ? ids.id("mld", multiLink.mldMac()) : null;
    }

    private ClientTrack clientTrack(String clientId) {
        ClientTrack track = clientTracks.computeIfAbsent(clientId, ignored -> new ClientTrack());
        if (clientTracks.size() > EDGE_LIMIT) clientTracks.pollFirstEntry();
        return track;
    }

    private void inferMacRotationRoam(String clientId, String toApId, String toBand, long time) {
        ClientTrack current = clientTracks.get(clientId);
        if (current == null || !current.local || current.cohort == null) return;
        String effectiveBand = toBand != null ? toBand : current.band;
        String matchedFromAp = null;
        for (var entry : clientTracks.entrySet()) {
            String otherId = entry.getKey();
            ClientTrack other = entry.getValue();
            if (otherId.equals(clientId) || !other.local || other.apId == null || other.apId.equals(toApId)) continue;
            long gap = time - other.lastSeen;
            if (gap <= 0 || gap > roamWindow || other.cohort == null) continue;
            boolean sameBand = Objects.equals(effectiveBand, other.band)
                    || effectiveBand == null || other.band == null
                    || current.bandCohort == null || other.bandCohort == null;
            boolean cohortMatch = sameBand
                    ? current.cohort.equals(other.cohort)
                    : current.bandCohort.equals(other.bandCohort);
            if (!cohortMatch || !relatedAccessPoints(other.apId, toApId)) continue;
            if (matchedFromAp != null) return; // Ambiguous match: do not fabricate a roam.
            matchedFromAp = other.apId;
        }
        if (matchedFromAp != null) roam(clientId, matchedFromAp, toApId, time, "INFERRED_MAC_ROTATION");
    }

    private boolean relatedAccessPoints(String fromApId, String toApId) {
        Ap from = aps.get(fromApId);
        Ap to = aps.get(toApId);
        if (from == null || to == null) return false;
        if (from.mldId != null && from.mldId.equals(to.mldId)) return true;
        SsidReveal fromName = resolvedName(from), toName = resolvedName(to);
        if (fromName != null && toName != null && fromName.token().equals(toName.token())) return true;
        if (from.domain != null && from.domain.equals(to.domain)) return true;
        if (from.ouiPrefix5 != null && from.ouiPrefix5.equals(to.ouiPrefix5)) return true;
        return from.clocks.size() >= 5 && to.clocks.size() >= 5
                && from.frequency == to.frequency
                && sameClock(List.copyOf(from.clocks), List.copyOf(to.clocks));
    }

    private static String bandForAp(Ap ap, int frameFrequencyMhz) {
        String band = WifiInventory.band(frameFrequencyMhz);
        return band != null || ap == null ? band : WifiInventory.band(ap.frequency);
    }

    void clear() {
        aps.clear();
        edges.clear();
        meshLinks.clear();
        recent.clear();
        memberships.clear();
        clientTracks.clear();
        linkRadios.clear();
        btmExchanges.clear();
        roams.clear();
        btmRejections.clear();
        shortSsids.clear();
    }

    private boolean recentSwitch(LastLink previous, String ap, long time) {
        return previous != null && !previous.ap.equals(ap) && time >= previous.time && time - previous.time <= roamWindow;
    }

    private void roam(String client, String from, String to, long time, String method) {
        Ap fromAp = aps.get(from), toAp = aps.get(to);
        boolean sameMld = fromAp != null && toAp != null && fromAp.mldId != null && fromAp.mldId.equals(toAp.mldId);
        if (sameMld && method.equals("DATA_SWITCH")) return;

        int previousIndex = roams.size() - 1;
        while (previousIndex >= 0 && !roams.get(previousIndex).clientId.equals(client)) previousIndex--;
        RoamEvent previous = previousIndex >= 0 ? roams.get(previousIndex) : null;
        long gap = previous == null ? Long.MAX_VALUE : time - previous.time;
        boolean duplicate = previous != null && gap >= 0 && gap <= roamWindow
                && previous.fromBssid.equals(from) && previous.toBssid.equals(to);
        boolean pingPong = previous != null && gap >= 0 && gap <= PING_PONG_MS
                && previous.fromBssid.equals(to) && previous.toBssid.equals(from);

        var fromLink = new Link(client, from);
        LinkRadio fromRadio = linkRadios.get(fromLink), toRadio = linkRadios.get(new Link(client, to));
        Integer fromSignal = fromRadio == null || fromRadio.signalAt > time ? null : fromRadio.signal;
        Integer toSignal = toRadio == null || toRadio.signalAt > time ? null : toRadio.signal;
        int fromFrequency = linkFrequency(fromRadio, fromAp, time), toFrequency = linkFrequency(toRadio, toAp, time);
        String fromBand = WifiInventory.band(fromFrequency), toBand = WifiInventory.band(toFrequency);
        Integer fromChannel = linkChannel(fromAp, fromFrequency), toChannel = linkChannel(toAp, toFrequency);
        String transition = sameMld ? "MLO_LINK_SWITCH" : transitionType(fromAp, toAp, fromBand, toBand);
        boolean steered = btmSteered(fromLink, to, time);

        if (duplicate) {
            roams.set(previousIndex, new RoamEvent(client, from, to, previous.time,
                    roamStrength(method) > roamStrength(previous.method) ? method : previous.method,
                    previous.pingPong, prefer(previous.fromRssiDbm, fromSignal), prefer(toSignal, previous.toRssiDbm),
                    previous.previousDwellMs,
                    prefer(fromAp == null || toAp == null ? null : transition, previous.transitionType),
                    prefer(previous.fromChannel, fromChannel), prefer(previous.toChannel, toChannel),
                    prefer(previous.fromBand, fromBand), prefer(previous.toBand, toBand), previous.btmSteered || steered));
            return;
        }
        LastLink membership = memberships.get(client);
        Long dwell = membership != null && membership.ap.equals(from) && membership.time <= time
                ? time - membership.enteredAt : null;
        if (previous != null && gap >= 0 && gap <= edgeTtl && previous.toBssid.equals(from)) dwell = gap;
        if (roams.size() == ROAM_LIMIT) roams.removeFirst();
        roams.add(new RoamEvent(client, from, to, time, method, pingPong, fromSignal, toSignal, dwell,
                transition, fromChannel, toChannel, fromBand, toBand, steered));
    }

    private boolean btmSteered(Link from, String to, long time) {
        BtmExchange exchange = btmExchanges.get(from);
        if (exchange == null || time < exchange.time) return false;
        if (exchange.accepted && time - exchange.time <= BTM_WINDOW_MS
                && (exchange.target == null || to.equals(exchange.target))) {
            btmExchanges.remove(from);
            return true;
        }
        return false;
    }

    private static int roamStrength(String method) {
        return switch (method) {
            case "FT_OVER_DS" -> 4;
            case "FT_REASSOC" -> 3;
            case "FT" -> 2;
            case "REASSOC" -> 1;
            default -> 0;
        };
    }

    private static int linkFrequency(LinkRadio radio, Ap ap, long time) {
        return radio != null && radio.frequency > 0 && radio.frequencyAt <= time ? radio.frequency
                : ap == null ? 0 : ap.frequency;
    }

    private static Integer linkChannel(Ap ap, int frequency) {
        int channel = Dot11FrameDecoder.channel(frequency);
        if (channel == 0 && ap != null) channel = ap.channel;
        return channel > 0 ? channel : null;
    }

    private String transitionType(Ap from, Ap to, String fromBand, String toBand) {
        if (from != null && to != null) {
            boolean coHosted = (from.ouiPrefix5 != null && from.ouiPrefix5.equals(to.ouiPrefix5))
                    || (from.hostname.value != null && from.hostname.value.equals(to.hostname.value));
            if (coHosted && fromBand != null && toBand != null && !fromBand.equals(toBand)) return "BAND_STEER";
            SsidReveal fromName = resolvedName(from), toName = resolvedName(to);
            if (!coHosted && fromName != null && toName != null && !fromName.token().equals(toName.token()))
                return "ESS_SWITCH";
        }
        return "INTER_AP_ROAM";
    }

    private static <T> T prefer(T value, T fallback) { return value != null ? value : fallback; }

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

    private void advertise(Dot11Frame frame, String id, List<MultipleBssidDecoder.Profile> profiles) {
        boolean inScope = allowsBssid.test(frame.addr2());
        Ap ap = inScope ? ap(id, frame.timestamp()) : new Ap();
        var security = SecurityDecoder.decode(frame.ies());
        advertiseTransmitter(frame, ap, security);
        if (inScope) {
            observeAdvertisedName(frame, id, ap, frame.ies(), frame.capability(), security);
            observeNeighborReports(frame.ies(), frame.timestamp());
        }
        for (var profile : profiles) {
            if (!unicast(profile.bssid()) || !allowsBssid.test(profile.bssid())) continue;
            advertiseProfile(frame, id, ap, profile);
        }
    }

    private void advertiseTransmitter(Dot11Frame frame, Ap ap, SecurityDecoder.Summary security) {
        var ies = frame.ies();
        observeHardware(ap, ies, frame.timestamp());
        if (frame.timestamp() < ap.advertisedAt) return;
        if (ap.advertisedAt < 0) ap.vendor = vendor(frame.addr3());
        ap.advertisedAt = frame.timestamp();
        if (ap.ouiPrefix5 == null) ap.ouiPrefix5 = globalOuiPrefix5(frame.addr3());
        ap.signal(frame.rssi());
        byte[] ds = ies.first(3), ht = ies.first(61), load = ies.first(11), country = ies.first(7);
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
        ap.country = country.length >= 3 && country[0] >= 'A' && country[0] <= 'Z'
                && country[1] >= 'A' && country[1] <= 'Z' ? new String(new char[]{(char) country[0], (char) country[1]}) : null;
        ap.stations = load.length == 5 ? u16(load, 0) : null;
        ap.utilization = load.length == 5 ? load[2] & 0xff : null;
        ap.admissionCapacity = load.length == 5 ? u16(load, 3) : null;
        var capabilities = CapabilityDecoder.decode(ies, ap.frequency, true, frame.capability(), security);
        var operation = ApRadioDecoder.decode(ies);
        int operatingWidth = operation.widthMhz();
        if (operatingWidth == 0 && capabilities.wifiGeneration().startsWith("802.11")) operatingWidth = 20;
        ap.apRadio = new ApRadioSummary(capabilities.wifiGeneration(), operatingWidth, capabilities.maxWidthMhz(),
                capabilities.spatialStreams(), operation.bssColor());
        setSecurity(ap, frame.capability(), security, capabilities.managementFeatures());
        ap.mldId = mldId(ies);
        ap.transmitter = null;
        if (frame.radiotap() != null && (ap.radioObservation == null || frame.timestamp() >= ap.radioObservation.timestamp())) {
            ap.radioObservation = frame.radioObservation();
        }
        if (frame.subtype() == 8 && frame.radiotapTsft() != null && frame.beaconTsf() != null && ap.frequency != 0) {
            if (ap.clocks.size() == 16) ap.clocks.removeFirst();
            // Two's complement subtraction handles wrap in either 64-bit TSF timer.
            ap.clocks.addLast(new ClockSample(frame.timestamp(), frame.beaconTsf() - frame.radiotapTsft()));
        }
    }

    private void advertiseProfile(Dot11Frame frame, String parentId, Ap parent, MultipleBssidDecoder.Profile profile) {
        String id = ids.id("wifi", profile.bssid());
        Ap ap = ap(id, frame.timestamp());
        var ies = profile.ies();
        observeAdvertisedName(frame, id, ap, ies, profile.capability(), profile.security());
        observeNeighborReports(ies, frame.timestamp());
        observeHardware(ap, ies, frame.timestamp());
        if (frame.timestamp() < ap.advertisedAt) return;
        if (ap.advertisedAt < 0) ap.vendor = vendor(profile.bssid());
        ap.advertisedAt = frame.timestamp();
        ap.transmitter = parentId;
        ap.clocks.clear();
        ap.ouiPrefix5 = globalOuiPrefix5(profile.bssid());
        ap.signal(frame.rssi());
        if (parent.frequency != 0) ap.frequency = parent.frequency;
        if (parent.channel != 0) ap.channel = parent.channel;
        ap.interval = parent.interval;
        ap.country = parent.country;
        ap.radioObservation = parent.radioObservation;
        ap.apRadio = parent.apRadio;
        byte[] load = ies.first(11);
        ap.stations = load.length == 5 ? u16(load, 0) : null;
        ap.utilization = load.length == 5 ? load[2] & 0xff : null;
        ap.admissionCapacity = load.length == 5 ? u16(load, 3) : null;
        setSecurity(ap, profile.capability(), profile.security(),
                CapabilityDecoder.managementFeatures(ies, profile.capability(), profile.security().rsnAkmSuites()));
        ap.mldId = mldId(ies);
    }

    private String vendor(String bssid) {
        if (oui != null) {
            var registration = oui.registration(bssid, true);
            if (registration.isPresent()) return registration.get().vendor();
        }
        return isLocallyAdministered(bssid) ? "Locally administered" : null;
    }

    private static void observeHardware(Ap ap, Dot11InformationElements ies, long timestamp) {
        var hardware = ApHardwareDecoder.decode(ies);
        ap.hostname.observe(hardware.apHostname(), timestamp);
        if (hardware.wpsInfo() != null) {
            if (ap.wps == null) ap.wps = new WpsObservation();
            ap.wps.observe(hardware.wpsInfo(), timestamp);
        }
    }

    private static void setSecurity(Ap ap, int capability, SecurityDecoder.Summary security,
                                    CapabilityDecoder.ManagementFeatures managementFeatures) {
        ap.security = security.profiles().isEmpty() ? (capability & 16) != 0 ? "Privacy bit set" : "Open"
                : String.join("+", security.profiles().stream().map(SecurityDecoder.Profile::key).toList());
        ap.advertisedSecurity = security.profiles().stream().map(profile -> new AdvertisedSecurity(profile.protocol(),
                profile.groupCipher(), profile.pairwiseCiphers(), profile.authentication(),
                profile.managementFrameProtection())).toList();
        ap.securityModes = security.modes();
        ap.managementFeatures = managementFeatures;
        ap.domain = ap.managementFeatures.mobilityDomain();
        ap.groupManagementCipher = security.groupManagementCipher();
        ap.rsnxeFeatures = security.rsnxeFeatures();
        ap.beaconProtection = security.beaconProtection();
        ap.ocvc = security.ocvc();
    }

    private void observeAdvertisedName(Dot11Frame frame, String id, Ap ap, Dot11InformationElements ies,
                                        int capability, SecurityDecoder.Summary security) {
        long time = frame.timestamp();
        byte[] ssid = ies.first(0);
        boolean beacon = frame.subtype() == 8;
        reveal(ap, ssid, beacon ? "BEACON" : "PROBE_RESP", time, RevealConfidence.AP_AUTHORITATIVE, null);
        rememberShortSsid(ssid, time);
        if (!beacon || time < ap.beaconNameObservedAt || !(ies.has(0) || isMesh(ies))) return;

        ap.beaconNameObservedAt = time;
        ap.hidden = hidden(ssid);
        ap.concealmentMode = !ap.hidden || !ies.has(0) ? null : ssid.length == 0 ? "ZERO_LENGTH" : "NULL_PADDED";
        ap.maskedSsidLength = "NULL_PADDED".equals(ap.concealmentMode) ? ssid.length : null;
        byte[] meshId = ies.first(114);
        ap.meshId = meshId.length <= 32 && !hidden(meshId) ? Dot11InformationElements.ssidLabel(meshId) : null;
        ap.beaconHiddenRole = isMesh(ies) ? "MESH_POINT" : SecurityDecoder.isMultiApBackhaul(ies) ? "MULTI_AP_BACKHAUL"
                : SecurityDecoder.hasOweTransitionElement(ies) ? "OWE_TRANSITION_BSS" : null;
        if (ap.name != null && ap.name.confidence() != RevealConfidence.AP_AUTHORITATIVE
                && (!ap.hidden || !matchesMaskedLength(ap, ap.name.length()))) ap.name = null;

        var owe = SecurityDecoder.decodeOweTransition(ies);
        String peerId = owe == null ? null : ids.id("wifi", owe.peerBssid());
        if (owe != null && !id.equals(peerId)) {
            linkOwe(ap, peerId, time);
            if (ap.hidden) {
                reveal(ap, owe.ssidBytes(), "OWE_TRANSITION", time, RevealConfidence.AP_AUTHORITATIVE, null);
            } else if ((capability & 16) == 0 && security.profiles().isEmpty() && allowsBssid.test(owe.peerBssid())) {
                Ap peer = ap(peerId, time);
                if (peer.owePartnerName == null || time >= peer.owePartnerName.observedAt()) {
                    peer.owePartnerName = new OwePair(id, owe.ssidBytes(), time);
                    linkOwe(peer, id, time);
                    applyOwePartnerName(peer);
                }
            }
        }
        applyOwePartnerName(ap);
    }

    private void observeNeighborReports(Dot11InformationElements ies, long time) {
        for (var neighbor : Dot11ChannelSwitchDecoder.decodeReducedNeighborReport(ies)) {
            String bssid = neighbor.bssid();
            if (neighbor.shortSsid() == null || !unicast(bssid) || !allowsBssid.test(bssid)) continue;
            Ap reported = ap(ids.id("wifi", bssid), time);
            if (time >= reported.rnrObservedAt) {
                reported.rnrShortSsid = neighbor.shortSsid();
                reported.rnrObservedAt = time;
            }
        }
    }

    private static boolean isMesh(Dot11InformationElements ies) {
        return ies.has(113) || ies.has(114);
    }

    private static void linkOwe(Ap ap, String peerId, long time) {
        if (time < ap.oweObservedAt) return;
        ap.owePeerBssid = peerId;
        ap.oweObservedAt = time;
    }

    private void applyOwePartnerName(Ap ap) {
        var pair = ap.owePartnerName;
        if (ap.hidden && pair != null && pair.peerId().equals(ap.owePeerBssid)) {
            reveal(ap, pair.ssid(), "OWE_TRANSITION", pair.observedAt(), RevealConfidence.AP_AUTHORITATIVE, null);
        }
    }

    private void observeProbe(Dot11Frame frame) {
        String bssid = frame.addr3();
        if (!allowsBssid.test(bssid)) return;
        byte[] ssid = frame.ies().first(0);
        rememberShortSsid(ssid, frame.timestamp());
        if (!unicast(bssid) || !bssid.equals(frame.addr1()) || bssid.equals(frame.addr2()) || !unicast(frame.addr2())) return;
        Ap ap = aps.get(ids.id("wifi", bssid));
        if (ap != null) reveal(ap, ssid, "PROBE_REQ", frame.timestamp(), RevealConfidence.TENTATIVE_CLIENT, null);
    }

    private void rejectAssociation(Link key, int subtype, long time) {
        var edge = edges.get(key);
        if (edge != null && edge.nameClaim != null && edge.nameClaim.matchesResponse(subtype, time)) edge.nameClaim = null;
        Ap ap = aps.get(key.ap());
        if (ap == null || ap.name == null || ap.name.confidence() != RevealConfidence.TENTATIVE_CLIENT) return;
        var claim = ap.name.association();
        if (claim != null && claim.link().equals(key) && claim.matchesResponse(subtype, time)) ap.name = null;
    }

    private void reveal(Ap ap, byte[] ssid, String source, long observedAt, RevealConfidence confidence,
                        AssociationClaim association) {
        if (hidden(ssid) || confidence != RevealConfidence.AP_AUTHORITATIVE
                && (!ap.hidden || !matchesMaskedLength(ap, ssid.length))) return;
        SsidReveal current = ap.name;
        if (current != null && (confidence.compareTo(current.confidence()) < 0
                || confidence == current.confidence() && observedAt < current.observedAt())) return;
        ap.name = ssidReveal(ssid, source, observedAt, confidence, association);
    }

    private SsidReveal ssidReveal(byte[] ssid, String source, long time, RevealConfidence confidence,
                                  AssociationClaim association) {
        return new SsidReveal(Dot11InformationElements.ssidLabel(ssid), ids.id("topology-ssid", ssid),
                source, time, confidence, ssid.length, association);
    }

    private static boolean matchesMaskedLength(Ap ap, int length) {
        return ap.maskedSsidLength == null || ap.maskedSsidLength == length;
    }

    private void rememberShortSsid(byte[] ssid, long time) {
        if (hidden(ssid)) return;
        int key = Dot11ChannelSwitchDecoder.shortSsidCrc32(ssid);
        var current = shortSsids.get(key);
        // Keep collision markers for the entire session, including when the corpus is full.
        if (current == null) {
            if (shortSsids.size() < SHORT_SSID_LIMIT) shortSsids.put(key, new ShortSsidMatch(ssid, time));
        } else if (current.ssid() != null && !Arrays.equals(current.ssid(), ssid)) {
            shortSsids.put(key, new ShortSsidMatch(null, time));
        }
    }

    private SsidReveal resolvedName(Ap ap) {
        if (!ap.hidden || ap.rnrShortSsid == null
                || ap.name != null && ap.name.confidence() == RevealConfidence.AP_AUTHORITATIVE) return ap.name;
        var match = shortSsids.get(ap.rnrShortSsid);
        if (match == null || match.ssid() == null || !matchesMaskedLength(ap, match.ssid().length)) return ap.name;
        // A later CRC collision withdraws this derived reveal without discarding independent evidence.
        long time = Math.max(ap.beaconNameObservedAt, Math.max(ap.rnrObservedAt, match.observedAt()));
        return ssidReveal(match.ssid(), "RNR_SHORT_SSID", time, RevealConfidence.AP_AUTHORITATIVE, null);
    }

    void purge(long now, long retention) {
        aps.values().removeIf(ap -> ap.last < now - retention);
        for (var ap : aps.values()) {
            if (ap.radioObservation != null && ap.radioObservation.timestamp() < now - retention) {
                ap.radioObservation = null;
            }
        }
        edges.values().removeIf(edge -> edge.observedThrough() <= now - Math.min(edgeTtl, retention));
        meshLinks.values().removeIf(link -> link.lastSeen() <= now - Math.min(edgeTtl, retention));
        roams.removeIf(event -> event.time < now - retention);
        btmRejections.removeIf(event -> event.time < now - retention);
        btmExchanges.values().removeIf(exchange -> exchange.time < now - Math.min(BTM_WINDOW_MS, retention));
        linkRadios.values().removeIf(radio -> Math.max(radio.signalAt, radio.frequencyAt) < now - Math.min(edgeTtl, retention));
        memberships.values().removeIf(link -> link.time < now - Math.min(edgeTtl, retention));
        clientTracks.values().removeIf(track -> track.lastSeen < now - roamWindow
                && track.mldSeen < now - retention);
        recent.values().removeIf(time -> time < now - RETRY_MS);
    }

    private record ApCopy(String id, List<Double> rssi, List<ClockSample> clocks, SsidReveal name,
                          String security, String domain, String country,
                          List<AdvertisedSecurity> advertisedSecurity, Integer stations, Integer utilization,
                          Integer admissionCapacity, int frequency, int channel, int interval, boolean hidden,
                          long last, long beaconNameObservedAt, List<String> securityModes,
                          CapabilityDecoder.ManagementFeatures managementFeatures, Dot11Frame.RadioObservation radioObservation,
                          String transmitter, String mldId, String concealmentMode, Integer maskedSsidLength,
                          String meshId, String hiddenRole, String owePeerBssid,
                          String vendor, String apHostname, WpsInfo wpsInfo, ApRadioSummary apRadio,
                          String groupManagementCipher, List<String> rsnxeFeatures, boolean beaconProtection,
                          boolean ocvc) { }

    static final class PendingSnapshot {
        private final SessionIdentifiers ids;
        private final List<AssociationEdge> links;
        private final List<ApCopy> apCopies;
        private final List<RoamEvent> roams;
        private final List<MeshLink> meshLinks;
        private final List<BtmRejection> btmRejections;
        private final boolean revealNames;

        private PendingSnapshot(SessionIdentifiers ids, List<AssociationEdge> links,
                                List<ApCopy> apCopies, List<RoamEvent> roams, List<MeshLink> meshLinks,
                                List<BtmRejection> btmRejections, boolean revealNames) {
            this.ids = ids;
            this.links = links;
            this.apCopies = apCopies;
            this.roams = roams;
            this.meshLinks = meshLinks;
            this.btmRejections = btmRejections;
            this.revealNames = revealNames;
        }

        Snapshot build() {
            var sortedLinks = new ArrayList<>(links);
            sortedLinks.sort(Comparator.comparing(AssociationEdge::bssid).thenComparing(AssociationEdge::clientId));
            var clients = new TreeMap<String, List<String>>();
            for (var edge : sortedLinks) clients.computeIfAbsent(edge.bssid(), id -> new ArrayList<>()).add(edge.clientId());

            var ess = new TreeMap<String, List<String>>();
            var output = new ArrayList<AccessPoint>(apCopies.size());
            var radio = new TreeMap<String, String>();
            var clocks = new TreeMap<Integer, TreeMap<String, ApCopy>>();
            var sortedAps = new TreeMap<String, ApCopy>();
            for (ApCopy ap : apCopies) {
                sortedAps.put(ap.id(), ap);
                if (ap.clocks().size() >= 5) clocks.computeIfAbsent(ap.frequency(), freq -> new TreeMap<>()).put(ap.id(), ap);
            }
            for (var channel : clocks.values()) {
                for (var a : channel.entrySet()) {
                    if (radio.containsKey(a.getKey())) continue;
                    for (var b : channel.tailMap(a.getKey(), false).entrySet()) {
                        if (!radio.containsKey(b.getKey()) && sameClock(a.getValue().clocks(), b.getValue().clocks())) {
                            radio.putIfAbsent(a.getKey(), a.getKey());
                            radio.put(b.getKey(), a.getKey());
                        }
                    }
                }
            }
            for (ApCopy ap : apCopies) {
                if (ap.transmitter() != null) {
                    radio.putIfAbsent(ap.transmitter(), ap.transmitter());
                    radio.put(ap.id(), radio.get(ap.transmitter()));
                }
            }
            var visibleByRadio = new HashMap<String, List<String>>();
            var visibleByMld = new HashMap<String, List<String>>();
            var visibleByOwePeer = new HashMap<String, List<String>>();
            for (ApCopy ap : apCopies) {
                if (ap.hidden() || ap.name() == null) continue;
                String ssid = ap.name().label();
                indexVisibleSsid(visibleByRadio, radio.get(ap.id()), ssid);
                indexVisibleSsid(visibleByMld, ap.mldId(), ssid);
                indexVisibleSsid(visibleByOwePeer, ap.owePeerBssid(), ssid);
            }
            for (var row : sortedAps.entrySet()) {
                String key = row.getKey();
                ApCopy ap = row.getValue();
                SsidReveal name = ap.name();
                String ssid = name == null ? null : name.label(), ssidToken = name == null ? null : name.token();
                String group = ssidToken == null || ap.security() == null ? null
                        : ids.id("ess", ssidToken + ":" + ap.security() + ":" + Objects.toString(ap.domain(), ""));
                if (group != null) ess.computeIfAbsent(group, id -> new ArrayList<>()).add(key);
                Double median = ap.rssi().isEmpty() ? null : WifiInventory.median(ap.rssi().stream().sorted().toList());
                String hiddenNameSource = ap.hidden() && name != null ? name.source() : "NONE";
                var hiddenEvidence = ap.hidden() ? new HiddenSsidEvidence(revealNames ? ssid : null, hiddenNameSource,
                        name == null ? null : name.observedAt(), ap.beaconNameObservedAt()) : null;
                String legacyNameSource = hiddenNameSource.equals("REASSOC_REQ") ? "ASSOC_REQ" : hiddenNameSource;
                var siblings = new TreeSet<String>();
                if (ap.hidden()) {
                    siblings.addAll(visibleByRadio.getOrDefault(radio.get(key), List.of()));
                    siblings.addAll(visibleByMld.getOrDefault(ap.mldId(), List.of()));
                    siblings.addAll(visibleByOwePeer.getOrDefault(key, List.of()));
                    siblings.addAll(visibleByOwePeer.getOrDefault(ap.owePeerBssid(), List.of()));
                    ApCopy peer = ap.owePeerBssid() == null ? null : sortedAps.get(ap.owePeerBssid());
                    if (peer != null && !peer.hidden() && peer.name() != null) siblings.add(peer.name().label());
                }
                output.add(new AccessPoint(key, ssid, ssidToken, ap.hidden(), legacyNameSource, ap.channel(),
                        WifiInventory.band(ap.frequency()), ap.security(), ap.interval(), ap.domain(), ap.stations(),
                        ap.utilization(), ap.admissionCapacity(), ap.country(), radio.get(key), group, median,
                        median == null ? null : median > -55 ? "STRONG" : median < -75 ? "WEAK" : "MEDIUM",
                        ap.last(), clients.getOrDefault(key, List.of()).stream().sorted().toList(),
                        ap.advertisedSecurity(), hiddenEvidence, ap.frequency(), ap.securityModes(), ap.managementFeatures(),
                        ap.radioObservation(), ap.transmitter() != null, ap.mldId(), ap.concealmentMode(),
                        ap.maskedSsidLength(), name == null ? null : name.confidence().name(), ap.meshId(), ap.hiddenRole(),
                        ap.owePeerBssid(), List.copyOf(siblings), ap.vendor(), ap.apHostname(), ap.wpsInfo(),
                        ap.apRadio(), ap.groupManagementCipher(), ap.rsnxeFeatures(), ap.beaconProtection(), ap.ocvc()));
            }
            ess.replaceAll((key, values) -> List.copyOf(values));
            return new Snapshot(List.copyOf(output), Map.copyOf(ess), List.copyOf(sortedLinks), roams, meshLinks, btmRejections);
        }

        private static void indexVisibleSsid(Map<String, List<String>> index, String key, String ssid) {
            if (key != null) index.computeIfAbsent(key, ignored -> new ArrayList<>()).add(ssid);
        }
    }

    Snapshot snapshot() { return snapshot(Long.MAX_VALUE); }

    record AssociationEvidence(long lastSeen, int frequencyMhz, String source) { }

    long associationRetention(long retention) { return Math.min(edgeTtl, retention); }

    AssociationEvidence associationEvidence(String clientId, String apId) {
        Edge edge = edges.get(new Link(clientId, apId));
        if (edge == null || (edge.legacyAssociation == null && edge.legacyData < minimum)) return null;
        return new AssociationEvidence(edge.legacyLast, edge.legacyFrequency,
                edge.legacyAssociation != null ? edge.legacyAssociation : "DATA");
    }

    Map<String, WifiInventory.AssociatedAp> associatedAps(String clientId) {
        var latest = new HashMap<String, Map.Entry<Link, Edge>>();
        for (var row : edges.entrySet()) {
            Link link = row.getKey();
            Edge edge = row.getValue();
            if ((clientId != null && !clientId.equals(link.client)) || !edge.confirmed
                    || !"ACTIVE".equals(edge.state) || !aps.containsKey(link.ap)) continue;
            latest.merge(link.client, row, (a, b) -> {
                int recent = Long.compare(a.getValue().lastEvidence(), b.getValue().lastEvidence());
                return recent > 0 || recent == 0 && a.getKey().ap.compareTo(b.getKey().ap) < 0 ? a : b;
            });
        }
        var result = new HashMap<String, WifiInventory.AssociatedAp>();
        latest.forEach((client, row) -> {
            String apId = row.getKey().ap;
            Ap ap = aps.get(apId);
            SsidReveal name = resolvedName(ap);
            Edge edge = row.getValue();
            int frequency = edge.frequency > 0 ? edge.frequency : ap.frequency;
            int channel = frequency > 0 ? Dot11FrameDecoder.channel(frequency) : ap.channel;
            result.put(client, new WifiInventory.AssociatedAp(apId, name == null ? null : name.label(),
                    channel, frequency, edge.source()));
        });
        return result;
    }

    PendingSnapshot prepareSnapshot(long retention) {
        var links = new ArrayList<AssociationEdge>();
        for (var row : edges.entrySet()) {
            Link key = row.getKey();
            Edge edge = row.getValue();
            if (!edge.confirmed || !aps.containsKey(key.ap)) continue;
            long lastEvidence = edge.lastEvidence();
            ClientTrack track = clientTracks.get(key.client);
            links.add(new AssociationEdge(key.client, key.ap, edge.first, lastEvidence, edge.count, edge.up, edge.down,
                    edge.source(),
                    edge.lastData < 0 ? null : edge.lastData, edge.associationSeen < 0 ? null : edge.associationSeen,
                    lastEvidence + Math.min(edgeTtl, retention), Dot11FrameDecoder.channel(edge.frequency), edge.frequency,
                    edge.state, edge.control, track == null ? null : track.mldId));
        }
        var apCopies = new ArrayList<ApCopy>(aps.size());
        for (var row : aps.entrySet()) {
            Ap ap = row.getValue();
            apCopies.add(new ApCopy(row.getKey(), List.copyOf(ap.rssi), List.copyOf(ap.clocks), resolvedName(ap),
                    ap.security, ap.domain, ap.country, ap.advertisedSecurity,
                    ap.stations, ap.utilization, ap.admissionCapacity, ap.frequency, ap.channel, ap.interval,
                    ap.hidden, ap.last, ap.beaconNameObservedAt, ap.securityModes,
                    ap.managementFeatures, ap.radioObservation, ap.transmitter, ap.mldId, ap.concealmentMode,
                    ap.maskedSsidLength, ap.meshId, ap.hiddenRole(), ap.owePeerBssid, ap.vendor, ap.hostname.value,
                    ap.wps == null ? null : ap.wps.info(), ap.apRadio, ap.groupManagementCipher, ap.rsnxeFeatures,
                    ap.beaconProtection, ap.ocvc));
        }
        var mesh = meshLinks.values().stream().sorted(Comparator.comparing(MeshLink::peerA)
                .thenComparing(MeshLink::peerB)).toList();
        return new PendingSnapshot(ids, links, apCopies, List.copyOf(roams), mesh, List.copyOf(btmRejections), revealNames);
    }

    Snapshot snapshot(long retention) {
        return prepareSnapshot(retention).build();
    }

    private static boolean sameClock(List<ClockSample> aClocks, List<ClockSample> bClocks) {
        // A shared clock yields nearly equal AP-minus-receiver TSF offsets. Pair nearby beacons
        // one to one so a single sample cannot establish a group, even at different beacon rates.
        var left = aClocks.iterator();
        var right = bClocks.iterator();
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

    private static boolean isLocallyAdministered(String mac) {
        return unicast(mac) && (Integer.parseInt(mac.substring(0, 2), 16) & 2) != 0;
    }

    private static String globalOuiPrefix5(String mac) {
        if (!unicast(mac) || isLocallyAdministered(mac) || mac.length() < 14) return null;
        return mac.substring(0, 14).toLowerCase(Locale.ROOT);
    }

    private static int u16(byte[] bytes, int offset) { return (bytes[offset] & 0xff) | (bytes[offset + 1] & 0xff) << 8; }

    private static final class ClientTrack {
        boolean local;
        String cohort;
        String bandCohort;
        String apId;
        String band;
        String mldId;
        long lastSeen = -1, mldSeen = -1;
    }

    private static final class LinkRadio {
        Integer signal;
        int frequency;
        long signalAt = -1, frequencyAt = -1;
    }

    private static final class AdvertisedField<T> {
        private T value;
        private long timestamp = Long.MIN_VALUE;

        void observe(T observed, long time) {
            if (observed != null && time >= timestamp) {
                value = observed;
                timestamp = time;
            }
        }
    }

    private static final class WpsObservation {
        private final AdvertisedField<String> state = new AdvertisedField<>();
        private final AdvertisedField<Boolean> locked = new AdvertisedField<>();
        private final AdvertisedField<String> manufacturer = new AdvertisedField<>();
        private final AdvertisedField<String> modelName = new AdvertisedField<>();
        private final AdvertisedField<String> modelNumber = new AdvertisedField<>();
        private final AdvertisedField<String> deviceName = new AdvertisedField<>();

        void observe(WpsInfo info, long time) {
            state.observe(info.state(), time);
            locked.observe(info.apSetupLocked(), time);
            manufacturer.observe(info.manufacturer(), time);
            modelName.observe(info.modelName(), time);
            modelNumber.observe(info.modelNumber(), time);
            deviceName.observe(info.deviceName(), time);
        }

        WpsInfo info() {
            return new WpsInfo(state.value, locked.value, manufacturer.value, modelName.value, modelNumber.value, deviceName.value);
        }
    }

    private static final class Ap {
        final ArrayDeque<Double> rssi = new ArrayDeque<>();
        final ArrayDeque<ClockSample> clocks = new ArrayDeque<>();
        SsidReveal name;
        String security, domain, country, ouiPrefix5;
        String transmitter, mldId;
        String concealmentMode, meshId, beaconHiddenRole, owePeerBssid;
        Integer maskedSsidLength, rnrShortSsid;
        OwePair owePartnerName;
        List<AdvertisedSecurity> advertisedSecurity = List.of();
        List<String> securityModes = List.of();
        String vendor, groupManagementCipher;
        final AdvertisedField<String> hostname = new AdvertisedField<>();
        WpsObservation wps;
        ApRadioSummary apRadio;
        List<String> rsnxeFeatures = List.of();
        boolean beaconProtection, ocvc;
        CapabilityDecoder.ManagementFeatures managementFeatures;
        Dot11Frame.RadioObservation radioObservation;
        Integer stations, utilization, admissionCapacity;
        int frequency, channel, interval;
        boolean hidden;
        long last, beaconNameObservedAt = -1, advertisedAt = -1, oweObservedAt = -1, rnrObservedAt = -1;

        String hiddenRole() {
            if (!hidden) return null;
            if (beaconHiddenRole != null) return beaconHiddenRole;
            return owePeerBssid != null ? "OWE_TRANSITION_BSS" : "HIDDEN_INFRASTRUCTURE";
        }

        void signal(double value) {
            if (!Double.isFinite(value)) return;
            if (rssi.size() == 64) rssi.removeFirst();
            rssi.addLast(value);
        }
    }

    private static final class Edge {
        long first = Long.MAX_VALUE, last, count, up, down, control;
        long lastData = -1, associationSeen = -1, lastControl = -1, stateAt = -1;
        int frequency, legacyFrequency;
        long legacyData, legacyLast = -1;
        boolean confirmed, psPollSeen;
        String associationType, state = "ACTIVE", legacyAssociation;
        AssociationClaim nameClaim;

        // The existing association/data view ages independently of passive control observations.
        void observeAssociationEvidence(Dot11Frame frame, boolean association, long ttl) {
            long time = frame.timestamp();
            if (legacyLast >= 0 && time - legacyLast >= ttl) {
                legacyData = 0;
                legacyAssociation = null;
                legacyFrequency = 0;
            }
            if (time < legacyLast && legacyLast - time >= ttl) return;
            if (frame.frequencyMhz() > 0 && (legacyFrequency == 0 || time >= legacyLast))
                legacyFrequency = frame.frequencyMhz();
            legacyLast = Math.max(legacyLast, time);
            if (!association) legacyData++;
            else if (legacyAssociation == null || time >= associationSeen)
                legacyAssociation = frame.subtype() == 1 ? "ASSOC" : "REASSOC";
        }

        long lastEvidence() { return Math.max(Math.max(lastData, associationSeen), lastControl); }
        long observedThrough() { return confirmed ? lastEvidence() : last; }
        String source() {
            return associationSeen >= 0 ? associationType : psPollSeen && up + down == 0 ? "CONTROL" : "DATA";
        }
    }
}
