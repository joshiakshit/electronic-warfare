package ewave.active;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.TreeSet;

/** Matches pairwise EAPOL messages from one AP, station, and association attempt. */
final class HandshakePackets {
    static final List<String> FIELDS = List.of(
            "wlan.fc.type_subtype", "radiotap.channel.freq", "wlan.bssid", "wlan.sa", "wlan.da",
            "wlan.ds.current_channel", "wlan.ht.info.primarychannel", "wlan.ext_tag.he_operation.6ghz.primary_channel",
            "wlan_rsna_eapol.keydes.msgnr", "eapol.keydes.replay_counter",
            "wlan_rsna_eapol.keydes.nonce", "wlan_rsna_eapol.keydes.key_info.key_type");

    record Observation(String clientMac, List<Integer> messages, boolean complete) {}

    private final String ap;
    private final String client;
    private final int frequency;
    private final int channel;
    private final LinkedHashMap<String, Exchange> exchanges = new LinkedHashMap<>();
    private boolean beaconSeen;
    private Observation best;

    HandshakePackets(String ap, String client, int frequency, int channel) {
        this.ap = ap;
        this.client = client;
        this.frequency = frequency;
        this.channel = channel;
        best = new Observation(client, List.of(), false);
    }

    synchronized void accept(String row) {
        String[] fields = row.split("\t", -1);
        if (fields.length != FIELDS.size() || !ap.equalsIgnoreCase(fields[2])) return;
        if (!fields[1].isEmpty() && !fields[1].equals(Integer.toString(frequency))) return;
        String subtype = fields[0];
        if (subtype.equals("0x0008")) {
            if (ap.equalsIgnoreCase(fields[3]) && beaconMatchesChannel(fields)) beaconSeen = true;
            return;
        }
        boolean fromAp = ap.equalsIgnoreCase(fields[3]);
        String peer = (fromAp ? fields[4] : fields[3]).toLowerCase(Locale.ROOT);
        if (!HandshakeAnalyzer.isStationAddress(peer)
                || (!fromAp && !ap.equalsIgnoreCase(fields[4]))
                || (client != null && !client.equalsIgnoreCase(peer))) return;
        if (subtype.equals("0x0000") || subtype.equals("0x0002")) {
            exchanges.remove(peer);
            return;
        }
        if (!fields[11].equals("1") && !fields[11].equalsIgnoreCase("true")) return;
        if (fields[8].length() != 1 || fields[8].charAt(0) < '1' || fields[8].charAt(0) > '4') return;
        int message = fields[8].charAt(0) - '0';
        if (fromAp != (message == 1 || message == 3)) return;
        long replay;
        try {
            replay = Long.parseUnsignedLong(fields[9]);
        } catch (NumberFormatException invalid) {
            return;
        }
        var exchange = exchanges.computeIfAbsent(peer, ignored -> new Exchange());
        if (exchange.accept(message, replay, fields[10])) {
            var observation = new Observation(peer, new ArrayList<>(exchange.messages), exchange.complete);
            if (!best.complete() && (observation.complete() || observation.messages().size() > best.messages().size())) {
                best = observation;
            }
        }
    }

    private boolean beaconMatchesChannel(String[] fields) {
        String expected = Integer.toString(channel);
        boolean advertised = false;
        for (int i = 5; i <= 7; i++) {
            if (fields[i].isEmpty()) continue;
            advertised = true;
            if (!expected.equals(fields[i])) return false;
        }
        return advertised || !fields[1].isEmpty();
    }

    synchronized boolean beaconSeen() { return beaconSeen; }
    synchronized Observation observation() { return best; }

    private static final class Exchange {
        final TreeSet<Integer> messages = new TreeSet<>();
        String apNonce;
        long firstReplay;
        Long thirdReplay;
        boolean matchingResponse;
        boolean complete;

        boolean accept(int message, long replay, String nonce) {
            if (message == 1 && (!nonce.equals(apNonce) || replay != firstReplay)) {
                messages.clear();
                apNonce = nonce;
                firstReplay = replay;
                matchingResponse = false;
                thirdReplay = null;
                complete = false;
            }
            if (message == 2 && apNonce != null && replay == firstReplay) matchingResponse = true;
            if (message == 3 && matchingResponse && !nonce.isEmpty() && nonce.equals(apNonce)
                    && Long.compareUnsigned(replay, firstReplay) > 0) thirdReplay = replay;
            if (message == 4 && thirdReplay != null && replay == thirdReplay) complete = true;
            return messages.add(message) || complete;
        }
    }
}
