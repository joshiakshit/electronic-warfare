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

    record Observation(String clientMac, List<Integer> messages, boolean complete,
                       boolean verifiable, String verifiablePair, int eapolFrames) {}

    private final String ap;
    private final String client;
    private final int frequency;
    private final int channel;
    private final boolean allowMacRotation;
    private final LinkedHashMap<String, Exchange> exchanges = new LinkedHashMap<>();
    private boolean beaconSeen;
    private int totalEapolFrames;
    private Observation best;

    HandshakePackets(String ap, String client, int frequency, int channel) {
        this(ap, client, frequency, channel, false);
    }

    HandshakePackets(String ap, String client, int frequency, int channel, boolean allowMacRotation) {
        this.ap = ap;
        this.client = client;
        this.frequency = frequency;
        this.channel = channel;
        this.allowMacRotation = allowMacRotation;
        best = new Observation(client, List.of(), false, false, null, 0);
    }

    static boolean isLocallyAdministered(String mac) {
        return HandshakeAnalyzer.isStationAddress(mac) && (Integer.parseInt(mac.substring(0, 2), 16) & 2) != 0;
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
        if (!HandshakeAnalyzer.isStationAddress(peer) || (!fromAp && !ap.equalsIgnoreCase(fields[4]))) return;
        if (client != null && !client.equalsIgnoreCase(peer)
                && (!allowMacRotation || !isLocallyAdministered(peer))) return;
        if (subtype.equals("0x0000") || subtype.equals("0x0002")) {
            exchanges.remove(peer);
            recomputeBest();
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
        totalEapolFrames++;
        var exchange = exchanges.computeIfAbsent(peer, ignored -> new Exchange());
        exchange.accept(message, replay, fields[10]);
        recomputeBest();
    }

    private void recomputeBest() {
        if (client != null) {
            var pinned = exchanges.get(client.toLowerCase(Locale.ROOT));
            if (pinned != null && !pinned.effectiveMessages().isEmpty()) {
                String pair = pinned.currentPair();
                best = new Observation(client.toLowerCase(Locale.ROOT), pinned.effectiveMessages(),
                        pinned.complete, pair != null, pair, totalEapolFrames);
                return;
            }
        }
        Observation candidate = null;
        for (var entry : exchanges.entrySet()) {
            var exchange = entry.getValue();
            var msgs = exchange.effectiveMessages();
            if (msgs.isEmpty()) continue;
            String pair = exchange.currentPair();
            boolean verifiable = pair != null;
            if (candidate == null || (!candidate.complete() && (exchange.complete
                    || (!candidate.verifiable() && verifiable)
                    || (candidate.verifiable() == verifiable && msgs.size() > candidate.messages().size())))) {
                candidate = new Observation(entry.getKey(), msgs, exchange.complete, verifiable, pair, totalEapolFrames);
            }
        }
        best = candidate != null ? candidate : new Observation(client, List.of(), false, false, null, totalEapolFrames);
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
        Long secondReplay;
        String secondNonce;
        Long thirdReplay;
        boolean matchingResponse;
        boolean matchedTwoThree;
        boolean complete;
        String latchedPair;
        List<Integer> latchedMessages = List.of();

        void accept(int message, long replay, String nonce) {
            if (message == 1 && (!nonce.equals(apNonce) || replay != firstReplay)) {
                if (matchingResponse) {
                    latchedPair = "M1_M2";
                    latchedMessages = List.copyOf(messages);
                } else if (matchedTwoThree && latchedPair == null) {
                    latchedPair = "M2_M3";
                    latchedMessages = List.copyOf(messages);
                }
                messages.clear();
                apNonce = nonce;
                firstReplay = replay;
                matchingResponse = false;
                secondReplay = null;
                secondNonce = null;
                matchedTwoThree = false;
                thirdReplay = null;
                complete = false;
            }
            if (message == 2) {
                if (apNonce != null && !apNonce.isEmpty() && !nonce.isEmpty() && replay == firstReplay) {
                    matchingResponse = true;
                }
                if (!nonce.isEmpty()) {
                    secondReplay = replay;
                    secondNonce = nonce;
                }
            }
            if (message == 3) {
                if (matchingResponse && !nonce.isEmpty() && nonce.equals(apNonce)
                        && Long.compareUnsigned(replay, firstReplay) > 0) {
                    thirdReplay = replay;
                }
                if (secondReplay != null && secondNonce != null && !secondNonce.isEmpty() && !nonce.isEmpty()
                        && Long.compareUnsigned(replay, secondReplay) > 0 && replay - secondReplay <= 2) {
                    matchedTwoThree = true;
                }
            }
            if (message == 4 && thirdReplay != null && replay == thirdReplay) complete = true;
            messages.add(message);
        }

        String currentPair() {
            if (complete) return "M1_M2_M3_M4";
            if (matchingResponse) return "M1_M2";
            if (matchedTwoThree) return "M2_M3";
            return latchedPair;
        }

        List<Integer> effectiveMessages() {
            if (!complete && !matchingResponse && !matchedTwoThree && latchedPair != null) {
                return latchedMessages;
            }
            return new ArrayList<>(messages);
        }
    }
}
