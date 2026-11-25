package ewave.decoder;

/** Management metadata or a data or control header. Data payloads never leave the decoder. */
public record Dot11Frame(int type, int subtype, int flags, int sequenceControl, int tid,
                         String addr1, String addr2, String addr3, String addr4,
                         long timestamp, int frequencyMhz, double rssi, Long radiotapTsft,
                         int frameLength, Dot11InformationElements ies, Long beaconTsf,
                         int beaconIntervalTu, int capability, String currentAp, int status,
                         int authenticationAlgorithm, Radiotap radiotap) {
    public Dot11Frame(int type, int subtype, int flags, int sequenceControl, int tid, String addr1, String addr2,
                      String addr3, String addr4, long timestamp, int frequencyMhz, double rssi, Long radiotapTsft,
                      int frameLength, Dot11InformationElements ies, Long beaconTsf, int beaconIntervalTu,
                      int capability, String currentAp, int status, int authenticationAlgorithm) {
        this(type, subtype, flags, sequenceControl, tid, addr1, addr2, addr3, addr4, timestamp, frequencyMhz, rssi,
                radiotapTsft, frameLength, ies, beaconTsf, beaconIntervalTu, capability, currentAp, status,
                authenticationAlgorithm, null);
    }

    public int sequenceNumber() { return sequenceControl >>> 4; }
    public record RadioObservation(long timestamp, int frequencyMhz, Radiotap metadata) { }

    public RadioObservation radioObservation() {
        return radiotap == null ? null : new RadioObservation(timestamp, frequencyMhz, radiotap);
    }
    public boolean management() { return type == 0; }
    public boolean retry() { return (flags & 8) != 0; }
    public boolean powerSave() { return (flags & 16) != 0; }
    public int ds() { return flags & 3; }
    public boolean probe() { return management() && subtype == 4; }
    public boolean apAdvertisement() { return management() && (subtype == 5 || subtype == 8); }
}
