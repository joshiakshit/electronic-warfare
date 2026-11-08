package ewave.decoder;

/** Management metadata or a data header. Data payloads never leave the decoder. */
public record Dot11Frame(int type, int subtype, int flags, int sequenceControl, int tid,
                         String addr1, String addr2, String addr3, String addr4,
                         long timestamp, int frequencyMhz, double rssi, Long radiotapTsft,
                         int frameLength, Dot11InformationElements ies, Long beaconTsf,
                         int beaconIntervalTu, int capability, String currentAp, int status,
                         int authenticationAlgorithm) {
    public boolean management() { return type == 0; }
    public boolean retry() { return (flags & 8) != 0; }
    public boolean powerSave() { return (flags & 16) != 0; }
    public int ds() { return flags & 3; }
    public boolean probe() { return management() && subtype == 4; }
    public boolean apAdvertisement() { return management() && (subtype == 5 || subtype == 8); }
}
