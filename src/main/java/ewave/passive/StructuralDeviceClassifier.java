package ewave.passive;

import ewave.decoder.CapabilityDecoder;
import ewave.decoder.Dot11InformationElements;
import ewave.passive.WifiInventory.Role;

import java.util.List;
import java.util.regex.Pattern;

/** Classifies a transmitter from passive management and data frame evidence. */
final class StructuralDeviceClassifier {
    record Classification(String family, String osHint, double confidence, String basis) { }

    private static final String VENDOR_IE = "VENDOR_IE_HEURISTIC";
    private static final String RADIO = "RADIO_CAPABILITY_HEURISTIC";
    private static final String OUI = "OUI_VENDOR";
    private static final Pattern IOT_VENDOR = Pattern.compile(
            "\\b(?:espressif|tuya|shenzhen bilian|sonoff|raspberry pi)\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern ANDROID_VENDOR = Pattern.compile(
            "\\b(?:samsung|xiaomi|oneplus|oppo|vivo)\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern APPLE_VENDOR = Pattern.compile("\\bapple\\b", Pattern.CASE_INSENSITIVE);

    private String wpsFamily;
    private long wpsTypeSeen = Long.MIN_VALUE;
    private boolean apple, samsung, android, microsoft, multipleBssids;

    void observe(Dot11InformationElements ies, long time, boolean apAdvertisement) {
        if (apAdvertisement) multipleBssids |= ies.has(71) || ies.extension(107).length > 0;
        boolean hasWps = false;
        for (var element : ies.elements()) {
            String oui = element.vendorOui();
            if (oui == null) continue;
            switch (oui) {
                case "0017f2", "00a040" -> apple = true;
                case "0000f0" -> samsung = true;
                case "001a11" -> android = true;
                case "0050f2" -> {
                    String key = element.vendorKey();
                    hasWps |= "0050f204".equals(key);
                    microsoft |= "0050f208".equals(key);
                }
                default -> { }
            }
        }
        if (hasWps) {
            microsoft |= ies.wpsManufacturer().filter("Microsoft"::equalsIgnoreCase).isPresent();
            String family = ies.wpsPrimaryDeviceType().map(StructuralDeviceClassifier::wpsFamily).orElse(null);
            if (family != null && time >= wpsTypeSeen) {
                wpsFamily = family;
                wpsTypeSeen = time;
            }
        }
    }

    Classification classify(FingerprintDb.Finding finding, Role role, boolean local, boolean androidScanPrefix,
                            String vendor, List<String> bands, CapabilityDecoder.Summary caps,
                            boolean dataRadioSeen, String inferredGeneration) {
        if (finding != null)
            return new Classification(finding.family(), finding.osHint(), finding.confidence(), finding.basis());
        if (wpsFamily != null) return new Classification(wpsFamily, null, 0.85, "WPS_DEVICE_TYPE");
        if (apple) {
            if (role == Role.AP && local) return new Classification("Mobile Hotspot", "iOS", 0.82, VENDOR_IE);
            if (caps != null && caps.spatialStreams() >= 3) return new Classification("Laptop", "macOS", 0.78, VENDOR_IE);
            return new Classification("Phone / Tablet", "iOS / iPadOS", 0.78, VENDOR_IE);
        }
        if (samsung) return new Classification("Phone", "Android (Samsung)", 0.80, VENDOR_IE);
        if (microsoft) return new Classification("Laptop / PC", "Windows", 0.76, VENDOR_IE);
        if (android || local && androidScanPrefix) return new Classification("Phone", "Android", 0.75, VENDOR_IE);

        if (role == Role.AP) {
            boolean mobilityDomain = caps != null && caps.managementFeatures().mobilityDomain() != null;
            if (local && !mobilityDomain && (bands.contains("2.4 GHz") || !multipleBssids))
                return new Classification("Mobile Hotspot", null, 0.70, RADIO);
            return new Classification("Access Point", null, 0.85, RADIO);
        }
        if (!local && vendor != null) return classifyVendor(vendor);
        if (local && caps != null) {
            var features = caps.managementFeatures();
            boolean roaming = features.bssTransition() || features.fastTransition();
            if (bands.equals(List.of("2.4 GHz")) && "Wi-Fi 4".equals(caps.wifiGeneration())
                    && caps.spatialStreams() == 1 && caps.maxWidthMhz() == 20 && !roaming)
                return new Classification("IoT / Embedded", null, 0.60, RADIO);
            if (WifiInventory.rank(caps.wifiGeneration()) >= 5 && caps.spatialStreams() == 2 && roaming)
                return new Classification("Phone / Mobile Client", null, 0.52, RADIO);
        }
        if (role == Role.CLIENT && caps == null && dataRadioSeen) {
            String family = "Wi-Fi 6".equals(inferredGeneration) || "Wi-Fi 6E".equals(inferredGeneration)
                    ? inferredGeneration + " Client" : "Active Client";
            return new Classification(family, null, 0.40, "RADIOTAP_DATA_HEURISTIC");
        }
        return new Classification("UNCLASSIFIED", null, local ? 0.1 : 0, null);
    }

    private static Classification classifyVendor(String vendor) {
        if (IOT_VENDOR.matcher(vendor).find()) return new Classification("IoT / Embedded", null, 0.70, OUI);
        if (APPLE_VENDOR.matcher(vendor).find()) return new Classification("Apple Device", "iOS / macOS", 0.65, OUI);
        if (ANDROID_VENDOR.matcher(vendor).find()) return new Classification("Phone", "Android", 0.60, OUI);
        return new Classification(vendor, null, 0.30, OUI);
    }

    private static String wpsFamily(Dot11InformationElements.WpsDeviceType type) {
        return switch (type.category()) {
            case 1 -> type.subcategory() == 5 ? "Laptop" : "Computer / PC";
            case 3 -> "Printer";
            case 4 -> "Camera";
            case 6 -> "Access Point";
            case 7 -> "Smart TV / Display";
            case 8 -> "Media / Console";
            case 10 -> "Phone";
            default -> null;
        };
    }
}
