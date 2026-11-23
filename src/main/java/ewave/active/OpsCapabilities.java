package ewave.active;

import java.io.File;
import java.io.IOException;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Read-only readiness report for the local Lab Ops control surface. */
public final class OpsCapabilities {
    public static final List<String> TOOLS = List.of("sudo", "iw", "aireplay-ng", "tcpdump", "tshark",
            "aircrack-ng", "hcxdumptool", "hcxpcapngtool", "mdk4", "mdk3", "hostapd", "dnsmasq", "python3");

    public record Tool(String name, boolean available, String path) { }
    public record Cache(String path, boolean available, long modifiedAt, int entries, String error) { }
    public record Operation(String id, String label, boolean ready, List<String> missing) { }
    public record Interface(String name, boolean up, boolean loopback, boolean virtual) { }

    @FunctionalInterface public interface ToolLocator {
        Path locate(String name);
    }

    private OpsCapabilities() { }

    public static Map<String, Object> snapshot(Path accessPointCache, Path lanCache, String wordlist,
                                               List<String> monitorInterfaces, List<Interface> interfaces,
                                               Map<String, Object> capture, String activeOperation,
                                               ToolLocator locator) {
        ToolLocator tools = locator == null ? systemPath() : locator;
        List<Tool> toolRows = TOOLS.stream().map(name -> {
            Path path = tools.locate(name);
            return new Tool(name, path != null, path == null ? null : path.toString());
        }).toList();
        Map<String, Boolean> available = new LinkedHashMap<>();
        toolRows.forEach(tool -> available.put(tool.name(), tool.available()));

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("operationsEnabled", true);
        response.put("tools", toolRows);
        response.put("operations", List.of(
                operation("deauth", "Deauthentication", available, List.of("sudo", "iw", "aireplay-ng"), List.of()),
                operation("uncloak", "Network name reveal", available, List.of("sudo", "iw", "aireplay-ng"), List.of()),
                operation("handshake", "Handshake capture", available, List.of("sudo", "iw", "tcpdump", "tshark"), List.of()),
                operation("handshake-verify", "PSK verification", available, List.of("aircrack-ng"), List.of()),
                operation("pmkid", "PMKID capture", available,
                        List.of("sudo", "hcxdumptool", "hcxpcapngtool", "aircrack-ng"), List.of()),
                operation("beacon", "Beacon flood", available, List.of("sudo"),
                        List.of("mdk4", "mdk3")),
                operation("evil-twin", "Evil twin", available, List.of("sudo", "hostapd", "dnsmasq", "python3"), List.of())));
        response.put("monitorInterfaces", monitorInterfaces == null ? List.of() : List.copyOf(monitorInterfaces));
        response.put("interfaces", interfaces == null ? List.of() : List.copyOf(interfaces));
        response.put("caches", Map.of(
                "accessPoints", cache(accessPointCache, path -> new WifiAccessPoints(path).all().size()),
                "lanHosts", cache(lanCache, path -> new LanScanner(path).scan().size())));
        response.put("wordlist", wordlist(wordlist));
        response.put("capture", capture == null ? Map.of() : capture);
        response.put("activeOperation", activeOperation);
        response.put("generatedAt", System.currentTimeMillis());
        return response;
    }

    /** Scans PATH without spawning a process, so readiness checks stay cheap on the API thread. */
    public static ToolLocator systemPath() {
        List<Path> directories = new ArrayList<>();
        String raw = System.getenv("PATH");
        if (raw != null) {
            for (String entry : raw.split(File.pathSeparator)) {
                if (!entry.isBlank()) directories.add(Path.of(entry));
            }
        }
        return name -> {
            if (name == null || name.isBlank() || name.indexOf('/') >= 0) return null;
            for (Path directory : directories) {
                Path candidate = directory.resolve(name);
                if (Files.isRegularFile(candidate) && Files.isExecutable(candidate)) return candidate;
            }
            return null;
        };
    }

    public static List<Interface> systemInterfaces() {
        try (var stream = NetworkInterface.networkInterfaces()) {
            return stream.map(network -> {
                boolean up = false, loopback = false, virtual = false;
                try {
                    up = network.isUp();
                    loopback = network.isLoopback();
                    virtual = network.isVirtual();
                } catch (SocketException ignored) { }
                return new Interface(network.getName(), up, loopback, virtual);
            }).sorted(Comparator.comparing(Interface::name)).toList();
        } catch (SocketException unavailable) {
            return List.of();
        }
    }

    @FunctionalInterface private interface EntryCount {
        int count(Path path) throws IOException;
    }

    private static Cache cache(Path path, EntryCount counter) {
        if (path == null) return new Cache(null, false, 0, 0, "Not configured");
        String display = path.toString();
        if (!Files.isRegularFile(path) || !Files.isReadable(path))
            return new Cache(display, false, 0, 0, "File not found");
        long modified = 0;
        try { modified = Files.getLastModifiedTime(path).toMillis(); }
        catch (IOException ignored) { /* Readability was already checked. */ }
        try {
            return new Cache(display, true, modified, counter.count(path), null);
        } catch (IOException | RuntimeException failure) {
            return new Cache(display, false, modified, 0,
                    failure.getMessage() == null ? "Unreadable cache" : failure.getMessage());
        }
    }

    private static Map<String, Object> wordlist(String configured) {
        Map<String, Object> response = new LinkedHashMap<>();
        String path = configured == null || configured.isBlank() ? null : configured;
        response.put("path", path);
        boolean available = false;
        if (path != null) {
            Path file = Path.of(path);
            available = Files.isRegularFile(file) && Files.isReadable(file);
        }
        response.put("available", available);
        return response;
    }

    private static Operation operation(String id, String label, Map<String, Boolean> available,
                                       List<String> required, List<String> alternatives) {
        List<String> missing = new ArrayList<>();
        for (String tool : required) if (!available.getOrDefault(tool, false)) missing.add(tool);
        if (!alternatives.isEmpty() && alternatives.stream().noneMatch(tool -> available.getOrDefault(tool, false)))
            missing.add(String.join(" or ", alternatives));
        return new Operation(id, label, missing.isEmpty(), List.copyOf(missing));
    }

    /** Kept for callers that want to compare a fixed tool set against a test locator. */
    public static Set<String> toolNames() {
        return Set.copyOf(TOOLS);
    }
}
