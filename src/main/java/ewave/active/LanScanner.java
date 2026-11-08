package ewave.active;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/** Reads the LAN scan cached by the launcher before monitor mode disconnects Wi-Fi. */
public final class LanScanner {
    private static final Pattern DEVICE = Pattern.compile(
            "^(\\d+\\.\\d+\\.\\d+\\.\\d+)\\s+([0-9a-fA-F:]{17})\\s+(.*)$");
    private static final Pattern LOCAL_IPV4 = Pattern.compile("\\bIPv4:\\s*(\\d+\\.\\d+\\.\\d+\\.\\d+)");
    public record Device(String ip, String mac, String vendor) {}
    private final Path cacheFile;

    public LanScanner() { this(Path.of("/tmp/ewave-lan-hosts.txt")); }

    /** File boundary for deterministic tests without accessing the host's cache. */
    public LanScanner(Path cacheFile) { this.cacheFile = Objects.requireNonNull(cacheFile); }

    public List<Device> scan() throws IOException {
        return parse(Files.readAllLines(cacheFile), localIpv4Addresses());
    }

    static List<Device> parse(List<String> lines, Set<String> localAddresses) {
        var localIps = new HashSet<>(localAddresses);
        // arp-scan records the pre-monitor IP in its Interface header, even after Wi-Fi disconnects.
        for (String line : lines) {
            if (!line.stripLeading().startsWith("Interface:")) continue;
            var local = LOCAL_IPV4.matcher(line);
            if (local.find()) localIps.add(local.group(1));
        }
        return lines.stream().map(String::stripLeading)
                .filter(line -> !line.startsWith("Interface:") && !line.startsWith("Starting")
                        && !line.startsWith("Ending") && !line.startsWith("#"))
                .map(DEVICE::matcher).filter(java.util.regex.Matcher::matches)
                .filter(match -> !localIps.contains(match.group(1)))
                .map(match -> new Device(match.group(1), match.group(2), vendor(match.group(3)))).toList();
    }

    private static String vendor(String value) {
        String result = value.strip();
        return result.startsWith("(") && result.endsWith(")") ? result.substring(1, result.length() - 1).strip() : result;
    }

    private static Set<String> localIpv4Addresses() {
        try {
            return NetworkInterface.networkInterfaces().flatMap(NetworkInterface::inetAddresses)
                    .filter(Inet4Address.class::isInstance).map(InetAddress::getHostAddress).collect(Collectors.toSet());
        } catch (SocketException unavailable) {
            return Set.of(); // The cached Interface header still supplies the pre-monitor address.
        }
    }
}
