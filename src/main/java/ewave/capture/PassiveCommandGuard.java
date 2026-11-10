package ewave.capture;

import java.util.List;

/** Exact capture commands, including filters and helper arguments. */
final class PassiveCommandGuard {
    private PassiveCommandGuard() { }

    static List<String> monitor(String iface) {
        return List.of("tcpdump", "-i", iface, "-y", "IEEE802_11_RADIO", "-U", "-s", "0", "-n", "-w", "-",
                "type mgt or type data");
    }

    static List<String> probes(String iface) {
        return List.of("sudo", "tcpdump", "-i", iface, "-e", "-l", "-s", "256", "type mgt subtype probe-req");
    }

    static List<String> packets(String iface) { return List.of("tcpdump", "-i", iface, "-e", "-l", "-n", "-tt"); }

    static void requireWifi(List<String> command, String iface) {
        if (iface == null || iface.isBlank() || iface.startsWith("-")
                || !(command.equals(monitor(iface)) || command.equals(probes(iface)) || command.equals(packets(iface))))
            throw new IllegalArgumentException("Capture command is outside the passive Wi-Fi allowlist");
    }
}
