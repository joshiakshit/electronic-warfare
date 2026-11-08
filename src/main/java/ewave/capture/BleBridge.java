package ewave.capture;

import ewave.model.BleAdvertisement;
import ewave.model.BleDevice;
import ewave.model.EwaveEvent;
import ewave.passive.DeviceProfiler;
import ewave.passive.PassiveBleSession;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

/** Owns one passive BLE capture subprocess. Histories are bounded and survive restart.
 * Supply the UI's shared event queue; this class never consumes it.
 */
public final class BleBridge implements AutoCloseable {
    public static final int RECENT_LIMIT = 256;
    public static final int DEVICE_LIMIT = 512;
    private static final System.Logger LOG = System.getLogger(BleBridge.class.getName());
    private final BlockingQueue<EwaveEvent> events;
    private final ProcessStarter processStarter;
    private final DeviceProfiler profiler;
    private final LinkedHashMap<String, BleDevice> devices = new LinkedHashMap<>();
    private final ArrayDeque<BleAdvertisement> recent = new ArrayDeque<>();
    private Session session;
    private boolean enabled;
    private int adapter;
    private long count, evictedDevices;
    private String error;
    private PassiveBleSession passiveBle;

    @FunctionalInterface interface ProcessStarter { Process start(ProcessBuilder builder) throws IOException; }

    public BleBridge(BlockingQueue<EwaveEvent> events) { this(events, new DeviceProfiler()); }
    public BleBridge(BlockingQueue<EwaveEvent> events, DeviceProfiler profiler) {
        this(events, ProcessBuilder::start, profiler);
    }
    BleBridge(BlockingQueue<EwaveEvent> events, ProcessStarter processStarter) {
        this(events, processStarter, new DeviceProfiler());
    }
    BleBridge(BlockingQueue<EwaveEvent> events, ProcessStarter processStarter, DeviceProfiler profiler) {
        this.events = Objects.requireNonNull(events);
        this.processStarter = Objects.requireNonNull(processStarter);
        this.profiler = Objects.requireNonNull(profiler);
    }

    public DeviceProfiler getProfiler() { return profiler; }

    public synchronized void start(int adapter) throws IOException { startCapture(adapter, false); }

    public synchronized void startPassive(int adapter) throws IOException { startCapture(adapter, true); }

    public synchronized PassiveBleSession getPassiveBle() { return passiveBle; }

    private void startCapture(int adapter, boolean privateReports) throws IOException {
        if (adapter < 0 || adapter > 65535) throw new IllegalArgumentException("HCI adapter index must be in 0..65535");
        if (session != null) throw new IllegalStateException("BLE capture is already running");
        PassiveBleSession reports = privateReports ? new PassiveBleSession() : null;
        Path helper = Files.createTempFile("ewave-passive-ble-", ".py");
        try {
            try (InputStream resource = BleBridge.class.getResourceAsStream("/ble/passive_capture.py")) {
                if (resource == null) throw new IOException("Missing bundled BLE capture helper");
                Files.copy(resource, helper, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
            var builder = new ProcessBuilder(PassiveCommandGuard.bluetooth(helper, adapter));
            PassiveCommandGuard.requireBluetooth(builder.command(), helper, adapter);
            Process child = processStarter.start(builder);
            Session current = new Session(child, helper);
            session = current;
            passiveBle = reports;
            this.adapter = adapter;
            enabled = true;
            error = null;
            current.diagnostics = new Thread(() -> diagnostics(current), "ewave-ble-diagnostics");
            current.reader = new Thread(() -> read(current, adapter, reports), "ewave-ble-reader");
            current.diagnostics.setDaemon(true);
            current.reader.setDaemon(true);
            try {
                current.diagnostics.start();
                current.reader.start();
            } catch (RuntimeException | Error failure) {
                session = null;
                terminate(current);
                throw failure;
            }
        } catch (IOException | RuntimeException | Error failure) {
            Files.deleteIfExists(helper);
            throw failure;
        }
    }

    public synchronized Map<String, BleDevice> getDevices() { return Map.copyOf(devices); }
    public synchronized List<BleAdvertisement> getAdvertisements() { return List.copyOf(recent); }
    public synchronized Map<String, Object> getStatus() {
        var status = new LinkedHashMap<String, Object>();
        status.put("enabled", enabled);
        status.put("captureRunning", session != null);
        status.put("adapter", "hci" + adapter);
        status.put("scanMode", "passive");
        status.put("advertisements", count);
        status.put("recentLimit", RECENT_LIMIT);
        status.put("deviceLimit", DEVICE_LIMIT);
        status.put("evictedDevices", evictedDevices);
        if (error != null) status.put("captureError", error);
        return Map.copyOf(status);
    }

    private void read(Session current, int adapter, PassiveBleSession reports) {
        String fallback = "BLE capture ended";
        try (InputStream input = current.process.getInputStream()) {
            BleCaptureReader.read(input, adapter, advertisement -> {
                synchronized (this) {
                    if (session != current) return;
                    if (reports == null) record(advertisement);
                    else {
                        reports.observe(advertisement);
                        count++;
                        long now = System.currentTimeMillis();
                        if (now >= current.nextReportEvent) {
                            current.nextReportEvent = now + 1000;
                            events.add(new EwaveEvent("BLE_DEVICE_SEEN", now, null));
                        }
                    }
                }
            });
        } catch (IOException | RuntimeException failure) {
            fallback = Objects.toString(failure.getMessage(), "BLE capture failed");
        } finally {
            try {
                current.process.waitFor(250, TimeUnit.MILLISECONDS);
                current.diagnostics.join(250);
            } catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
            String diagnostic;
            synchronized (current.stderr) { diagnostic = current.stderr.toString().strip(); }
            try {
                int exit = current.process.exitValue();
                if (exit != 0) fallback = "BLE capture exited with code " + exit + ": "
                        + (diagnostic.isEmpty() ? fallback : diagnostic);
            } catch (IllegalThreadStateException running) { /* Keep the decoder error. */ }
            boolean owns;
            synchronized (this) {
                owns = session == current;
                if (owns) { error = fallback; session = null; }
            }
            if (owns) {
                LOG.log(System.Logger.Level.WARNING, fallback);
                terminate(current);
            }
        }
    }

    private void record(BleAdvertisement advertisement) {
        profiler.observe(advertisement);
        if (recent.size() == RECENT_LIMIT) recent.removeFirst();
        recent.addLast(advertisement);
        count++;
        BleDevice previous = devices.remove(advertisement.deviceId());
        if (previous == null && devices.size() == DEVICE_LIMIT) {
            String oldest = devices.keySet().iterator().next();
            devices.remove(oldest);
            evictedDevices++;
            events.add(EwaveEvent.bleDeviceRemoved(oldest));
        }
        boolean newest = previous == null || advertisement.timestamp() >= previous.lastSeen();
        String name = previous == null ? null : previous.lastAdvertisedName();
        if (newest && advertisement.payload().localName() != null && !advertisement.payload().localName().isEmpty())
            name = advertisement.payload().localName();
        BleDevice device = new BleDevice(advertisement.deviceId(), advertisement.address(), advertisement.addressType(), name,
                previous == null ? advertisement.timestamp() : Math.min(previous.firstSeen(), advertisement.timestamp()),
                previous == null ? advertisement.timestamp() : Math.max(previous.lastSeen(), advertisement.timestamp()),
                previous == null ? 1 : previous.advertisementCount() + 1, newest ? advertisement : previous.latest());
        devices.put(device.id(), device);
        events.add(EwaveEvent.bleDeviceUpdated(device));
        events.add(EwaveEvent.bleAdvertisement(advertisement));
    }

    private void diagnostics(Session current) {
        try (var input = new InputStreamReader(current.process.getErrorStream(), StandardCharsets.UTF_8)) {
            char[] buffer = new char[512];
            int length;
            while ((length = input.read(buffer)) >= 0) {
                synchronized (current.stderr) {
                    current.stderr.append(buffer, 0, length);
                    if (current.stderr.length() > 4096) current.stderr.delete(0, current.stderr.length() - 4096);
                }
                System.err.print(new String(buffer, 0, length));
            }
        } catch (IOException closed) { LOG.log(System.Logger.Level.DEBUG, "BLE diagnostic stream closed", closed); }
    }

    public void stop() {
        Session current;
        synchronized (this) { current = session; session = null; }
        if (current != null) terminate(current);
    }
    @Override public void close() { stop(); }

    private static void terminate(Session current) {
        boolean interrupted = Thread.interrupted();
        current.process.destroy(); // SIGTERM lets the helper disable only its owned scan.
        try {
            if (!current.process.waitFor(5000, TimeUnit.MILLISECONDS)) current.process.destroyForcibly();
        } catch (InterruptedException failure) { interrupted = true; current.process.destroyForcibly(); }
        for (var stream : List.of(current.process.getInputStream(), current.process.getErrorStream(), current.process.getOutputStream())) {
            try { stream.close(); } catch (IOException ignored) { }
        }
        for (Thread thread : new Thread[]{current.reader, current.diagnostics}) if (thread != null && thread != Thread.currentThread()) {
            try { thread.join(1000); } catch (InterruptedException failure) { interrupted = true; }
        }
        try { Files.deleteIfExists(current.helper); } catch (IOException failure) {
            LOG.log(System.Logger.Level.WARNING, "Could not remove BLE helper", failure);
        }
        if (interrupted) Thread.currentThread().interrupt();
    }

    private static final class Session {
        final Process process;
        final Path helper;
        final StringBuilder stderr = new StringBuilder();
        Thread reader, diagnostics;
        long nextReportEvent;
        Session(Process process, Path helper) { this.process = process; this.helper = helper; }
    }
}
