package ewave.active;

import ewave.fixtures.CompletedProcess;
import ewave.fixtures.StreamingCaptureProcess;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(20)
class EvilTwinTest {
    @TempDir Path directory;

    @Test void writesConfigsAndStartsAllThreeHelpers() throws Exception {
        var commands = new CopyOnWriteArrayList<List<String>>();
        var processes = new CopyOnWriteArrayList<StreamingCaptureProcess>();
        Path work = directory.resolve("work"), creds = directory.resolve("creds.txt");
        var twin = new EvilTwin("wlo1ap", "ewave-portal", 6, 8080, work.toString(), creds.toString(),
                launcher(commands, processes));

        var status = twin.start();

        assertTrue(status.running());
        assertEquals("Portal active", status.stage());
        assertEquals("ewave-portal", status.ssid());
        assertEquals("http://10.0.0.1:8080/", status.portalUrl());
        assertEquals(work.toString(), status.workDir());
        assertEquals(creds.toString(), status.credentialsFile());
        assertEquals(3, commands.size());
        assertEquals(List.of("sudo", "hostapd", work.resolve("hostapd.conf").toString()), commands.get(0));
        assertEquals(List.of("sudo", "dnsmasq", "-C", work.resolve("dnsmasq.conf").toString(), "-k"), commands.get(1));
        assertEquals(List.of("sudo", "python3", work.resolve("portal_server.py").toString(), "--port", "8080",
                "--root", work.toString(), "--creds", creds.toString()), commands.get(2));

        String hostapd = Files.readString(work.resolve("hostapd.conf"));
        assertTrue(hostapd.contains("interface=wlo1ap"));
        assertTrue(hostapd.contains("ssid=ewave-portal"));
        assertTrue(hostapd.contains("hw_mode=g"));
        assertTrue(hostapd.contains("channel=6"));
        String dnsmasq = Files.readString(work.resolve("dnsmasq.conf"));
        assertTrue(dnsmasq.contains("dhcp-range=10.0.0.10,10.0.0.100,12h"));
        assertTrue(dnsmasq.contains("address=/#/10.0.0.1"));
        assertTrue(Files.readString(work.resolve("portal.html")).contains("action=\"/submit\""));
        assertTrue(Files.readString(work.resolve("portal_server.py")).contains("ThreadingHTTPServer"));
        assertFalse(Files.exists(creds));

        twin.terminate();
        assertFalse(twin.status().running());
        for (var process : processes) assertFalse(process.isAlive());
    }

    @Test void tailsAndBoundsCredentialsFromThePortalLog() throws Exception {
        var processes = new CopyOnWriteArrayList<StreamingCaptureProcess>();
        Path work = directory.resolve("work"), creds = directory.resolve("creds.txt");
        var twin = new EvilTwin("wlo1ap", "portal", 1, 80, work.toString(), creds.toString(),
                launcher(new CopyOnWriteArrayList<>(), processes));
        twin.start();
        try {
            Files.writeString(creds, "2026-01-01T10:00:00\t10.0.0.42\tstudent\tsecret\n"
                    + "malformed line without fields\n"
                    + "2026-01-01T10:00:05\t10.0.0.43\tlab\tpassword\n", StandardCharsets.UTF_8);
            await(() -> twin.status().credentials().size() == 2);
            var captured = twin.status().credentials();
            assertEquals(new EvilTwin.Credential("2026-01-01T10:00:00", "10.0.0.42", "student", "secret"),
                    captured.get(0));
            assertEquals(new EvilTwin.Credential("2026-01-01T10:00:05", "10.0.0.43", "lab", "password"),
                    captured.get(1));
            Files.writeString(creds, "2026-01-01T10:00:09\t10.0.0.44\tthird\tvalue\n",
                    StandardCharsets.UTF_8, StandardOpenOption.APPEND);
            await(() -> twin.status().credentials().size() == 3);
            assertEquals("value", twin.status().credentials().getLast().password());
        } finally {
            twin.terminate();
        }
        for (var process : processes) assertFalse(process.isAlive());
    }

    @Test void stopsTheRemainingHelpersWhenOneProcessExits() throws Exception {
        var commands = new CopyOnWriteArrayList<List<String>>();
        var processes = new CopyOnWriteArrayList<StreamingCaptureProcess>();
        Path work = directory.resolve("work"), creds = directory.resolve("creds.txt");
        var twin = new EvilTwin("wlo1ap", "portal", 6, 80, work.toString(), creds.toString(), builder -> {
            commands.add(List.copyOf(builder.command()));
            if (builder.command().stream().anyMatch(part -> part.endsWith("portal_server.py")))
                return new CompletedProcess("", 0);
            var process = new StreamingCaptureProcess();
            processes.add(process);
            return process;
        });
        twin.start();
        await(() -> twin.status().error() != null && twin.status().error().contains("portal server exited"));
        assertFalse(twin.status().running());
        await(() -> processes.stream().noneMatch(Process::isAlive));
        for (var process : processes) assertFalse(process.isAlive());
    }

    @Test void validatesSettingsAndPropagatesLaunchFailures() {
        String work = directory.resolve("work").toString(), creds = directory.resolve("creds.txt").toString();
        for (String iface : new String[]{null, "", "a b", "x".repeat(16)})
            assertThrows(IllegalArgumentException.class, () -> new EvilTwin(iface, "lab", 6, 80, work, creds,
                    builder -> new StreamingCaptureProcess()));
        for (String ssid : new String[]{null, "", " ", "x".repeat(33), "two\nlines"})
            assertThrows(IllegalArgumentException.class, () -> new EvilTwin("wlo1ap", ssid, 6, 80, work, creds,
                    builder -> new StreamingCaptureProcess()));
        assertThrows(IllegalArgumentException.class, () -> new EvilTwin("wlo1ap", "lab", 0, 80, work, creds,
                builder -> new StreamingCaptureProcess()));
        assertThrows(IllegalArgumentException.class, () -> new EvilTwin("wlo1ap", "lab", 6, 0, work, creds,
                builder -> new StreamingCaptureProcess()));

        var twin = new EvilTwin("wlo1ap", "lab", 6, 80, work, creds, builder -> {
            throw new IOException("hostapd is missing");
        });
        var failure = assertThrows(IOException.class, twin::start);
        assertEquals("hostapd is missing", failure.getMessage());
        assertFalse(twin.status().running());
        assertEquals("hostapd is missing", twin.status().error());
        assertThrows(IllegalStateException.class, twin::start);
    }

    private static EvilTwin.ProcessStarter launcher(List<List<String>> commands,
                                                    List<StreamingCaptureProcess> processes) {
        return builder -> {
            commands.add(List.copyOf(builder.command()));
            var process = new StreamingCaptureProcess();
            processes.add(process);
            return process;
        };
    }

    private static void await(java.util.function.BooleanSupplier condition) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < deadline) {
            if (condition.getAsBoolean()) return;
            Thread.sleep(25);
        }
        fail("condition was not met before the timeout");
    }
}
