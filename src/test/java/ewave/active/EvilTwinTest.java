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
import java.nio.file.attribute.PosixFilePermissions;
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
                "--creds", creds.toString()), commands.get(2));

        String hostapd = Files.readString(work.resolve("hostapd.conf"));
        assertTrue(hostapd.contains("interface=wlo1ap"));
        assertTrue(hostapd.contains("ssid=ewave-portal"));
        assertTrue(hostapd.contains("hw_mode=g"));
        assertTrue(hostapd.contains("channel=6"));
        String dnsmasq = Files.readString(work.resolve("dnsmasq.conf"));
        assertTrue(dnsmasq.contains("dhcp-range=10.0.0.10,10.0.0.100,12h"));
        assertTrue(dnsmasq.contains("address=/#/10.0.0.1"));
        assertFalse(Files.exists(work.resolve("portal.html")));
        assertTrue(Files.readString(work.resolve("portal_server.py")).contains("ThreadingHTTPServer"));
        assertTrue(Files.isRegularFile(creds));
        assertEquals("", Files.readString(creds));
        assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(creds));
        assertEquals(Files.getOwner(work), Files.getOwner(creds));

        twin.terminate();
        assertFalse(twin.status().running());
        for (var process : processes) assertFalse(process.isAlive());
    }

    @Test void createsTheBackendOwnedLogBeforeLaunchingTheElevatedPortal() throws Exception {
        Path work = directory.resolve("work"), creds = directory.resolve("creds.txt");
        Files.writeString(creds, "old\tentry\tfrom\tprevious-run\n");
        Files.setPosixFilePermissions(creds, PosixFilePermissions.fromString("rw-------"));
        var processes = new CopyOnWriteArrayList<StreamingCaptureProcess>();
        var twin = new EvilTwin("wlo1ap", "portal", 6, 8080, work.toString(), creds.toString(), builder -> {
            if (builder.command().contains("python3")) {
                assertTrue(Files.isRegularFile(creds), "The backend must create the log before sudo starts Python");
                assertEquals("", Files.readString(creds));
                assertEquals(Files.getOwner(work), Files.getOwner(creds));
                assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(creds));
                Files.writeString(creds, "2026-01-01T10:00:00\t10.0.0.42\tlab\tdummy\n",
                        StandardOpenOption.APPEND);
            }
            var process = new StreamingCaptureProcess();
            processes.add(process);
            return process;
        });
        try {
            twin.start();
            await(() -> twin.status().credentials().size() == 1);
            assertEquals("dummy", twin.status().credentials().getFirst().password());
            assertNull(twin.status().error());
        } finally {
            twin.terminate();
        }
        assertTrue(processes.stream().noneMatch(Process::isAlive));
    }

    @Test void defaultRunsUseSeparatePrivatePathsInsteadOfSharedRootOwnedLogs() {
        var first = new EvilTwin("wlo1ap", "portal", 6, 80).status();
        var second = new EvilTwin("wlo1ap", "portal", 6, 80).status();
        assertNotEquals(first.workDir(), second.workDir());
        assertEquals(Path.of(first.workDir()).resolve("credentials.tsv"), Path.of(first.credentialsFile()));
        assertEquals(Path.of(second.workDir()).resolve("credentials.tsv"), Path.of(second.credentialsFile()));
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

    @Test void usesDsssModeForChannelFourteenAndRejectsUnsupportedSixGhzChannels() throws Exception {
        Path work = directory.resolve("channel14"), creds = directory.resolve("channel14.tsv");
        var twin = new EvilTwin("wlo1ap", "Lab", 14, 80, work.toString(), creds.toString(), builder -> {
            throw new IOException("Stop before any helper starts");
        });
        assertThrows(IOException.class, twin::start);
        assertTrue(Files.readString(work.resolve("hostapd.conf")).contains("hw_mode=b\n"));
        for (int channel : new int[]{15, 31, 178, 233})
            assertThrows(IllegalArgumentException.class, () -> new EvilTwin("wlo1ap", "Lab", channel, 80));
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

    @Test void refusesPreexistingWorkDirectoriesAndSymlinkCredentialsWithoutStartingHelpers() throws Exception {
        Path victim = directory.resolve("victim");
        Files.createDirectory(victim);
        Files.writeString(victim.resolve("hostapd.conf"), "keep this config");
        Path work = directory.resolve("work");
        Files.createSymbolicLink(work, victim);
        var twin = new EvilTwin("wlo1ap", "lab", 6, 80, work.toString(), directory.resolve("creds").toString(),
                builder -> { fail("Unsafe paths must fail before starting helpers"); return null; });
        assertThrows(IOException.class, twin::start);
        assertEquals("keep this config", Files.readString(victim.resolve("hostapd.conf")));
        Files.delete(work);
        Path creds = directory.resolve("creds");
        Files.createSymbolicLink(creds, victim.resolve("hostapd.conf"));
        var second = new EvilTwin("wlo1ap", "lab", 6, 80, work.toString(), creds.toString(),
                builder -> { fail("Unsafe paths must fail before starting helpers"); return null; });
        assertThrows(IOException.class, second::start);
        assertTrue(Files.isSymbolicLink(creds));
        assertEquals("keep this config", Files.readString(victim.resolve("hostapd.conf")));
    }

    @Test void assignsAndCleansUpLabIpAddressWhenConfigureAddressIsEnabled() throws Exception {
        var commands = new CopyOnWriteArrayList<List<String>>();
        var processes = new CopyOnWriteArrayList<StreamingCaptureProcess>();
        Path work = directory.resolve("addr-work"), creds = directory.resolve("addr-creds.tsv");
        var twin = new EvilTwin("wlo1ap", "ewave-portal", 6, 8080, true, work.toString(), creds.toString(),
                builder -> {
                    var command = List.copyOf(builder.command());
                    commands.add(command);
                    if (command.size() > 1 && command.get(1).equals("ip")) {
                        return new CompletedProcess("", 0);
                    }
                    var process = new StreamingCaptureProcess();
                    processes.add(process);
                    return process;
                });

        var status = twin.start();
        assertTrue(status.running());
        assertEquals(5, commands.size());
        assertEquals(List.of("sudo", "ip", "link", "set", "dev", "wlo1ap", "up"), commands.get(0));
        assertEquals(List.of("sudo", "ip", "addr", "replace", "10.0.0.1/24", "dev", "wlo1ap"), commands.get(1));
        assertEquals("hostapd", commands.get(2).get(1));

        twin.terminate();
        assertEquals(6, commands.size());
        assertEquals(List.of("sudo", "ip", "addr", "del", "10.0.0.1/24", "dev", "wlo1ap"), commands.get(5));
        for (var process : processes) assertFalse(process.isAlive());
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
