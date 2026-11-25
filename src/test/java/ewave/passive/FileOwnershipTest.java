package ewave.passive;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import static org.junit.jupiter.api.Assertions.*;

class FileOwnershipTest {
    @TempDir Path directory;

    @Test void resolvesTheSudoOperatorsActualHomeInsteadOfTheRootHome() {
        Path operator = directory.resolve("custom operator home");
        assertEquals(operator, FileOwnership.operatorHome("root", Path.of("/root"), "operator", name -> {
            assertEquals("operator", name);
            return operator;
        }));
        assertEquals(Path.of("/root"), FileOwnership.operatorHome("root", Path.of("/root"), null, name -> {
            fail("A direct root launch has no sudo operator"); return null;
        }));
        assertEquals(operator, FileOwnership.operatorHome("operator", operator, "someone-else", name -> {
            fail("An unprivileged launch must ignore sudo metadata"); return null;
        }));
        assertThrows(IllegalStateException.class,
                () -> FileOwnership.operatorHome("root", Path.of("/root"), "missing", name -> null));
    }

    @Test void restoresEveryNewParentWithoutChangingExistingAncestors() throws Exception {
        Path recordings = directory.resolve(".local/share/ewave/recordings");
        var restored = new ArrayList<Path>();
        FileOwnership.createPrivateDirectories(recordings, restored::add);
        assertEquals(List.of(directory.resolve(".local"), directory.resolve(".local/share"),
                directory.resolve(".local/share/ewave"), recordings), restored);
        for (Path path : restored)
            assertEquals(PosixFilePermissions.fromString("rwx------"), Files.getPosixFilePermissions(path));
        assertFalse(restored.contains(directory));
    }

    @Test void explicitStorePathsOverrideEvenAnInvalidOperatorHome() {
        String previousHome = System.setProperty("rf.userHome", "relative-home");
        String previousFile = System.setProperty("rf.networkProfile", directory.resolve("explicit.json").toString());
        try {
            assertEquals(directory.resolve("explicit.json"),
                    FileOwnership.storagePath("rf.networkProfile", ".config", "ewave", "my-network.json"));
            System.clearProperty("rf.networkProfile");
            assertThrows(IllegalStateException.class,
                    () -> FileOwnership.storagePath("rf.networkProfile", ".config", "ewave", "my-network.json"));
        } finally {
            restore("rf.userHome", previousHome);
            restore("rf.networkProfile", previousFile);
        }
    }

    @Test void profilesSavedUnderAnElevatedHomeAreVisibleToTheNormalUser() throws Exception {
        String oldHome = System.getProperty("user.home");
        String oldOperatorHome = System.getProperty("rf.userHome");
        String oldProfile = System.getProperty("rf.networkProfile");
        Path operator = Files.createDirectory(directory.resolve("operator"));
        Path root = Files.createDirectory(directory.resolve("root"));
        try {
            System.clearProperty("rf.networkProfile");
            System.setProperty("user.home", root.toString());
            System.setProperty("rf.userHome", operator.toString());
            var profile = MyNetworkProfile.EMPTY.change(new MyNetworkProfile.Change(
                    "save-ap", null, "02:11:22:33:44:55", null, "Lab AP", null), null);
            new MyNetworkStore().save(profile);
            Path saved = operator.resolve(".config/ewave/my-network.json");
            assertTrue(Files.isRegularFile(saved));
            assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(saved));
            assertFalse(Files.exists(root.resolve(".config")));
            System.setProperty("user.home", operator.toString());
            System.clearProperty("rf.userHome");
            assertEquals(profile, new MyNetworkStore().get());
        } finally {
            restore("user.home", oldHome);
            restore("rf.userHome", oldOperatorHome);
            restore("rf.networkProfile", oldProfile);
        }
    }

    private static void restore(String name, String previous) {
        if (previous == null) System.clearProperty(name);
        else System.setProperty(name, previous);
    }

    @Test
    @EnabledOnOs(OS.LINUX)
    void directSudoMetadataResolvesTheHomeThroughTheAccountDatabase() throws Exception {
        var builder = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-Duser.name=root", "-Duser.home=/root", "-cp", System.getProperty("java.class.path"),
                HomeProbe.class.getName()).redirectErrorStream(true);
        builder.environment().put("SUDO_USER", System.getProperty("user.name"));
        // Use a clean child JVM so the launcher-only home override cannot hide a broken account lookup.
        builder.environment().remove("JAVA_TOOL_OPTIONS");
        builder.environment().remove("JDK_JAVA_OPTIONS");
        builder.environment().remove("_JAVA_OPTIONS");
        Process child = builder.start();
        try {
            assertTrue(child.waitFor(5, TimeUnit.SECONDS));
            String result = new String(child.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).strip();
            assertEquals(0, child.exitValue(), result);
            assertEquals(Path.of(System.getProperty("user.home"), "fixture").toString(), result);
        } finally {
            if (child.isAlive()) child.destroyForcibly();
        }
    }

    public static class HomeProbe {
        public static void main(String[] args) {
            System.out.println(FileOwnership.storagePath("rf.testStore", "fixture"));
        }
    }
}
