package ewave.active;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

import static org.junit.jupiter.api.Assertions.*;

class PrivateWorkspaceTest {
    @TempDir Path directory;

    @Test void createsPrivateDirectoriesAndRefusesToAdoptExistingPaths() throws Exception {
        Path run = PrivateWorkspace.create(directory.resolve("run"));
        assertEquals(PosixFilePermissions.fromString("rwx------"), Files.getPosixFilePermissions(run));
        assertEquals(Files.getOwner(directory), Files.getOwner(run));
        assertThrows(IOException.class, () -> PrivateWorkspace.create(run));
        Files.setPosixFilePermissions(run, PosixFilePermissions.fromString("rwxrwxrwx"));
        assertThrows(IOException.class, () -> PrivateWorkspace.requireDirectory(run));
        assertEquals(PosixFilePermissions.fromString("rwxrwxrwx"), Files.getPosixFilePermissions(run));
    }

    @Test void rejectsSymlinksInAnyPathComponentAndHardlinkedFiles() throws Exception {
        Path real = Files.createDirectory(directory.resolve("real"));
        Path link = Files.createSymbolicLink(directory.resolve("link"), real);
        assertThrows(IOException.class, () -> PrivateWorkspace.create(link.resolve("run")));
        assertFalse(Files.exists(real.resolve("run")));
        Path file = Files.createFile(directory.resolve("file"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        PrivateWorkspace.requireFile(file);
        Files.createLink(directory.resolve("hardlink"), file);
        assertThrows(IOException.class, () -> PrivateWorkspace.requireFile(file));
    }

    @Test void handshakeRejectsUnsafeCaptureDirectoriesBeforeStartingProcesses() throws Exception {
        Path linked = Files.createSymbolicLink(directory.resolve("link"), directory);
        var analyzer = new HandshakeAnalyzer("mon0", "02:00:00:00:00:01", null, 6, linked.toString(),
                builder -> { fail("Unsafe capture paths must fail before starting processes"); return null; });
        assertThrows(IOException.class, analyzer::capture);
    }
}
