package ewave.passive;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.UserPrincipal;

/** Restores user ownership for files created during a sudo-elevated launcher run. */
public final class FileOwnership {
    private FileOwnership() { }

    public static void restoreSudoOwner(Path path) {
        if (path == null) return;
        String sudoUser = System.getenv("SUDO_USER");
        if (sudoUser == null || sudoUser.isBlank() || !"root".equals(System.getProperty("user.name"))) return;
        try {
            UserPrincipal owner = FileSystems.getDefault().getUserPrincipalLookupService().lookupPrincipalByName(sudoUser);
            Files.setOwner(path, owner);
        } catch (IOException | UnsupportedOperationException | SecurityException ignored) {
            // Best-effort ownership restoration; ignore on non-POSIX or restricted filesystems.
        }
    }
}
