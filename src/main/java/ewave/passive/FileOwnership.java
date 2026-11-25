package ewave.passive;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.Consumer;

/** Restores user ownership for files created during a sudo-elevated launcher run. */
public final class FileOwnership {
    private FileOwnership() { }

    /** Explicit store paths take priority; defaults follow the operator even under sudo -H. */
    public static Path storagePath(String property, String... relative) {
        String configured = System.getProperty(property);
        if (configured != null) return Path.of(configured).toAbsolutePath();
        String configuredHome = System.getProperty("rf.userHome");
        Path home = configuredHome != null ? Path.of(configuredHome)
                : operatorHome(System.getProperty("user.name"), Path.of(System.getProperty("user.home")),
                        System.getenv("SUDO_USER"), FileOwnership::lookupHome);
        if (!home.isAbsolute()) throw new IllegalStateException("The operator home directory must be absolute");
        return home.resolve(Path.of("", relative));
    }

    static Path operatorHome(String user, Path home, String sudoUser, Function<String, Path> lookup) {
        if (!"root".equals(user) || sudoUser == null || sudoUser.isBlank()) return home;
        Path operator = lookup.apply(sudoUser);
        if (operator == null || !operator.isAbsolute())
            throw new IllegalStateException("Could not resolve the invoking user's home; set -Drf.userHome=/path/to/home");
        return operator;
    }

    private static Path lookupHome(String user) {
        try {
            Process lookup = new ProcessBuilder("getent", "passwd", "--", user)
                    .redirectError(ProcessBuilder.Redirect.DISCARD).start();
            try {
                if (!lookup.waitFor(2, TimeUnit.SECONDS) || lookup.exitValue() != 0) return null;
                try (var input = lookup.getInputStream()) {
                    String[] fields = new String(input.readAllBytes(), StandardCharsets.UTF_8).strip().split(":", -1);
                    return fields.length == 7 && fields[0].equals(user) ? Path.of(fields[5]) : null;
                }
            } finally {
                if (lookup.isAlive()) lookup.destroyForcibly();
            }
        } catch (IOException unavailable) {
            return null;
        } catch (InterruptedException stopped) {
            Thread.currentThread().interrupt();
            return null;
        }
    }

    /** Include newly created parents, so a first elevated launch does not leave root-only ancestors. */
    public static void createPrivateDirectories(Path directory) throws IOException {
        createPrivateDirectories(directory, FileOwnership::restoreSudoOwner);
    }

    static void createPrivateDirectories(Path directory, Consumer<Path> restoreOwner) throws IOException {
        var missing = new ArrayList<Path>();
        for (Path parent = directory.toAbsolutePath(); parent != null && Files.notExists(parent); parent = parent.getParent())
            missing.add(parent);
        if (directory.getFileSystem().supportedFileAttributeViews().contains("posix"))
            Files.createDirectories(directory, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        else Files.createDirectories(directory);
        for (Path created : missing.reversed()) restoreOwner.accept(created);
        if (missing.isEmpty()) restoreOwner.accept(directory);
    }

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
