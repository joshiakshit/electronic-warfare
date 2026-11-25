package ewave.active;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

/** Private, backend-owned paths for files passed to lab helper processes. */
final class PrivateWorkspace {
    private PrivateWorkspace() { }

    static Path create(Path path) throws IOException {
        Path parent = path.getParent();
        noSymlinks(parent);
        if (parent.equals(Path.of(System.getProperty("java.io.tmpdir")).toAbsolutePath().normalize())) {
            int uid = (int) Files.getAttribute(parent, "unix:uid", LinkOption.NOFOLLOW_LINKS);
            int mode = (int) Files.getAttribute(parent, "unix:mode", LinkOption.NOFOLLOW_LINKS);
            var current = parent.getFileSystem().getUserPrincipalLookupService()
                    .lookupPrincipalByName(System.getProperty("user.name"));
            if (uid != 0 && !Files.getOwner(parent, LinkOption.NOFOLLOW_LINKS).equals(current)
                    || (mode & 0022) != 0 && (mode & 01000) == 0)
                throw new IOException("Untrusted temporary directory: " + parent);
        } else {
            requireDirectory(parent);
        }
        // Atomic creation: never adopt or chmod a pre-existing work directory.
        Files.createDirectory(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        return requireDirectory(path);
    }

    static Path requireDirectory(Path path) throws IOException {
        noSymlinks(path);
        if (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) throw new IOException("Not a private directory: " + path);
        requireOwnerAndMode(path);
        return path;
    }

    static void requireFile(Path path) throws IOException {
        noSymlinks(path);
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) throw new IOException("Not a regular private file: " + path);
        requireOwnerAndMode(path);
        if ((int) Files.getAttribute(path, "unix:nlink", LinkOption.NOFOLLOW_LINKS) != 1)
            throw new IOException("Private file has multiple links: " + path);
    }

    private static void requireOwnerAndMode(Path path) throws IOException {
        var owner = path.getFileSystem().getUserPrincipalLookupService()
                .lookupPrincipalByName(System.getProperty("user.name"));
        if (!Files.getOwner(path, LinkOption.NOFOLLOW_LINKS).equals(owner))
            throw new IOException("Private path is owned by another user: " + path);
        for (var permission : Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS)) {
            if (permission.name().startsWith("GROUP_") || permission.name().startsWith("OTHERS_"))
                throw new IOException("Private path is accessible by other users: " + path);
        }
    }

    private static void noSymlinks(Path path) throws IOException {
        Path current = path.toAbsolutePath().getRoot();
        for (Path part : path.toAbsolutePath()) {
            current = current.resolve(part);
            if (Files.isSymbolicLink(current)) throw new IOException("Private path contains a symbolic link: " + current);
        }
    }
}
