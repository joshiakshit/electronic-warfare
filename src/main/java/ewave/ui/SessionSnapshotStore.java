package ewave.ui;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import ewave.passive.FileOwnership;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.channels.FileChannel;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

import static java.nio.file.LinkOption.NOFOLLOW_LINKS;
import static java.nio.file.StandardOpenOption.WRITE;

/** Stores versioned passive reports in a private local directory. */
final class SessionSnapshotStore {
    static final int MAX_SNAPSHOTS = 32;
    static final int MAX_BYTES = 8 * 1024 * 1024;
    private static final int VERSION = 1;
    private static final Object SAVE_LOCK = new Object();
    private static final Pattern ENTRY = Pattern.compile("[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\\.json");
    private static final List<String> REPORTS = List.of(
            "spotter", "whistleblower", "decloaker", "inspector", "profiler", "tracker", "lookout");
    private final ObjectMapper mapper;
    private final Path directory = FileOwnership.storagePath(
            "rf.sessionDirectory", ".local", "share", "ewave", "sessions").normalize();

    record Entry(UUID id, String name, long savedAt, UUID sessionId) { }

    static final class Limit extends IOException {
        Limit(String message) { super(message); }
    }

    SessionSnapshotStore(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    List<Entry> list() throws IOException {
        if (!checkDirectory(false)) return List.of();
        var entries = new ArrayList<Entry>();
        for (Path file : files()) {
            ObjectNode snapshot = read(file);
            if (snapshot != null) entries.add(metadata(snapshot));
            if (entries.size() == MAX_SNAPSHOTS) break;
        }
        entries.sort(Comparator.comparingLong(Entry::savedAt).reversed().thenComparing(Entry::id));
        return entries;
    }

    ObjectNode load(UUID id) throws IOException {
        return checkDirectory(false) ? read(file(id)) : null;
    }

    boolean delete(UUID id) throws IOException {
        if (!checkDirectory(false) || !privateFile(file(id))) return false;
        return Files.deleteIfExists(file(id));
    }

    Entry save(String name, UUID sessionId, ObjectNode reports) throws IOException {
        if (!validName(name)) throw new IllegalArgumentException("Provide a snapshot name of 1–120 characters");
        var entry = new Entry(UUID.randomUUID(), name.strip(), System.currentTimeMillis(), sessionId);
        ObjectNode snapshot = mapper.valueToTree(entry);
        snapshot.put("version", VERSION).set("reports", reports);
        synchronized (SAVE_LOCK) {
            checkDirectory(true);
            Path lock = directory.resolve(".save.lock");
            try {
                Files.createFile(lock, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
                FileOwnership.restoreSudoOwner(lock);
            } catch (FileAlreadyExistsException exists) {
                // Keep the existing lock inode across processes.
            }
            if (!privateFile(lock)) throw new IOException("Invalid snapshot lock file");
            try (var channel = FileChannel.open(lock, Set.of(WRITE, NOFOLLOW_LINKS))) {
                try (var ignored = channel.lock()) {
                    if (files().size() >= MAX_SNAPSHOTS)
                        throw new Limit("Snapshot library is full. Delete a snapshot before saving another.");
                    write(snapshot, file(entry.id()));
                }
            }
        }
        return entry;
    }

    private void write(ObjectNode snapshot, Path file) throws IOException {
        Path pending = Files.createTempFile(directory, ".snapshot-", ".tmp",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        try {
            try (var output = new LimitedOutput(Files.newOutputStream(pending, WRITE, NOFOLLOW_LINKS))) {
                mapper.writeValue(output, snapshot);
            }
            FileOwnership.restoreSudoOwner(pending);
            if (!privateFile(pending)) throw new IOException("Invalid snapshot file ownership");
            Files.move(pending, file, StandardCopyOption.ATOMIC_MOVE);
        } finally {
            Files.deleteIfExists(pending);
        }
    }

    private List<Path> files() throws IOException {
        try (var children = Files.list(directory)) {
            return children.filter(file -> ENTRY.matcher(file.getFileName().toString()).matches())
                    .limit(MAX_SNAPSHOTS + 1L).toList();
        }
    }

    private Path file(UUID id) {
        return directory.resolve(id + ".json");
    }

    private ObjectNode read(Path file) throws IOException {
        if (!privateFile(file)) return null;
        try (var input = Files.newInputStream(file, NOFOLLOW_LINKS)) {
            byte[] data = input.readNBytes(MAX_BYTES + 1);
            if (data.length > MAX_BYTES) return null;
            var parsed = mapper.readTree(data);
            if (!(parsed instanceof ObjectNode snapshot) || snapshot.path("version").asInt() != VERSION
                    || !validReports(snapshot.path("reports"))) return null;
            Entry entry = metadata(snapshot);
            return file(entry.id()).equals(file) && validName(entry.name()) && entry.savedAt() > 0 ? snapshot : null;
        } catch (JsonProcessingException | IllegalArgumentException | NoSuchFileException corrupt) {
            return null;
        }
    }

    private static Entry metadata(ObjectNode snapshot) {
        return new Entry(UUID.fromString(snapshot.path("id").asText()), snapshot.path("name").textValue(),
                snapshot.path("savedAt").longValue(), UUID.fromString(snapshot.path("sessionId").asText()));
    }

    private static boolean validReports(JsonNode reports) {
        return reports.size() == REPORTS.size() && REPORTS.stream().allMatch(reports::has)
                && rows(reports.path("spotter").path("accessPoints")) && rows(reports.path("spotter").path("edges"))
                && rows(reports.path("whistleblower").path("accessPoints"))
                && rows(reports.path("decloaker").path("corpus"))
                && rows(reports.path("inspector").path("accessPoints"))
                && rows(reports.path("profiler"))
                && rows(reports.path("tracker").path("roams"))
                && (reports.path("lookout").isNull() || rows(reports.path("lookout").path("channels")));
    }

    private static boolean rows(JsonNode rows) {
        if (!rows.isArray()) return false;
        for (JsonNode row : rows) if (!row.isObject()) return false;
        return true;
    }

    private static boolean validName(String name) {
        return name != null && !name.isBlank() && name.length() <= 120
                && name.codePoints().noneMatch(Character::isISOControl);
    }

    private boolean checkDirectory(boolean create) throws IOException {
        UserPrincipal operator = operator();
        Path current = directory.getRoot();
        for (Path part : directory) {
            current = current.resolve(part);
            if (Files.notExists(current, NOFOLLOW_LINKS)) {
                if (!create) return false;
                try {
                    Files.createDirectory(current,
                            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
                    FileOwnership.restoreSudoOwner(current);
                } catch (FileAlreadyExistsException exists) {
                    // Another process initialized it. Check the existing path below.
                }
            }
            var attrs = Files.readAttributes(current, PosixFileAttributes.class, NOFOLLOW_LINKS);
            int mode = (int) Files.getAttribute(current, "unix:mode", NOFOLLOW_LINKS);
            boolean rootOwned = (int) Files.getAttribute(current, "unix:uid", NOFOLLOW_LINKS) == 0;
            boolean expectedOwner = attrs.owner().equals(operator);
            if (!attrs.isDirectory() || (current.equals(directory)
                    ? !expectedOwner || (mode & 0777) != 0700
                    : !(expectedOwner || rootOwned) || ((mode & 0022) != 0 && !(rootOwned && (mode & 01000) != 0))))
                throw new IOException("Snapshot directory is not private or has an untrusted parent");
        }
        if (directory.equals(directory.getRoot())) throw new IOException("Invalid snapshot directory");
        return true;
    }

    private boolean privateFile(Path file) throws IOException {
        try {
            var attrs = Files.readAttributes(file, PosixFileAttributes.class, NOFOLLOW_LINKS);
            return attrs.isRegularFile() && attrs.owner().equals(operator())
                    && attrs.permissions().equals(PosixFilePermissions.fromString("rw-------"))
                    && (int) Files.getAttribute(file, "unix:nlink", NOFOLLOW_LINKS) == 1;
        } catch (NoSuchFileException missing) {
            return false;
        }
    }

    private UserPrincipal operator() throws IOException {
        String user = System.getProperty("user.name");
        String sudoUser = System.getenv("SUDO_USER");
        if ("root".equals(user) && sudoUser != null && !sudoUser.isBlank()) user = sudoUser;
        return directory.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByName(user);
    }

    private static final class LimitedOutput extends FilterOutputStream {
        private int remaining = MAX_BYTES;

        LimitedOutput(OutputStream output) { super(output); }

        @Override public void write(int value) throws IOException {
            reserve(1);
            out.write(value);
        }

        @Override public void write(byte[] bytes, int offset, int length) throws IOException {
            reserve(length);
            out.write(bytes, offset, length);
        }

        private void reserve(int length) throws Limit {
            if (length > remaining) throw new Limit("Snapshot exceeds 8 MiB");
            remaining -= length;
        }
    }
}
