package ewave.ui;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import ewave.capture.MonitorPcapReader;
import ewave.passive.FileOwnership;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;

/** Stores uploaded classic PCAPs by opaque ID. Each complete record is published in one move. */
final class RecordingLibrary {
    static final long MAX_BYTES = 128L * 1024 * 1024;
    private static final String DATA = "capture.pcap";
    private static final String ENTRY = "recording.json";
    private final Path directory = FileOwnership.storagePath("rf.recordingDirectory", ".local", "share", "ewave", "recordings");
    private final ObjectMapper mapper;

    record Recording(UUID id, String name, long bytes, long importedAt) { }

    static final class TooLarge extends IOException { }

    RecordingLibrary(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    List<Recording> recordings() throws IOException {
        if (Files.notExists(directory)) return List.of();
        List<Recording> recordings = new ArrayList<>();
        try (var children = Files.list(directory)) {
            for (Path child : children.toList()) {
                UUID id;
                try {
                    id = UUID.fromString(child.getFileName().toString());
                } catch (IllegalArgumentException ignored) {
                    continue;
                }
                Recording recording = find(id);
                if (recording != null) recordings.add(recording);
            }
        }
        recordings.sort(Comparator.comparingLong(Recording::importedAt).reversed().thenComparing(Recording::id));
        return List.copyOf(recordings);
    }

    Recording find(UUID id) throws IOException {
        Path entry = directory.resolve(id.toString());
        Path metadata = entry.resolve(ENTRY);
        if (!Files.isDirectory(entry, LinkOption.NOFOLLOW_LINKS)
                || !Files.isRegularFile(metadata, LinkOption.NOFOLLOW_LINKS)
                || !Files.isRegularFile(file(id), LinkOption.NOFOLLOW_LINKS)) return null;
        Recording recording;
        try {
            recording = mapper.readValue(metadata.toFile(), Recording.class);
        } catch (JsonProcessingException corrupt) {
            return null;
        }
        return recording != null && id.equals(recording.id()) ? recording : null;
    }

    Path file(UUID id) {
        return directory.resolve(id.toString()).resolve(DATA);
    }

    Recording add(String name, InputStream input) throws IOException {
        if (name == null || name.isBlank() || name.length() > 255
                || name.indexOf('/') >= 0 || name.indexOf('\\') >= 0
                || name.codePoints().anyMatch(Character::isISOControl))
            throw new IllegalArgumentException("Provide a valid recording filename");
        FileOwnership.createPrivateDirectories(directory);
        Path staged = Files.createTempDirectory(directory, ".import-", privatePermissions("rwx------"));
        Path data = staged.resolve(DATA);
        Path metadata = staged.resolve(ENTRY);
        UUID id = UUID.randomUUID();
        try {
            Files.createFile(data, privatePermissions("rw-------"));
            long size = 0;
            try (var output = Files.newOutputStream(data)) {
                byte[] buffer = new byte[64 * 1024];
                for (int count; (count = input.read(buffer)) != -1; ) {
                    size += count;
                    if (size > MAX_BYTES) throw new TooLarge();
                    output.write(buffer, 0, count);
                }
            }
            if (size < 24) throw new IllegalArgumentException("Truncated PCAP header");
            try (var stored = Files.newInputStream(data)) {
                MonitorPcapReader.validateRecording(stored);
            } catch (IOException invalid) {
                throw new IllegalArgumentException(invalid.getMessage(), invalid);
            }
            Recording recording = new Recording(id, name, size, System.currentTimeMillis());
            Files.createFile(metadata, privatePermissions("rw-------"));
            mapper.writeValue(metadata.toFile(), recording);
            FileOwnership.restoreSudoOwner(data);
            FileOwnership.restoreSudoOwner(metadata);
            FileOwnership.restoreSudoOwner(staged);
            Files.move(staged, directory.resolve(id.toString()), StandardCopyOption.ATOMIC_MOVE);
            return recording;
        } finally {
            Files.deleteIfExists(data);
            Files.deleteIfExists(metadata);
            Files.deleteIfExists(staged);
        }
    }

    private FileAttribute<?>[] privatePermissions(String mode) {
        return directory.getFileSystem().supportedFileAttributeViews().contains("posix")
                ? new FileAttribute<?>[]{PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString(mode))}
                : new FileAttribute<?>[0];
    }
}
