package ewave.passive;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;

/** Access is serialized by PacketBridge. Configuration stays local to the launch account. */
public final class MyNetworkStore {
    private final Path file = Path.of(System.getProperty("rf.networkProfile",
            Path.of(System.getProperty("user.home"), ".config", "ewave", "my-network.json").toString()))
            .toAbsolutePath();
    private final ObjectMapper mapper = new ObjectMapper();
    private MyNetworkProfile cached;

    public MyNetworkProfile get() throws IOException {
        if (cached == null)
            cached = Files.notExists(file) ? MyNetworkProfile.EMPTY : mapper.readValue(file.toFile(), MyNetworkProfile.class);
        if (cached == null) throw new IOException("My Network profile is empty");
        return cached;
    }

    public void save(MyNetworkProfile profile) throws IOException {
        Path directory = file.getParent();
        Files.createDirectories(directory, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        Path pending = Files.createTempFile(directory, ".my-network-", ".json",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        try {
            mapper.writeValue(pending.toFile(), profile);
            Files.move(pending, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            cached = profile;
        } finally {
            Files.deleteIfExists(pending);
        }
    }
}
