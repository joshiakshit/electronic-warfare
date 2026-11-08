package ewave.fixtures;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/** A finite subprocess result for hardware-free process orchestration tests. */
public final class CompletedProcess extends Process {
    private final InputStream output;
    private final int code;
    public CompletedProcess(String output, int code) {
        this(output.getBytes(StandardCharsets.UTF_8), code);
    }
    public CompletedProcess(byte[] output, int code) {
        this.output = new ByteArrayInputStream(output);
        this.code = code;
    }
    @Override public InputStream getInputStream() { return output; }
    @Override public InputStream getErrorStream() { return InputStream.nullInputStream(); }
    @Override public OutputStream getOutputStream() { return OutputStream.nullOutputStream(); }
    @Override public int waitFor() { return code; }
    @Override public int exitValue() { return code; }
    @Override public void destroy() { }
}
