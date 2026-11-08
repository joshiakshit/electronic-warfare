package ewave.fixtures;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class StreamingCaptureProcess extends Process {
    private final PipedInputStream stdout = new PipedInputStream(8192);
    private final PipedOutputStream writer = new PipedOutputStream(stdout);
    private final CountDownLatch ended = new CountDownLatch(1);
    private final String diagnostic;
    private final int exitCode;
    public StreamingCaptureProcess() throws IOException { this("",0); }
    public StreamingCaptureProcess(String diagnostic, int exitCode) throws IOException {
        this.diagnostic=diagnostic; this.exitCode=exitCode;
    }
    public void write(byte[] bytes) throws IOException { writer.write(bytes); writer.flush(); }
    public void finish() throws IOException { writer.close(); ended.countDown(); }
    @Override public InputStream getInputStream() { return stdout; }
    @Override public OutputStream getOutputStream() { return OutputStream.nullOutputStream(); }
    @Override public InputStream getErrorStream() { return new ByteArrayInputStream(diagnostic.getBytes(StandardCharsets.UTF_8)); }
    @Override public int waitFor() throws InterruptedException { ended.await(); return exitCode; }
    @Override public boolean waitFor(long timeout, TimeUnit unit) throws InterruptedException { return ended.await(timeout,unit); }
    @Override public int exitValue() { if (ended.getCount()!=0) throw new IllegalThreadStateException(); return exitCode; }
    @Override public void destroy() { try { finish(); } catch(IOException failure) { throw new UncheckedIOException(failure); } }
    @Override public Process destroyForcibly() { destroy(); return this; }
}
