package pl.aiwcorpo.mcp.gateway.upstream;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Hard limit on the bytes read from a server response, counted as they are read, so a body without line
 * breaks or without Content-Length cannot grow the gateway's memory past the limit.
 */
final class BoundedInputStream extends FilterInputStream {

    static final class LimitExceededException extends IOException {
        LimitExceededException() {
            super("response exceeds the size limit");
        }
    }

    private final long limit;
    private long count;

    BoundedInputStream(InputStream in, long limit) {
        super(in);
        this.limit = limit;
    }

    @Override
    public int read() throws IOException {
        int b = super.read();
        if (b >= 0) {
            add(1);
        }
        return b;
    }

    @Override
    public int read(byte[] buffer, int offset, int length) throws IOException {
        int n = super.read(buffer, offset, length);
        if (n > 0) {
            add(n);
        }
        return n;
    }

    @Override
    public long skip(long n) throws IOException {
        long skipped = super.skip(n);
        add(skipped);
        return skipped;
    }

    private void add(long n) throws LimitExceededException {
        count += n;
        if (count > limit) {
            throw new LimitExceededException();
        }
    }
}
