package dev.ivar;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Reads the top level field names of a JSON request body and hands the app
 * a request that replays the same bytes. Values are never kept: only names
 * leave the application (section 16).
 */
final class BodyKeys {
    static final String ATTRIBUTE = "dev.ivar.body_keys";
    static final int MAX_BYTES = 64 * 1024;

    private BodyKeys() {}

    static HttpServletRequest read(HttpServletRequest req) throws IOException {
        String type = req.getContentType();
        if (type == null || !type.contains("json") || req.getContentLengthLong() > MAX_BYTES) return req;
        byte[] body = req.getInputStream().readNBytes(MAX_BYTES + 1);
        if (body.length > MAX_BYTES) return req;
        List<String> keys = new ArrayList<>();
        try {
            var node = IvarRuntime.JSON.readTree(body);
            if (node != null && node.isObject()) node.fieldNames().forEachRemaining(keys::add);
        } catch (IOException ignored) {
            // Not JSON after all: no names to report.
        }
        Collections.sort(keys);
        req.setAttribute(ATTRIBUTE, keys.size() > 64 ? keys.subList(0, 64) : keys);
        return new HttpServletRequestWrapper(req) {
            @Override
            public ServletInputStream getInputStream() {
                ByteArrayInputStream in = new ByteArrayInputStream(body);
                return new ServletInputStream() {
                    @Override public int read() { return in.read(); }
                    @Override public int read(byte[] b, int off, int len) { return in.read(b, off, len); }
                    @Override public boolean isFinished() { return in.available() == 0; }
                    @Override public boolean isReady() { return true; }
                    @Override public void setReadListener(ReadListener l) { throw new UnsupportedOperationException("synchronous body"); }
                };
            }

            @Override
            public BufferedReader getReader() {
                return new BufferedReader(new InputStreamReader(new ByteArrayInputStream(body), StandardCharsets.UTF_8));
            }
        };
    }

    @SuppressWarnings("unchecked")
    static List<String> of(HttpServletRequest req) {
        Object keys = req.getAttribute(ATTRIBUTE);
        return keys instanceof List<?> l ? (List<String>) l : List.of();
    }
}
