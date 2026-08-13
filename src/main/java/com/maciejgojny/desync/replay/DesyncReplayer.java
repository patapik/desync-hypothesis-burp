package com.maciejgojny.desync.replay;

import com.maciejgojny.desync.Hypothesis;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

public class DesyncReplayer {

    /** Inter-read quiet window: once no bytes arrive for this long, a response burst is deemed complete. */
    private static final int GAP_MS = 700;

    private final int connectTimeoutMs;
    private final int readTimeoutMs;
    private final int firstReadTimeoutMs;

    public DesyncReplayer() {
        this(8000, 4000, 6000);
    }

    public DesyncReplayer(int connectTimeoutMs, int readTimeoutMs, int firstReadTimeoutMs) {
        this.connectTimeoutMs = connectTimeoutMs;
        this.readTimeoutMs = readTimeoutMs;
        this.firstReadTimeoutMs = firstReadTimeoutMs;
    }

    public ClassifyResult replay(Hypothesis hyp, String host, int port, boolean tls) {
        return replay(hyp, host, port, tls, null);
    }

    public ClassifyResult replay(Hypothesis hyp, String host, int port, boolean tls, Baseline baseline) {
        long start = System.currentTimeMillis();
        String hostHeader = host + (port != (tls ? 443 : 80) ? (":" + port) : "");
        String raw = hyp.raw.replace("{HOST}", hostHeader);
        raw = resolveContentLength(raw);
        String followupRaw = hyp.followup == null ? null : hyp.followup.replace("{HOST}", hostHeader);

        try (Socket socket = openSocket(host, port, tls)) {
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();

            out.write(raw.getBytes(StandardCharsets.ISO_8859_1));
            out.flush();

            byte[] firstResp;
            try {
                firstResp = readAvailable(socket, in, firstReadTimeoutMs);
            } catch (java.net.SocketTimeoutException e) {
                return new ClassifyResult("timeout", "no response within timeout", -1, -1, System.currentTimeMillis() - start);
            }

            int firstStatus = extractStatus(firstResp);

            // Front-end already rejected the malformed request: the follow-up is pointless,
            // so return immediately instead of paying another ~1s read.
            if (firstStatus == 400 || firstStatus == 501) {
                return new ClassifyResult("reject", "first response rejected (" + firstStatus + ")", firstStatus, -1, System.currentTimeMillis() - start);
            }

            if (followupRaw == null) {
                return new ClassifyResult("sent", "no followup configured", firstStatus, -1, System.currentTimeMillis() - start);
            }

            out.write(followupRaw.getBytes(StandardCharsets.ISO_8859_1));
            out.flush();

            byte[] followupResp;
            try {
                followupResp = readAvailable(socket, in, readTimeoutMs);
            } catch (java.net.SocketTimeoutException e) {
                return new ClassifyResult("anomaly", "followup timed out", firstStatus, -1, System.currentTimeMillis() - start);
            }

            int followupStatus = extractStatus(followupResp);

            String verdict;
            String detail;
            if (hasQueuedResponse(firstResp)) {
                verdict = "desync";
                detail = "queued response in first read";
            } else if (identityPoison(followupResp, baseline)) {
                verdict = "desync";
                detail = "identity: smuggled resource served on follow-up slot";
            } else if (followupStatus > 0 && followupStatus != firstStatus) {
                verdict = "anomaly";
                detail = "status differential first=" + firstStatus + " followup=" + followupStatus;
            } else {
                verdict = "clean";
                detail = "no smuggling signal";
            }
            return new ClassifyResult(verdict, detail, firstStatus, followupStatus, System.currentTimeMillis() - start);

        } catch (java.net.SocketTimeoutException e) {
            return new ClassifyResult("timeout", "connect/handshake timeout", -1, -1, System.currentTimeMillis() - start);
        } catch (java.net.SocketException e) {
            return new ClassifyResult("break", e.getMessage() == null ? "connection error" : e.getMessage(), -1, -1, System.currentTimeMillis() - start);
        } catch (Exception e) {
            return new ClassifyResult("error", e.toString(), -1, -1, System.currentTimeMillis() - start);
        }
    }

    /**
     * Resolves a {CL} placeholder to the byte-accurate Content-Length of the body,
     * computed AFTER {HOST} (and any other) substitution. Requests without {CL}
     * keep their literal, intentionally-crafted Content-Length untouched.
     */
    private String resolveContentLength(String raw) {
        if (!raw.contains("{CL}")) {
            return raw;
        }
        int idx = raw.indexOf("\r\n\r\n");
        String body = idx >= 0 ? raw.substring(idx + 4) : "";
        int cl = body.getBytes(StandardCharsets.ISO_8859_1).length;
        return raw.replace("{CL}", Integer.toString(cl));
    }

    /**
     * Per-scan resource fingerprints, probed once on clean connections. Lets the
     * classifier tell a "quiet 200/200" desync apart from a clean run by checking
     * WHICH resource answered on the follow-up slot (smuggled vs expected), the way
     * an oracle-free response-identity check does.
     */
    public static class Baseline {
        public final Sig followupSig;
        public final Sig smuggledSig;

        public Baseline(Sig followupSig, Sig smuggledSig) {
            this.followupSig = followupSig;
            this.smuggledSig = smuggledSig;
        }
    }

    /** Stable-enough fingerprint of a response: status + body length + body checksum. */
    public static class Sig {
        final int status;
        final int bodyLen;
        final int checksum;

        Sig(int status, int bodyLen, int checksum) {
            this.status = status;
            this.bodyLen = bodyLen;
            this.checksum = checksum;
        }

        boolean matches(Sig o) {
            return o != null && status == o.status && bodyLen == o.bodyLen && checksum == o.checksum;
        }

        @Override
        public String toString() {
            return status + "/" + bodyLen + "b";
        }
    }

    /** Probe a single GET path on a fresh connection and fingerprint the response. */
    public Sig probe(String host, int port, boolean tls, String path) {
        String hostHeader = host + (port != (tls ? 443 : 80) ? (":" + port) : "");
        String req = "GET " + path + " HTTP/1.1\r\nHost: " + hostHeader + "\r\nConnection: close\r\n\r\n";
        try (Socket socket = openSocket(host, port, tls)) {
            socket.setSoTimeout(firstReadTimeoutMs);
            socket.getOutputStream().write(req.getBytes(StandardCharsets.ISO_8859_1));
            socket.getOutputStream().flush();
            return signature(readToEnd(socket.getInputStream()));
        } catch (Exception e) {
            return null;
        }
    }

    /** Build both baselines for a scan. Returns null only if neither probe succeeded. */
    public Baseline buildBaseline(String host, int port, boolean tls, String smuggledPath, String followupPath) {
        Sig followupSig = probe(host, port, tls, followupPath);
        Sig smuggledSig = probe(host, port, tls, smuggledPath);
        if (followupSig == null && smuggledSig == null) {
            return null;
        }
        return new Baseline(followupSig, smuggledSig);
    }

    /**
     * True if the follow-up slot served the SMUGGLED resource instead of the expected
     * follow-up resource — a response-queue poison that a plain status compare misses
     * (both are often 200). Skipped when the two baselines are indistinguishable.
     */
    private boolean identityPoison(byte[] followupResp, Baseline b) {
        if (b == null || b.smuggledSig == null || b.followupSig == null) {
            return false;
        }
        if (b.smuggledSig.matches(b.followupSig)) {
            return false;
        }
        Sig fu = signature(followupResp);
        if (fu == null) {
            return false;
        }
        return b.smuggledSig.matches(fu) && !b.followupSig.matches(fu);
    }

    private Sig signature(byte[] data) {
        if (!startsWith(data, 0, "HTTP/1.")) {
            return null;
        }
        int status = extractStatus(data);
        int headerEnd = indexOf(data, 0, "\r\n\r\n");
        if (headerEnd < 0) {
            return null;
        }
        int bodyStart = headerEnd + 4;
        String headers = new String(data, 0, headerEnd, StandardCharsets.ISO_8859_1);
        int end = responseEnd(headers, data, bodyStart);
        if (end < 0 || end > data.length) {
            end = data.length;
        }
        int checksum = 0;
        for (int i = bodyStart; i < end; i++) {
            checksum = checksum * 31 + (data[i] & 0xff);
        }
        return new Sig(status, end - bodyStart, checksum);
    }

    private byte[] readToEnd(InputStream in) {
        ByteArrayOutputStream acc = new ByteArrayOutputStream();
        byte[] buf = new byte[65536];
        try {
            int n;
            while ((n = in.read(buf)) > 0) {
                acc.write(buf, 0, n);
            }
        } catch (Exception ignored) {
            // timeout / connection close -> return what we have
        }
        return acc.toByteArray();
    }

    /** True if, after the first framed HTTP response, more bytes begin another HTTP response. */
    private boolean hasQueuedResponse(byte[] data) {
        if (!startsWith(data, 0, "HTTP/1.")) {
            return false;
        }
        int headerEnd = indexOf(data, 0, "\r\n\r\n");
        if (headerEnd < 0) {
            return false;
        }
        int bodyStart = headerEnd + 4;
        String headers = new String(data, 0, headerEnd, StandardCharsets.ISO_8859_1);
        int end = responseEnd(headers, data, bodyStart);
        // Unknown framing (no Content-Length, not chunked): can't split reliably -> no FP.
        if (end < 0 || end >= data.length) {
            return false;
        }
        return startsWith(data, end, "HTTP/1.");
    }

    /** Byte offset just past response #1, or -1 if its length can't be determined. */
    private int responseEnd(String headers, byte[] data, int bodyStart) {
        int cl = headerInt(headers, "content-length");
        if (cl >= 0) {
            return bodyStart + cl;
        }
        if (isChunked(headers)) {
            return chunkedEnd(data, bodyStart);
        }
        return -1;
    }

    private int headerInt(String headers, String name) {
        for (String line : headers.split("\r\n")) {
            int c = line.indexOf(':');
            if (c > 0 && line.substring(0, c).trim().equalsIgnoreCase(name)) {
                try {
                    return Integer.parseInt(line.substring(c + 1).trim());
                } catch (NumberFormatException e) {
                    return -1;
                }
            }
        }
        return -1;
    }

    private boolean isChunked(String headers) {
        for (String line : headers.split("\r\n")) {
            int c = line.indexOf(':');
            if (c > 0 && line.substring(0, c).trim().equalsIgnoreCase("transfer-encoding")
                    && line.substring(c + 1).toLowerCase().contains("chunked")) {
                return true;
            }
        }
        return false;
    }

    private int chunkedEnd(byte[] data, int start) {
        int pos = start;
        while (pos < data.length) {
            int lineEnd = indexOf(data, pos, "\r\n");
            if (lineEnd < 0) {
                return -1;
            }
            String sizeTok = new String(data, pos, lineEnd - pos, StandardCharsets.ISO_8859_1);
            int semi = sizeTok.indexOf(';');
            if (semi >= 0) {
                sizeTok = sizeTok.substring(0, semi);
            }
            int size;
            try {
                size = Integer.parseInt(sizeTok.trim(), 16);
            } catch (NumberFormatException e) {
                return -1;
            }
            if (size == 0) {
                int termEnd = indexOf(data, lineEnd, "\r\n\r\n");
                return termEnd < 0 ? -1 : termEnd + 4;
            }
            pos = lineEnd + 2 + size + 2;
        }
        return -1;
    }

    private static int indexOf(byte[] data, int from, String pat) {
        byte[] p = pat.getBytes(StandardCharsets.ISO_8859_1);
        outer:
        for (int i = Math.max(0, from); i <= data.length - p.length; i++) {
            for (int j = 0; j < p.length; j++) {
                if (data[i + j] != p[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private static boolean startsWith(byte[] data, int off, String pat) {
        byte[] p = pat.getBytes(StandardCharsets.ISO_8859_1);
        if (off < 0 || off + p.length > data.length) {
            return false;
        }
        for (int j = 0; j < p.length; j++) {
            if (data[off + j] != p[j]) {
                return false;
            }
        }
        return true;
    }

    private Socket openSocket(String host, int port, boolean tls) throws Exception {
        if (tls) {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{new PermissiveTrustManager()}, new SecureRandom());
            SSLSocketFactory factory = ctx.getSocketFactory();
            SSLSocket sslSocket = (SSLSocket) factory.createSocket();
            sslSocket.connect(new InetSocketAddress(host, port), connectTimeoutMs);
            // Bound the TLS handshake too: a server that accepts TCP but stalls the
            // handshake would otherwise hang the scan thread forever (default SO_TIMEOUT
            // is 0 = infinite). A stalled handshake now throws SocketTimeoutException,
            // which the caller maps to a "timeout" verdict.
            sslSocket.setSoTimeout(connectTimeoutMs);
            sslSocket.startHandshake();
            return sslSocket;
        }
        Socket socket = new Socket();
        socket.connect(new InetSocketAddress(host, port), connectTimeoutMs);
        return socket;
    }

    /**
     * Reads a response burst. Blocks up to {@code firstByteMs} for the FIRST byte (so a
     * silent server still surfaces as a timeout), then keeps draining with a short
     * inter-read "quiet gap" until no more data arrives for {@code GAP_MS} or the overall
     * budget expires. This is what lets a QUEUED second response — which arrives a few
     * milliseconds after response #1 — land in the same buffer. The old in.available()
     * gate stopped as soon as the socket was momentarily empty and dropped that response,
     * mislabelling real desyncs as "clean".
     */
    private byte[] readAvailable(Socket socket, InputStream in, int firstByteMs) throws Exception {
        ByteArrayOutputStream acc = new ByteArrayOutputStream();
        byte[] buf = new byte[65536];

        socket.setSoTimeout(firstByteMs);
        int n = in.read(buf); // SocketTimeoutException here -> caller treats as timeout
        if (n < 0) {
            return new byte[0];
        }
        if (n > 0) {
            acc.write(buf, 0, n);
        }

        long deadline = System.currentTimeMillis() + firstByteMs;
        socket.setSoTimeout(GAP_MS);
        while (System.currentTimeMillis() < deadline) {
            try {
                n = in.read(buf);
            } catch (java.net.SocketTimeoutException e) {
                break; // quiet for GAP_MS -> the burst is complete
            }
            if (n < 0) {
                break; // EOF
            }
            if (n > 0) {
                acc.write(buf, 0, n);
            }
        }
        return acc.toByteArray();
    }

    private int extractStatus(byte[] resp) {
        String s = new String(resp, StandardCharsets.ISO_8859_1);
        if (!s.startsWith("HTTP/")) {
            return -1;
        }
        // Tolerate multiple spaces in the status line: skip to the first space run, then the digits.
        int i = s.indexOf(' ');
        if (i < 0) {
            return -1;
        }
        while (i < s.length() && s.charAt(i) == ' ') {
            i++;
        }
        int j = i;
        while (j < s.length() && Character.isDigit(s.charAt(j))) {
            j++;
        }
        if (j == i) {
            return -1;
        }
        try {
            return Integer.parseInt(s.substring(i, j));
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private static class PermissiveTrustManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        @Override
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }
}