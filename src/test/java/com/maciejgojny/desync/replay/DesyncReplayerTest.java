package com.maciejgojny.desync.replay;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for the framing-based classifier and identity match. The interesting
 * logic lives in private helpers (no socket needed), so they are exercised via
 * reflection on captured/synthetic response bytes — the same cases verified live
 * against the GGSec Cortex CSD lab.
 */
class DesyncReplayerTest {

    private static final DesyncReplayer R = new DesyncReplayer();

    private static byte[] b(String s) {
        return s.getBytes(StandardCharsets.ISO_8859_1);
    }

    private static boolean hasQueued(String s) throws Exception {
        Method m = DesyncReplayer.class.getDeclaredMethod("hasQueuedResponse", byte[].class);
        m.setAccessible(true);
        return (boolean) m.invoke(R, (Object) b(s));
    }

    private static int status(String s) throws Exception {
        Method m = DesyncReplayer.class.getDeclaredMethod("extractStatus", byte[].class);
        m.setAccessible(true);
        return (int) m.invoke(R, (Object) b(s));
    }

    private static Object signature(String s) throws Exception {
        Method m = DesyncReplayer.class.getDeclaredMethod("signature", byte[].class);
        m.setAccessible(true);
        return m.invoke(R, (Object) b(s));
    }

    private static boolean identityPoison(String followup, DesyncReplayer.Baseline base) throws Exception {
        Method m = DesyncReplayer.class.getDeclaredMethod("identityPoison", byte[].class, DesyncReplayer.Baseline.class);
        m.setAccessible(true);
        return (boolean) m.invoke(R, b(followup), base);
    }

    // ---- hasQueuedResponse: frames response #1, then looks for a real second response ----

    @Test
    void singleContentLengthResponseIsNotQueued() throws Exception {
        assertFalse(hasQueued("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO"));
    }

    @Test
    void pipelinedResponsesWithBodyAreQueued() throws Exception {
        // The 2nd response is NOT preceded by a blank line (body ends right before it) —
        // the case a naive "\r\n\r\nHTTP/1." anchor would miss.
        assertTrue(hasQueued("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLOHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"));
    }

    @Test
    void singleChunkedResponseIsNotQueued() throws Exception {
        assertFalse(hasQueued("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHELLO\r\n0\r\n\r\n"));
    }

    @Test
    void chunkedThenQueuedResponseIsDetected() throws Exception {
        assertTrue(hasQueued("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHELLO\r\n0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"));
    }

    @Test
    void statusLineReflectedInBodyIsNotQueued() throws Exception {
        assertFalse(hasQueued("HTTP/1.1 200 OK\r\nContent-Length: 30\r\n\r\nyou sent HTTP/1.1 GET evil hehe"));
    }

    @Test
    void unknownFramingIsConservativelyNotQueued() throws Exception {
        assertFalse(hasQueued("HTTP/1.1 200 OK\r\nServer: x\r\n\r\nbody then HTTP/1.1 junk"));
    }

    // ---- extractStatus: tolerant of multiple spaces ----

    @Test
    void extractStatusHandlesNormalAndDoubleSpace() throws Exception {
        assertEquals(200, status("HTTP/1.1 200 OK"));
        assertEquals(404, status("HTTP/1.1  404 x"));
        assertEquals(500, status("HTTP/1.1 500"));
        assertEquals(-1, status("garbage"));
    }

    // ---- identityPoison: smuggled resource served on the follow-up slot ----

    @Test
    void identityPoisonFiresWhenSmuggledResourceAnswersFollowup() throws Exception {
        String steal = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nSTEAL-PAGE";
        String worm = "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nWORM-PAGE";
        DesyncReplayer.Baseline base = new DesyncReplayer.Baseline(
                (DesyncReplayer.Sig) signature(steal), (DesyncReplayer.Sig) signature(worm));

        assertTrue(identityPoison(worm, base), "worm on follow-up slot = poison");
        assertFalse(identityPoison(steal, base), "expected resource = clean");
    }

    @Test
    void identityPoisonSkippedWhenBaselinesEqualOrNull() throws Exception {
        String worm = "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nWORM-PAGE";
        DesyncReplayer.Sig s = (DesyncReplayer.Sig) signature(worm);
        assertFalse(identityPoison(worm, new DesyncReplayer.Baseline(s, s)), "indistinguishable baselines");
        assertFalse(identityPoison(worm, null), "no baseline");
    }
}
