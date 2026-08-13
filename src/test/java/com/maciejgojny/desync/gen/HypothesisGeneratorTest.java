package com.maciejgojny.desync.gen;

import com.maciejgojny.desync.Hypothesis;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HypothesisGeneratorTest {

    @Test
    void cappedQuickScanSamplesEveryFamily() {
        HypothesisGenerator g = new HypothesisGenerator();
        g.setSmuggledAuthority("collab.example"); // so the absolute-form-oob family appears

        List<Hypothesis> quick = g.generate(20);
        assertEquals(20, quick.size());

        Set<String> categories = new HashSet<>();
        boolean h2Native = false;
        for (Hypothesis h : quick) {
            categories.add(h.category);
            if ("h2".equals(h.nativeEngine)) {
                h2Native = true;
            }
        }
        // Round-robin stratification must reach the late families, not just the first few.
        assertTrue(categories.size() >= 10, "quick scan should span most families, got " + categories);
        assertTrue(h2Native, "h2-native must be reachable in a capped quick scan");
    }

    @Test
    void fullGenerationHasUniqueIds() {
        List<Hypothesis> all = new HypothesisGenerator().generate(0);
        assertTrue(all.size() > 40, "expected the full hypothesis set");
        Set<String> ids = new HashSet<>();
        for (Hypothesis h : all) {
            assertTrue(ids.add(h.id), "duplicate id: " + h.id);
        }
    }

    @Test
    void sharedParserConfusionUsesResolvableContentLengthToken() {
        List<Hypothesis> all = new HypothesisGenerator().generate(0);
        boolean sawSpcWithClToken = all.stream()
                .filter(h -> "shared-parser-confusion".equals(h.category))
                .anyMatch(h -> h.raw.contains("Content-Length: {CL}"));
        assertTrue(sawSpcWithClToken, "SPC family should emit the {CL} token resolved at replay time");
    }
}
