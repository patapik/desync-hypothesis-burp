package com.maciejgojny.desync;

public class Hypothesis {
    public String id;
    public String category;
    public String raw;
    public String followup;
    public String expect;
    public String path;
    public String nativeEngine;

    public Hypothesis(String id, String category, String raw, String followup, String expect) {
        this.id = id;
        this.category = category;
        this.raw = raw;
        this.followup = followup;
        this.expect = expect;
    }

    public Hypothesis(String id, String category, String raw, String followup, String expect, String path, String nativeEngine) {
        this.id = id;
        this.category = category;
        this.raw = raw;
        this.followup = followup;
        this.expect = expect;
        this.path = path;
        this.nativeEngine = nativeEngine;
    }
}