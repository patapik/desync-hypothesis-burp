package com.maciejgojny.desync.replay;

public class ClassifyResult {
    public final String verdict;
    public final String detail;
    public final int firstStatus;
    public final int followupStatus;
    public final long elapsedMs;

    public ClassifyResult(String verdict, String detail, int firstStatus, int followupStatus, long elapsedMs) {
        this.verdict = verdict;
        this.detail = detail;
        this.firstStatus = firstStatus;
        this.followupStatus = followupStatus;
        this.elapsedMs = elapsedMs;
    }

    @Override
    public String toString() {
        return verdict + " (" + detail + ") first=" + firstStatus + " followup=" + followupStatus + " " + elapsedMs + "ms";
    }
}