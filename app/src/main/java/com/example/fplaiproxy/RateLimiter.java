package com.example.fplaiproxy;

import java.util.ArrayDeque;
import java.util.Deque;

public final class RateLimiter {
    private final int maxCalls;
    private final long windowMs;
    private final Deque<Long> calls = new ArrayDeque<>();

    public RateLimiter(int maxCalls, long windowMs) {
        this.maxCalls = maxCalls;
        this.windowMs = windowMs;
    }

    public synchronized boolean tryAcquire() {
        long now = System.currentTimeMillis();
        while (!calls.isEmpty() && now - calls.peekFirst() > windowMs) {
            calls.removeFirst();
        }
        if (calls.size() >= maxCalls) return false;
        calls.addLast(now);
        return true;
    }
}
