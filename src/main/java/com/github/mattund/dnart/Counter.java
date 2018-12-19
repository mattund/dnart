package com.github.mattund.dnart;

public class Counter {
    private final long start;
    private volatile long last;
    private volatile long estimatedPackets;
    private volatile long estimatedBytes;

    public Counter(long start) {
        this.start = start;
    }

    public Counter() {
        this(System.nanoTime());
    }

    public double getEstimatedPacketsPerSecond() {
        long transpired, estimatedPackets;

        synchronized (this) {
            transpired = getTranspired();
            estimatedPackets = getEstimatedPackets();
        }

        if (transpired <= 0) return estimatedPackets;
        else if (estimatedPackets <= 0) return 0;

        double transpiredSeconds = (double)(transpired) / 1_000_000_000D;
        return ((double) estimatedPackets) / transpiredSeconds;
    }

    public double getEstimatedBytesPerSecond() {
        long transpired, estimatedBytes;

        synchronized (this) {
            transpired = getTranspired();
            estimatedBytes = getEstimatedBytes();
        }

        if (transpired <= 0) return estimatedBytes;
        else if (estimatedBytes <= 0) return 0;

        double transpiredSeconds = (double)(transpired) / 1_000_000_000D;
        return ((double) estimatedBytes) / transpiredSeconds;
    }

    public long getEstimatedPackets() {
        return estimatedPackets;
    }

    public long getEstimatedBytes() {
        return estimatedBytes;
    }

    public long getTranspired() {
        synchronized (this) {
            return last - start;
        }
    }

    public long getLast() {
        return last;
    }

    public void setLast(long last) {
        this.last = last;
    }

    public void setEstimatedPackets(long estimatedPackets) {
        this.estimatedPackets = estimatedPackets;
    }
    public void setEstimatedBytes(long estimatedBytes) {
        this.estimatedBytes = estimatedBytes;
    }

    public void addEstimatedValues(long estimatedPackets, long estimatedBytes) {
        synchronized (this) {
            setEstimatedPackets(this.estimatedPackets + estimatedPackets);
            setEstimatedBytes(this.estimatedBytes + estimatedBytes);

            setLast(System.nanoTime());
        }
    }
}
