package com.github.mattund.dnart;

import com.github.mattund.dnart.model.ProtocolField;
import org.apache.commons.collections4.map.LRUMap;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.Map;

public class TokenBucket {
    private final ProtocolField field;
    private final Map<Object, Counter> counters;

    public TokenBucket(ProtocolField field, int maximumTokens) {
        this.field = field;
        this.counters = Collections.synchronizedMap(new LRUMap<Object, Counter>(maximumTokens));
    }

    public ProtocolField getField() {
        return field;
    }

    public Collection<Map.Entry<Object, Counter>> getEntries() {
        return Collections.unmodifiableCollection(new LinkedList<>(counters.entrySet()));
    }

    public Collection<Counter> getCounters() {
        return Collections.unmodifiableCollection(new LinkedList<>(counters.values()));
    }

    public Counter getCounter(Object key) {
        return counters.computeIfAbsent(key, x -> new Counter());
    }

    public void reset(Object key) {
        counters.remove(key);
    }
}
