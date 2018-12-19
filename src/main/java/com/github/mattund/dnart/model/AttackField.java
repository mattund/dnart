package com.github.mattund.dnart.model;

import java.util.LinkedList;
import java.util.List;
import java.util.function.Function;

public class AttackField {
    private final String identifier;
    private final List<Function<Object, Boolean>> conditions = new LinkedList<>();
    private final double ppsThreshold, bpsThreshold;

    public AttackField(String identifier, double ppsThreshold, double bpsThreshold) {
        this.identifier = identifier;

        this.ppsThreshold = ppsThreshold;
        this.bpsThreshold = bpsThreshold;
    }

    public void addCondition(Function<Object, Boolean> condition) {
        this.conditions.add(condition);
    }

    public boolean meetsConditions(Object value) {
        for (Function<Object, Boolean> condition : conditions)
            if (!condition.apply(value)) return false;

        return true;
    }

    public String getIdentifier() {
        return identifier;
    }

    public double getPacketsPerSecondThreshold() {
        return ppsThreshold;
    }

    public double getBytesPerSecondThreshold() {
        return bpsThreshold;
    }
}
