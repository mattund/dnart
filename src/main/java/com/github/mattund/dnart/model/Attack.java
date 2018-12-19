package com.github.mattund.dnart.model;

public class Attack {
    private final String identifier;
    private final String name;
    private final AttackField field;

    public Attack(String identifier, String name, AttackField field) {
        this.identifier = identifier;
        this.name = name;
        this.field = field;
    }

    public String getIdentifier() {
        return identifier;
    }

    public String getName() {
        return name;
    }

    public AttackField getField() {
        return field;
    }
}
