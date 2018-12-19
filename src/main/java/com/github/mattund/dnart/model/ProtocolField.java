package com.github.mattund.dnart.model;

import org.pcap4j.packet.Packet;

public abstract class ProtocolField {
    private final Protocol protocol;
    private final String identifier;

    public ProtocolField(Protocol protocol, String identifier) {
        this.protocol = protocol;
        this.identifier = identifier;
    }

    public final Protocol getProtocol() {
        return protocol;
    }

    public final String getIdentifier() {
        return identifier;
    }

    public abstract Object getValue(Packet instance) throws Exception;
}
