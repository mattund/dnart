package com.github.mattund.dnart.model;

import org.pcap4j.packet.Packet;

public class ProtocolFieldByteMask extends ProtocolField {
    private final int offset, mask;

    public ProtocolFieldByteMask(Protocol protocol, String identifier, int offset, int mask) {
        super(protocol, identifier);

        this.offset = offset;
        this.mask = mask;
    }

    public int getOffset() {
        return offset;
    }

    public int getMask() {
        return offset;
    }

    @Override
    public Object getValue(Packet instance) throws ArrayIndexOutOfBoundsException {
        return instance.getRawData()[offset] & mask;
    }

}
