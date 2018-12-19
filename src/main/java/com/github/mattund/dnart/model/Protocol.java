package com.github.mattund.dnart.model;

import org.pcap4j.packet.Packet;

import java.lang.reflect.Method;
import java.util.*;
import java.util.function.Function;

public class Protocol {
    private final String identifier;

    private final Class<? extends Packet> packetClass;
    private final Class<? extends Packet.Header> headerClass;

    private final List<ProtocolField> fields = new LinkedList<>();
    private final Map<String, ProtocolField> fieldIdMap = new LinkedHashMap<>();

    public Protocol(String identifier,
                    Class<? extends Packet> packetClass,
                    Class<? extends Packet.Header> headerClass) {
        this.identifier = identifier;
        this.packetClass = packetClass;
        this.headerClass = headerClass;
    }

    public String getIdentifier() {
        return identifier;
    }

    public Class<? extends Packet> getPacketClass() {
        return packetClass;
    }

    public Class<? extends Packet.Header> getHeaderClass() {
        return headerClass;
    }

    public ProtocolField createMethodAccessorField(String identifier,
                                                   String accessorMethodName,
                                                   Function<Object, Object> cast)
            throws ReflectiveOperationException {
        // get method and ret type
        Method accessorMethod = headerClass.getMethod(accessorMethodName);
        Class type = accessorMethod.getReturnType();

        // register and create
        ProtocolField field = new ProtocolFieldMethod(
                this,
                identifier,
                accessorMethod,
                type,
                cast
        );

        fields.add(field);
        fieldIdMap.put(identifier, field);

        // return result
        return field;
    }

    public ProtocolField createByteMaskField(String identifier, int offset, int mask) {
        // register and create
        ProtocolField field = new ProtocolFieldByteMask(this, identifier, offset, mask);

        fields.add(field);
        fieldIdMap.put(identifier, field);

        // return result
        return field;
    }

    public Collection<ProtocolField> getFields() {
        return Collections.unmodifiableCollection(fields);
    }

    public ProtocolField getField(String identifier) throws IllegalArgumentException {
        ProtocolField field = fieldIdMap.get(identifier);
        if (field == null) throw new IllegalArgumentException("field not found");
        return field;
    }
}
