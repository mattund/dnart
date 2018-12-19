package com.github.mattund.dnart.model;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.NamedNumber;

import java.lang.reflect.Method;
import java.util.function.Function;

public class ProtocolFieldMethod extends ProtocolField {
    public static final Function<Object, Object> DEFAULT_CAST = (obj) -> obj;
    public static final Function<Object, Object> NAMED_NUMBER_CAST = (obj) -> ((NamedNumber)obj).value().longValue();

    private final Method accessorMethod;
    private final Class type;
    private final Function<Object, Object> cast;

    public ProtocolFieldMethod(Protocol protocol,
                               String identifier,
                               Method accessorMethod,
                               Class type,
                               Function<Object, Object> cast) {
        super(protocol, identifier);

        this.accessorMethod = accessorMethod;
        this.type = type;
        this.cast = cast;
    }

    public Method getAccessorMethod() {
        return accessorMethod;
    }

    public Class getType() {
        return type;
    }

    @Override
    public Object getValue(Packet instance) throws ReflectiveOperationException {
        return cast.apply(accessorMethod.invoke(instance.getHeader()));
    }
}
