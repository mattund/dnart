package com.github.mattund.dnart.model;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import org.pcap4j.packet.Packet;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

public class Protocols {
    private final Collection<Protocol> protocols;

    // lookups
    private final Map<String, Protocol> idMap;
    private final Map<Class<? extends Packet>, Protocol> packetClassMap;
    private final Map<Class<? extends Packet.Header>, Protocol> headerClassMap;

    public Protocols(Collection<Protocol> protocols) {
        this.protocols = protocols;

        this.idMap = protocols.stream().collect(Collectors.toMap(
                Protocol::getIdentifier,
                x -> x
        ));

        this.packetClassMap = protocols.stream().collect(Collectors.toMap(
                Protocol::getPacketClass,
                x -> x
        ));

        this.headerClassMap = protocols.stream().collect(Collectors.toMap(
                Protocol::getHeaderClass,
                x -> x
        ));
    }

    public Collection<Protocol> getProtocols() {
        return protocols;
    }

    public Protocol getProtocolById(String identifier) {
        return idMap.get(identifier);
    }

    public Protocol getProtocolByPacketClass(Class<? extends Packet> packetClass) {
        return packetClassMap.get(packetClass);
    }

    public Protocol getProtocolByHeaderClass(Class<? extends Packet.Header> headerClass) {
        return headerClassMap.get(headerClass);
    }

    private static List<Protocol> parseProtocols(JsonElement element) throws ReflectiveOperationException {
        if (!element.isJsonObject()) throw new IllegalArgumentException("root node is not JSON object");

        JsonElement protocols = element.getAsJsonObject().get("protocols");
        if (!protocols.isJsonArray()) throw new IllegalArgumentException("protocols node is not JSON array");

        final List<Protocol> protocolList = new LinkedList<>();

        for (JsonElement protocolElement : protocols.getAsJsonArray()) {
            if (!protocolElement.isJsonObject()) throw new IllegalArgumentException("protocol item is not JSON object");

            String id = protocolElement.getAsJsonObject().get("id").getAsString();
            String packetClassName = protocolElement.getAsJsonObject().get("packetClass").getAsString();
            String headerClassName = protocolElement.getAsJsonObject().get("headerClass").getAsString();

            Class<? extends Packet> packetClass =
                    (Class<? extends Packet>) Class.forName(packetClassName);

            Class<? extends Packet.Header> headerClass =
                    (Class<? extends Packet.Header>) Class.forName(headerClassName);

            Protocol protocol = new Protocol(
                    id,
                    packetClass,
                    headerClass
            );

            JsonElement fieldsElement = protocolElement.getAsJsonObject().get("fields");
            if (!fieldsElement.isJsonArray()) throw new IllegalArgumentException("fields node is not JSON array");

            for (JsonElement fieldElement : fieldsElement.getAsJsonArray()) {
                if (!fieldElement.isJsonObject()) throw new IllegalArgumentException("field item is not JSON object");

                if (fieldElement.getAsJsonObject().has("method")) {
                    Function<Object, Object> cast = ProtocolFieldMethod.DEFAULT_CAST;

                    if (fieldElement.getAsJsonObject().has("cast")) {
                        switch (fieldElement.getAsJsonObject().get("cast").getAsString()) {
                            case "namedNumber":
                                cast = ProtocolFieldMethod.NAMED_NUMBER_CAST;
                                break;
                            default:
                                throw new IllegalArgumentException("unsupported cast: " + fieldElement.toString());
                        }
                    }

                    protocol.createMethodAccessorField(
                            fieldElement.getAsJsonObject().get("id").getAsString(),
                            fieldElement.getAsJsonObject().get("method").getAsString(),
                            cast
                    );
                } else if (fieldElement.getAsJsonObject().has("offset") &&
                        fieldElement.getAsJsonObject().has("mask")) {
                    protocol.createByteMaskField(
                            fieldElement.getAsJsonObject().get("id").getAsString(),
                            fieldElement.getAsJsonObject().get("offset").getAsInt(),
                            fieldElement.getAsJsonObject().get("mask").getAsInt()
                    );
                } else {
                    throw new IllegalArgumentException("unexpected field definition: " +  fieldElement.toString());
                }
            }

            protocolList.add(protocol);
        }

        return protocolList;
    }

    public static Protocols readProtocols() throws ReflectiveOperationException, IOException {
        return new Protocols(Collections.unmodifiableCollection(
                parseProtocols(
                        new JsonParser()
                                .parse(new InputStreamReader(Protocol.class.getResourceAsStream("/protocols.json")))
                )
        ));
    }
}
