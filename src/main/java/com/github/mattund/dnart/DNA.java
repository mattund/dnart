package com.github.mattund.dnart;


import com.github.mattund.dnart.model.*;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import in.ashwanthkumar.slack.webhook.Slack;
import in.ashwanthkumar.slack.webhook.SlackAttachment;
import io.lettuce.core.RedisClient;
import io.lettuce.core.pubsub.RedisPubSubAdapter;
import io.lettuce.core.pubsub.StatefulRedisPubSubConnection;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.function.Consumer;
import java.util.logging.ConsoleHandler;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

public class DNA {
    public static void main(String[] args) {
        Logger logger = Logger.getGlobal();

        try {
            logger.setUseParentHandlers(false);

            FileHandler allMessages = new FileHandler("info.log", true);
            allMessages.setFormatter(new LineLogFormatter());
            allMessages.setLevel(Level.INFO);
            logger.addHandler(allMessages);

            FileHandler errorMessages = new FileHandler("error.log", true);
            errorMessages.setFormatter(new LineLogFormatter());
            errorMessages.setLevel(Level.SEVERE);
            logger.addHandler(errorMessages);

            ConsoleHandler handler = new ConsoleHandler();
            handler.setFormatter(new LineLogFormatter());
            handler.setLevel(Level.ALL);
            logger.addHandler(handler);

            // Connect to database backend
            Properties properties = new Properties();
            properties.load(new FileInputStream(new File("dna.properties")));

            Level logLevel = Level.parse(properties.getProperty("system.log.level"));
            logger.setLevel(logLevel);
            logger.log(logLevel, "System root log level set to " + logLevel.getName() + ".");

            String redisHost = properties.getProperty("redis.host");
            int redisPort = Integer.parseInt(properties.getProperty("redis.port"));
            int redisBacklog = Integer.parseInt(properties.getProperty("redis.backlog"));
            String redisChannel = properties.getProperty("redis.channel");
            int tokenSize = Integer.parseInt(properties.getProperty("dna.tokensize"));
            int packetMultiplier = Integer.parseInt(properties.getProperty("dna.packetmultiplier"));
            int defaultPps = Integer.parseInt(properties.getProperty("dna.defaultpps"));
            int defaultBps = Integer.parseInt(properties.getProperty("dna.defaultbps"));
            int delay = Integer.parseInt(properties.getProperty("dna.delay"));

            logger.info("Compiling protocol metadata...");
            Protocols protocols = Protocols.readProtocols();

            logger.info("Building protocol token buckets from protocol definitions...");
            Map<ProtocolField, TokenBucket> fieldBuckets = new LinkedHashMap<>();
            Map<String, TokenBucket> nameBuckets = new LinkedHashMap<>();

            for (Protocol protocol : protocols.getProtocols()) {
                for (ProtocolField field : protocol.getFields()) {
                    TokenBucket bucket = new TokenBucket(field, tokenSize);
                    fieldBuckets.put(field, bucket);
                    nameBuckets.put(field.getProtocol().getIdentifier() + "." + field.getIdentifier(), bucket);
                }
            }
            logger.info("Built " + fieldBuckets.size() + " protocol token buckets.");

            logger.info("Reading attack definitions...");
            List<Attack> attackList = new LinkedList<>();
            JsonObject rootObject = (new JsonParser()).parse(new FileReader("attacks.json")).getAsJsonObject();
            JsonArray attacksArray = rootObject.get("attacks").getAsJsonArray();
            for (JsonElement attackElement : attacksArray) {
                JsonObject attackObject = attackElement.getAsJsonObject();
                String identifier = attackObject.get("id").getAsString();
                String name = attackObject.get("name").getAsString();

                JsonObject fieldObject = attackObject.get("field").getAsJsonObject();
                String fieldId = fieldObject.get("id").getAsString();

                double ppsThreshold = fieldObject.has("pps") ? fieldObject.get("pps").getAsDouble() : defaultPps;
                double bpsThreshold = fieldObject.has("bps") ? fieldObject.get("bps").getAsDouble() : defaultBps;

                AttackField field = new AttackField(fieldId, ppsThreshold, bpsThreshold);

                if (fieldObject.has("where")) {
                    for (JsonElement whereElement : fieldObject.get("where").getAsJsonArray()) {
                        JsonObject whereObject = whereElement.getAsJsonObject();
                        if (whereObject.has("eq")) {
                            Object value = whereObject.get("eq").getAsInt();
                            field.addCondition(o -> o.equals(value));
                        } else {
                            throw new IllegalArgumentException("unrecognized where clause: " + whereObject.toString());
                        }
                    }
                }

                attackList.add(new Attack(identifier, name, field));
            }
            logger.info("Read " + attackList.size() + " attack definitions.");


            logger.info("Reading webhooks...");
            List<Webhook> webhooks = new LinkedList<>();
            JsonObject rootWebhooksObject = (new JsonParser()).parse(new FileReader("webhooks.json")).getAsJsonObject();
            JsonArray webhooksArray = rootWebhooksObject.get("webhooks").getAsJsonArray();
            for (JsonElement webook : webhooksArray) {
                JsonObject webhookObject = webook.getAsJsonObject();
                webhooks.add(new Webhook(
                        webhookObject.get("title").getAsString(),
                        webhookObject.get("url").getAsString()
                ));
            }
            logger.info("Read " + webhooks.size() + " webhooks.");

            logger.info("Connecting to redis...");
            BlockingQueue<String> redisQueue = new LinkedBlockingDeque<>(redisBacklog);

            RedisClient client = RedisClient.create("redis://" + redisHost + ":" + redisPort);
            StatefulRedisPubSubConnection<String, String> connection = client.connectPubSub();
            connection.addListener(new RedisPubSubAdapter<String, String>() {
                @Override
                public void message(String channel, String message) {
                    try {
                        redisQueue.add(message);
                    } catch (IllegalStateException ex) {
                        logger.warning("Failed to add redis message to queue!  Is the system overloaded?");
                    }
                }
            });

            Consumer<Packet> packetHandler = packet -> {
                long packetSize = packet.length();

                while (packet != null) {
                    Protocol protocol = protocols.getProtocolByPacketClass(packet.getClass());

                    if (protocol != null) {
                        TokenBucket bucket;
                        for (ProtocolField field : protocol.getFields()) {
                            bucket = fieldBuckets.get(field);
                            if (bucket == null) continue;

                            try {
                                bucket
                                        .getCounter(field.getValue(packet))
                                        .addEstimatedValues(packetMultiplier, packetSize * packetMultiplier);
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                        }
                    }

                    packet = packet.getPayload();
                }
            };

            Consumer<JsonElement> alertHandler = element -> {
                String packetDataString = element.getAsJsonObject().get("packet").getAsString();

                byte[] packetData;
                try {
                    packetData =  java.util.Base64.getDecoder().decode(packetDataString);
                } catch (IllegalArgumentException e) {
                    throw new RuntimeException(e);
                }

                EthernetPacket ethernetPacket;
                try {
                    ethernetPacket = EthernetPacket.newPacket(packetData, 0, packetData.length);
                } catch (IllegalRawDataException e) {
                    throw new RuntimeException(e);
                }

                packetHandler.accept(ethernetPacket);
            };

            logger.info("Starting workers...");

            Runnable worker = () -> {
                JsonParser parser = new JsonParser();
                JsonElement element;

                while (true) {
                    try {
                        element = parser.parse(redisQueue.take());
                    } catch (Throwable e) {
                        logger.log(Level.SEVERE, "Problem retrieving alert from queue", e);
                        continue;
                    }

                    try {
                        alertHandler.accept(element);
                    } catch (Throwable e) {
                        logger.log(Level.SEVERE, "Problem handling alert", e);
                    }
                }
            };

            int workers = Integer.parseInt(properties.getProperty("dna.workers"));
            ExecutorService executorService = Executors.newFixedThreadPool(workers);
            for (int i = 0; i < workers; i ++) executorService.submit(worker);

            connection.sync().subscribe(redisChannel);

            logger.info("Ready.");

            long wakeTime = System.currentTimeMillis();
            long interval = delay; // ms, 5 sec
            long baseThreshold = defaultPps; // 1Kpps

            ExecutorService webhookDispatchService = Executors.newFixedThreadPool(1);

            while (true) {
                for (Map.Entry<ProtocolField, TokenBucket> bucket : fieldBuckets.entrySet()) {
                    bucket.getValue().getEntries()
                            .stream()
                            .filter(x -> System.nanoTime() - x.getValue().getLast() >= (interval * 1_000_000L))
                            .forEach(expired -> {
                                bucket.getValue().reset(expired.getKey());

                                // Mark end of attack?
                            });

                    /*bucket.getValue().getEntries()
                            .stream()
                            .filter(x -> x.getValue().getTranspired() >= (interval * 1_000_000L))
                            .filter(x -> x.getValue().getEstimatedPacketsPerSecond() >= baseThreshold)
                            .forEach(alerting -> {
                                logger.log(Level.WARNING,
                                        bucket.getKey().getProtocol().getIdentifier()
                                                + "." + bucket.getKey().getIdentifier() + "=" +
                                                alerting.getKey() + ": " +
                                                String.format("%.2f",
                                                        alerting.getValue().getEstimatedPacketsPerSecond()
                                                                / 1_000D)
                                                + "Kpps, " +
                                                String.format("%.3f",
                                                        (alerting.getValue().getEstimatedBytesPerSecond() * 8D)
                                                                / 1_000_000D)
                                                + "Mbps, " +
                                                String.format("%.2f",
                                                        ((double)alerting.getValue().getEstimatedBytes() /
                                                                (double)alerting.getValue().getEstimatedPackets()))
                                                + " bytes/pkt for " +
                                                    String.format("%.3f",
                                                            alerting.getValue().getTranspired() / 1_000_000_000D)
                                                + "sec.");
                            });*/
                }

                for (Attack attack : attackList) {
                    AttackField field = attack.getField();
                    TokenBucket attackedBucket = nameBuckets.get(field.getIdentifier());

                    attackedBucket.getEntries()
                            .stream()
                            .filter(x -> x.getValue().getTranspired() >= (interval * 1_000_000L))
                            .filter(x ->
                                    x.getValue().getEstimatedPacketsPerSecond()
                                            >= field.getPacketsPerSecondThreshold() ||
                                    x.getValue().getEstimatedBytesPerSecond()
                                            >= field.getBytesPerSecondThreshold()
                            )
                            .filter(x -> attack.getField().meetsConditions(x.getKey()))
                            .forEach(alerting -> {
                                logger.log(Level.SEVERE,
                                        attack.getName() +
                                                " (" + attackedBucket.getField().getProtocol().getIdentifier()
                                                + "." + attackedBucket.getField().getIdentifier() + "=" +
                                                alerting.getKey() + "): " +
                                                String.format("%.2f",
                                                        alerting.getValue().getEstimatedPacketsPerSecond()
                                                                / 1_000D)
                                                + "Kpps, " +
                                                String.format("%.3f",
                                                        (alerting.getValue().getEstimatedBytesPerSecond() * 8D)
                                                                / 1_000_000D)
                                                + "Mbps, " +
                                                String.format("%.2f",
                                                        ((double)alerting.getValue().getEstimatedBytes() /
                                                                (double)alerting.getValue().getEstimatedPackets()))
                                                + " bytes/pkt for " +
                                                String.format("%.3f",
                                                        alerting.getValue().getTranspired() / 1_000_000_000D)
                                                + "sec.");


                                for (Webhook webhook : webhooks) {
                                    final SlackAttachment attachment = new SlackAttachment(webhook.getTitle());

                                    attachment.timestamp((int) (System.currentTimeMillis() / 1000L));

                                    attachment.addField(new SlackAttachment.Field(
                                            "Attack type",
                                            attack.getName(),
                                            true
                                    ));

                                    attachment.addField(new SlackAttachment.Field(
                                            "Attack signature",
                                            attackedBucket.getField().getProtocol().getIdentifier()
                                                    + "." + attackedBucket.getField().getIdentifier() + "=" +
                                                    alerting.getKey(),
                                            true
                                    ));

                                    attachment.addField(new SlackAttachment.Field(
                                            "Attack volume",
                                            String.format("%.2f",
                                                    alerting.getValue().getEstimatedPacketsPerSecond()
                                                            / 1_000D)
                                                    + "Kpps, " +
                                                    String.format("%.3f",
                                                            (alerting.getValue().getEstimatedBytesPerSecond() * 8D)
                                                                    / 1_000_000D)
                                                    + "Mbps, " +
                                                    String.format("%.2f",
                                                            ((double)alerting.getValue().getEstimatedBytes() /
                                                                    (double)alerting.getValue().getEstimatedPackets()))
                                                    + " bytes/pkt for " +
                                                    String.format("%.3f",
                                                            alerting.getValue().getTranspired() / 1_000_000_000D)
                                                    + "sec.",
                                            true
                                    ));

                                    webhookDispatchService.submit(() -> {
                                        try {
                                            new Slack(webhook.getUrl())
                                                    .sendToUser("slackbot")
                                                    .displayName("dnart")
                                                    .push(attachment);
                                        } catch (Exception e) {
                                            Logger.getGlobal().log(Level.WARNING, "Problem sending Slack message", e);
                                        }
                                    });
                                }
                            });
                }

                try {
                    wakeTime += interval;
                    long sleep = wakeTime - System.currentTimeMillis();
                    if (sleep > 0)
                        Thread.sleep(sleep);
                    else {
                        logger.log(Level.WARNING, "Problem processing buckets; is the system falling behind?");
                        wakeTime = System.currentTimeMillis();
                    }
                } catch (InterruptedException e) {
                    break;
                }
            }
        } catch (Throwable e) {
            logger.log(Level.SEVERE, "Critical problem encountered in main thread, shutting down...", e);

            System.exit(1);
        }

        System.exit(0);
    }
}
