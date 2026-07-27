// SPDX-License-Identifier: MIT OR Apache-2.0
//
// StormProducers — the Redpanda-side twin of `storm-produce` (#1192 S1, epic #1196; gates #1193):
// N concurrent producers, EACH publishing to its OWN topic, every send an awaited durable ack
// (`producer.send(record).get()`, acks=all, max.in.flight=1, linger.ms=0 — the per-message storm
// shape). One JVM, N threads, N KafkaProducer instances of the OFFICIAL kafka-clients (from the
// provisioned Kafka perf-tools distro), so the client stack is Redpanda's standard one while the
// measurement method (whole-phase wall aggregate, per-thread nearest-rank ack percentiles from raw
// nanosecond samples) is IDENTICAL to the IronBus driver — a same-instrument harness, unlike the
// whole-ms-resolution kafka-producer-perf-test summary (methodology guardrail 4 of the epic).
//
// The harness (storm2.sh) creates the N topics (1 partition, replication 1, write.caching=false —
// fsync before ack, matched to IronBus sync durability) BEFORE this driver runs; the driver only
// produces. Emits ONE JSON object on stdout, schema `storm-produce-v1` — the same field names as
// the Rust driver so the scenario script parses one way.
//
//   javac -cp "$KAFKA_HOME/libs/*" StormProducers.java
//   java  -cp "$KAFKA_HOME/libs/*:." StormProducers <bootstrap> <producers> <count> <bytes> <prefix>

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.CyclicBarrier;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;

public final class StormProducers {

    /** One producer thread's raw result: its wall window offsets and its sorted ack RTTs (ns). */
    private static final class ProducerResult {
        long startNs;
        long endNs;
        long[] sortedRttsNs;
        String error; // non-null = the thread failed
    }

    /**
     * The same compressible record-like ASCII pattern `ironbus bench --payload-shape realistic`
     * fills (replicated in the Rust driver too), so both brokers carry identical bytes.
     */
    private static byte[] realisticPayload(int size) {
        final byte[] pattern =
                "ts=000000 sensor=edge temp=21.5 occ=1 batt=98 rssi=-67; ".getBytes();
        byte[] payload = new byte[size];
        for (int i = 0; i < size; i++) {
            payload[i] = pattern[i % pattern.length];
        }
        return payload;
    }

    /** Nearest-rank quantile over an ascending-sorted array — identical to the Rust driver's. */
    private static long nearestRank(long[] sorted, double p) {
        if (sorted.length == 0) {
            return 0;
        }
        int idx = (int) Math.ceil(p * sorted.length) - 1;
        if (idx < 0) {
            idx = 0;
        }
        if (idx >= sorted.length) {
            idx = sorted.length - 1;
        }
        return sorted[idx];
    }

    private static double nsToUs(long ns) {
        return Math.round(ns / 10.0) / 100.0;
    }

    private static double medianOf(double[] values) {
        if (values.length == 0) {
            return 0.0;
        }
        double[] v = values.clone();
        Arrays.sort(v);
        int mid = v.length / 2;
        return (v.length % 2 == 1) ? v[mid] : (v[mid - 1] + v[mid]) / 2.0;
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 5) {
            System.err.println(
                    "usage: StormProducers <bootstrap> <producers> <countPerProducer> <payloadBytes> <topicPrefix>");
            System.exit(2);
        }
        final String bootstrap = args[0];
        final int producers = Integer.parseInt(args[1]);
        final long count = Long.parseLong(args[2]);
        final int payloadBytes = Integer.parseInt(args[3]);
        final String prefix = args[4];

        final byte[] payload = realisticPayload(payloadBytes);
        final CyclicBarrier barrier = new CyclicBarrier(producers);
        final long epochNs = System.nanoTime();
        final ProducerResult[] results = new ProducerResult[producers];
        List<Thread> threads = new ArrayList<>(producers);

        for (int t = 0; t < producers; t++) {
            final int idx = t;
            results[idx] = new ProducerResult();
            Thread th = new Thread(() -> {
                ProducerResult r = results[idx];
                // The storm shape: durable ack per message, single in-flight, no batching window.
                // acks=all on a 1-replica write.caching=false topic = fsync before ack.
                Properties props = new Properties();
                props.put("bootstrap.servers", bootstrap);
                props.put("acks", "all");
                props.put("linger.ms", "0");
                props.put("max.in.flight.requests.per.connection", "1");
                props.put("compression.type", "none");
                // Plain at-least-once, matching IronBus's at-least-once ack semantics. Also load-
                // bearing: with the 4.3.1 client's idempotence-on default, a herd of N concurrent
                // InitProducerId handshakes against this broker races into a client-side
                // FindCoordinator NPE (null key) that kills producer I/O threads. Disabling the
                // idempotence layer (sequence numbers) is the charitable-config direction anyway.
                props.put("enable.idempotence", "false");
                // Bound the per-producer send buffer pool: the default 32 MiB x 128 producers
                // would dwarf the guest; a sync send loop needs one small batch at a time.
                props.put("buffer.memory", "1048576");
                props.put("key.serializer",
                        "org.apache.kafka.common.serialization.ByteArraySerializer");
                props.put("value.serializer",
                        "org.apache.kafka.common.serialization.ByteArraySerializer");
                String topic = prefix + idx;
                long[] rtts = new long[(int) count];
                try (KafkaProducer<byte[], byte[]> producer = new KafkaProducer<>(props)) {
                    barrier.await();
                    r.startNs = System.nanoTime() - epochNs;
                    for (int i = 0; i < count; i++) {
                        long t0 = System.nanoTime();
                        producer.send(new ProducerRecord<>(topic, null, payload)).get();
                        rtts[i] = System.nanoTime() - t0;
                    }
                    r.endNs = System.nanoTime() - epochNs;
                    Arrays.sort(rtts);
                    r.sortedRttsNs = rtts;
                } catch (Exception e) {
                    r.error = "producer " + idx + ": " + e;
                }
            }, "storm-producer-" + idx);
            threads.add(th);
            th.start();
        }
        for (Thread th : threads) {
            th.join();
        }
        for (ProducerResult r : results) {
            if (r.error != null) {
                System.err.println("StormProducers: " + r.error);
                System.exit(1);
            }
        }

        // Whole-phase wall: first thread's post-barrier start to the last thread's end.
        long wallStart = Long.MAX_VALUE;
        long wallEnd = 0;
        long totalSamples = 0;
        for (ProducerResult r : results) {
            wallStart = Math.min(wallStart, r.startNs);
            wallEnd = Math.max(wallEnd, r.endNs);
            totalSamples += r.sortedRttsNs.length;
        }
        long wallNs = Math.max(1, wallEnd - wallStart);
        long totalMsgs = count * producers;
        double msgsPerSec = totalMsgs / (wallNs / 1e9);

        long[] pooled = new long[(int) totalSamples];
        int off = 0;
        double[] perP50 = new double[producers];
        double[] perP99 = new double[producers];
        StringBuilder perProducer = new StringBuilder("[");
        for (int i = 0; i < producers; i++) {
            ProducerResult r = results[i];
            System.arraycopy(r.sortedRttsNs, 0, pooled, off, r.sortedRttsNs.length);
            off += r.sortedRttsNs.length;
            perP50[i] = nsToUs(nearestRank(r.sortedRttsNs, 0.50));
            perP99[i] = nsToUs(nearestRank(r.sortedRttsNs, 0.99));
            if (i > 0) {
                perProducer.append(",");
            }
            perProducer.append(String.format(
                    "{\"stream\":\"%s%d\",\"msgs\":%d,\"p50_us\":%s,\"p99_us\":%s}",
                    prefix, i, r.sortedRttsNs.length, perP50[i], perP99[i]));
        }
        perProducer.append("]");
        Arrays.sort(pooled);

        System.out.println(String.format(
                "{\"schema\":\"storm-produce-v1\",\"producers\":%d,\"streams\":%d,"
                        + "\"count_per_producer\":%d,\"total_messages\":%d,\"payload_bytes\":%d,"
                        + "\"wall_s\":%s,\"msgs_per_sec\":%s,"
                        + "\"ack_p50_us_pooled\":%s,\"ack_p99_us_pooled\":%s,\"ack_p999_us_pooled\":%s,"
                        + "\"per_producer_p50_us_median\":%s,\"per_producer_p99_us_median\":%s,"
                        + "\"per_producer\":%s}",
                producers, producers, count, totalMsgs, payloadBytes,
                Math.round(wallNs / 1e9 * 1000.0) / 1000.0,
                Math.round(msgsPerSec * 10.0) / 10.0,
                nsToUs(nearestRank(pooled, 0.50)),
                nsToUs(nearestRank(pooled, 0.99)),
                nsToUs(nearestRank(pooled, 0.999)),
                medianOf(perP50), medianOf(perP99),
                perProducer));
    }

    private StormProducers() {}
}
