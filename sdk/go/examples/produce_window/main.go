// Command produce_window demonstrates PIPELINED windowed produce: a batch of
// durable records written in ONE coalesced write and covered by a SINGLE
// group-commit fsync — the single-connection durable-throughput lever the
// awaited Produce cannot reach. Every returned ack is fsync-durable.
//
// Start a broker first:
//
//	ironbus serve --data-dir /tmp/ironbus-demo --addr 127.0.0.1:7777
//
// Then: go run ./examples/produce_window [-addr 127.0.0.1:7777] [-window 1024] [-total 10000]
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	ironbus "github.com/ELares/IronBus/sdk/go"
)

func main() {
	addr := flag.String("addr", ironbus.DefaultAddr, "broker address")
	window := flag.Int("window", 1024, "records per pipelined window")
	total := flag.Int("total", 10000, "total records to produce")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := ironbus.Connect(ctx, ironbus.Config{Addr: *addr})
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer client.Close()

	start := time.Now()
	produced := 0
	for produced < *total {
		n := *window
		if remaining := *total - produced; remaining < n {
			n = remaining
		}
		batch := make([]*ironbus.Message, n)
		for i := range batch {
			batch[i] = &ironbus.Message{Payload: []byte(fmt.Sprintf("event-%d", produced+i))}
		}
		// One coalesced write of n frames; the broker group-commits the window
		// under a single fsync and replies n acks FIFO. Every returned ack means
		// the record is durable.
		acks, err := client.ProduceWindow(ctx, batch)
		if err != nil {
			log.Fatalf("produce window: %v", err)
		}
		produced += len(acks)
	}

	elapsed := time.Since(start)
	fmt.Printf("produced %d durable records in %s (%.0f msg/s) with window %d\n",
		produced, elapsed.Round(time.Millisecond), float64(produced)/elapsed.Seconds(), *window)
}
