// Command produce publishes a few messages to a running broker, demonstrating
// the awaited produce, fire-and-forget, and opt-in dedup (a retried MsgID is a
// benign duplicate returning the original offset).
//
// Start a broker first:
//
//	ironbus serve --data-dir /tmp/ironbus-demo --addr 127.0.0.1:7777
//
// Then: go run ./examples/produce [-addr 127.0.0.1:7777]
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
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := ironbus.Connect(ctx, ironbus.Config{Addr: *addr})
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer client.Close()

	// An awaited produce: returns once the record is durable (ack level 1).
	for i := 0; i < 3; i++ {
		offset, err := client.Produce(ctx, &ironbus.Message{
			Key:     []byte(fmt.Sprintf("user-%d", i)),
			Payload: []byte(fmt.Sprintf("hello ironbus %d", i)),
		})
		if err != nil {
			log.Fatalf("produce: %v", err)
		}
		fmt.Printf("produced at offset %d\n", offset)
	}

	// Fire-and-forget (ack level 0): no reply, loss accepted by contract.
	if err := client.ProduceFireAndForget(ctx, &ironbus.Message{Payload: []byte("qos0")}); err != nil {
		log.Fatalf("fire-and-forget: %v", err)
	}
	fmt.Println("fired and forgot one message")

	// Opt-in dedup: the retry is a benign duplicate at the ORIGINAL offset.
	dedup := ironbus.Dedup{ProducerID: []byte("example-producer"), Epoch: 1, MsgID: []byte("order-42")}
	first, err := client.ProduceDedup(ctx, &ironbus.Message{Payload: []byte("exactly once-ish")}, dedup)
	if err != nil {
		log.Fatalf("produce dedup: %v", err)
	}
	retry, err := client.ProduceDedup(ctx, &ironbus.Message{Payload: []byte("exactly once-ish")}, dedup)
	if err != nil {
		log.Fatalf("produce dedup retry: %v", err)
	}
	fmt.Printf("dedup: first %+v, retry %+v\n", first, retry)
}
