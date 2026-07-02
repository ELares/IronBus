// Command streams demonstrates NAMED streams: declare, query, produce-to, and
// consume from the stream's own work-group (independent of the default
// stream's groups).
//
//	go run ./examples/streams [-addr 127.0.0.1:7777]
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

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client, err := ironbus.Connect(ctx, ironbus.Config{Addr: *addr})
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer client.Close()
	if !client.Info().Streams {
		log.Fatal("this broker did not confirm the streams capability")
	}

	// Declare is idempotent: create-or-ensure.
	if err := client.DeclareStream(ctx, "orders"); err != nil {
		log.Fatalf("declare: %v", err)
	}
	info, err := client.QueryStream(ctx, "orders")
	if err != nil {
		log.Fatalf("query: %v", err)
	}
	fmt.Printf("stream orders: exists=%v head=%d\n", info.Exists, info.Head)

	for i := 0; i < 3; i++ {
		ack, err := client.ProduceTo(ctx, "orders", &ironbus.Message{
			Payload: []byte(fmt.Sprintf("order-%d", i)),
		})
		if err != nil {
			log.Fatalf("produce to: %v", err)
		}
		fmt.Printf("produced order-%d at stream offset %d\n", i, ack.Offset)
	}

	// A separate consumer connection bound to the stream's own work-group.
	consumer, err := ironbus.Connect(ctx, ironbus.Config{Addr: *addr})
	if err != nil {
		log.Fatalf("connect consumer: %v", err)
	}
	defer consumer.Close()
	if err := consumer.SubscribeTo(ctx, "orders", "pickers"); err != nil {
		log.Fatalf("subscribe to: %v", err)
	}
	res, err := consumer.Fetch(ctx, ironbus.FetchOptions{MaxRecords: 16})
	if err != nil {
		log.Fatalf("fetch: %v", err)
	}
	for _, m := range res.Messages {
		fmt.Printf("consumed %q at offset %d\n", m.Payload, m.Offset)
		if _, err := consumer.Ack(ctx, m.Offset, m.Generation); err != nil {
			log.Fatalf("ack: %v", err)
		}
	}
}
