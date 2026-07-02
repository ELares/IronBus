// Command consume_ack_group joins a competing work-group, fetches a batch, and
// acks (or nacks) each delivery, demonstrating the Tier-W at-least-once loop
// with lease-generation fencing.
//
// Produce something first (go run ./examples/produce), then:
//
//	go run ./examples/consume_ack_group [-addr 127.0.0.1:7777] [-group workers]
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
	group := flag.String("group", "workers", "competing work-group name")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client, err := ironbus.Connect(ctx, ironbus.Config{Addr: *addr})
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer client.Close()

	if err := client.Subscribe(ctx, *group); err != nil {
		log.Fatalf("subscribe: %v", err)
	}

	res, err := client.Fetch(ctx, ironbus.FetchOptions{
		MaxRecords: 64,
		Expires:    2 * time.Second,
	})
	if err != nil {
		log.Fatalf("fetch: %v", err)
	}
	fmt.Printf("fetched %d messages (%d dead letters, %d truncations, %d gaps)\n",
		len(res.Messages), len(res.DeadLetters), len(res.Truncations), len(res.Gaps))

	for _, m := range res.Messages {
		fmt.Printf("  offset %d key=%q payload=%q\n", m.Offset, m.Key, m.Payload)
		committed, err := client.Ack(ctx, m.Offset, m.Generation)
		if err != nil {
			log.Fatalf("ack %d: %v", m.Offset, err)
		}
		if !committed {
			// The lease generation was stale: the record was already
			// redelivered elsewhere. At-least-once means someone else owns it.
			fmt.Printf("  ack %d was fenced (redelivered elsewhere)\n", m.Offset)
		}
	}
	for _, dl := range res.DeadLetters {
		fmt.Printf("  dead-lettered offset %d (reason %d)\n", dl.Offset, dl.Reason)
	}
}
