// Command subjects_wildcard demonstrates subject routing: bind a WILDCARD
// pattern to a stream, publish by literal subjects the pattern covers, and
// subscribe by subject. Resolution is fail-closed single-home: an unbound
// subject is a typed reject, never a silent drop.
//
//	go run ./examples/subjects_wildcard [-addr 127.0.0.1:7777]
package main

import (
	"context"
	"errors"
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

	// Bind the wildcard pattern order.> to the "orders" stream: every subject
	// under order. routes there.
	if err := client.BindSubject(ctx, "orders", "order.>"); err != nil {
		log.Fatalf("bind: %v", err)
	}

	for _, subject := range []string{"order.us.created", "order.eu.shipped"} {
		ack, err := client.ProduceSubject(ctx, subject, &ironbus.Message{
			Payload: []byte("event on " + subject),
		})
		if err != nil {
			log.Fatalf("produce %s: %v", subject, err)
		}
		fmt.Printf("published %s at offset %d\n", subject, ack.Offset)
	}

	// An UNBOUND subject is rejected with a stable code (the explicit beat
	// over a silent drop).
	_, err = client.ProduceSubject(ctx, "invoice.us", &ironbus.Message{Payload: []byte("x")})
	var serverErr *ironbus.ServerError
	if errors.As(err, &serverErr) {
		fmt.Printf("unbound subject rejected as expected: %s\n", serverErr.Code)
	}

	// Subscribe by a literal subject the binding covers; deliveries come from
	// the bound stream's work-group.
	consumer, err := ironbus.Connect(ctx, ironbus.Config{Addr: *addr})
	if err != nil {
		log.Fatalf("connect consumer: %v", err)
	}
	defer consumer.Close()
	if err := consumer.SubscribeSubject(ctx, "order.us.created", "workers"); err != nil {
		log.Fatalf("subscribe subject: %v", err)
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
