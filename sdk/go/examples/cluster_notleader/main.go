// Command cluster_notleader demonstrates handling the typed NotLeader (tag 42)
// produce redirect a CLUSTERED broker sends when the connected node is not the
// target partition's current leader: reconnect to the leader hint and retry.
//
// A single-node broker NEVER emits NotLeader (the redirect path is
// cluster-gated), so against a single node this program simply produces
// without redirecting — run it against a cluster node to see the redirect.
//
//	go run ./examples/cluster_notleader [-addr 127.0.0.1:7777]
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

// maxRedirects bounds the redirect-chase so a flapping cluster cannot loop the
// producer forever.
const maxRedirects = 3

// produceToLeader produces m, transparently following up to maxRedirects
// NotLeader redirects to the hinted leader. It returns the client that ended
// up holding the leader connection (which may be the one passed in).
func produceToLeader(ctx context.Context, client *ironbus.Client, m *ironbus.Message) (*ironbus.Client, uint64, error) {
	for redirect := 0; ; redirect++ {
		offset, err := client.Produce(ctx, m)
		var notLeader *ironbus.NotLeaderError
		if !errors.As(err, &notLeader) {
			return client, offset, err
		}
		// A redirect without a hint means the cluster is mid-failover: the
		// caller falls back to its own peer discovery.
		if notLeader.LeaderHint == "" || redirect >= maxRedirects {
			return client, 0, err
		}
		fmt.Printf("redirected to leader %s\n", notLeader.LeaderHint)
		_ = client.Close()
		client, err = ironbus.Connect(ctx, ironbus.Config{Addr: notLeader.LeaderHint})
		if err != nil {
			return client, 0, err
		}
	}
}

func main() {
	addr := flag.String("addr", ironbus.DefaultAddr, "broker (or cluster node) address")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := ironbus.Connect(ctx, ironbus.Config{Addr: *addr})
	if err != nil {
		log.Fatalf("connect: %v", err)
	}

	client, offset, err := produceToLeader(ctx, client, &ironbus.Message{
		Payload: []byte("hello from the go sdk"),
	})
	if err != nil {
		log.Fatalf("produce: %v", err)
	}
	defer client.Close()
	fmt.Printf("produced at offset %d\n", offset)
}
