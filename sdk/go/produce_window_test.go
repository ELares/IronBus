package ironbus

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ELares/IronBus/sdk/go/internal/wire"
)

// startWindowBroker accepts one connection, answers the Connect handshake with an
// empty Info, then reads `count` Pub frames and replies `count` PubAcks with
// offsets base, base+1, ... — the minimal broker a windowed produce needs. It
// reads the whole window BEFORE replying, mirroring the group-commit drain.
func startWindowBroker(t *testing.T, count int, base uint64) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if err := discardFrame(conn); err != nil { // the Connect request
			return
		}
		info, err := wire.AppendFrame(nil, wire.TagInfo, nil)
		if err != nil {
			return
		}
		if _, err := conn.Write(info); err != nil {
			return
		}
		for i := 0; i < count; i++ { // the N pub frames (one coalesced client write)
			if err := discardFrame(conn); err != nil {
				return
			}
		}
		for i := 0; i < count; i++ { // N acks, FIFO, ascending offsets
			frame, err := wire.AppendFrame(nil, wire.TagPubAck, wire.AppendPubAck(nil, base+uint64(i)))
			if err != nil {
				return
			}
			if _, err := conn.Write(frame); err != nil {
				return
			}
		}
		_, _ = io.Copy(io.Discard, conn)
	}()
	return ln.Addr().String()
}

// TestProduceWindowPipelinesAndPreservesFIFO pins the windowed produce: N messages
// are written before any ack is awaited, and the N replies come back FIFO so the
// Nth ack belongs to the Nth message.
func TestProduceWindowPipelinesAndPreservesFIFO(t *testing.T) {
	const n = 8
	addr := startWindowBroker(t, n, 100)
	c, err := Connect(context.Background(), Config{Addr: addr})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()

	msgs := make([]*Message, n)
	for i := range msgs {
		msgs[i] = &Message{Payload: []byte{byte(i)}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	acks, err := c.ProduceWindow(ctx, msgs)
	if err != nil {
		t.Fatalf("produce window: %v", err)
	}
	if len(acks) != n {
		t.Fatalf("got %d acks, want %d", len(acks), n)
	}
	for i, a := range acks {
		if a.Offset != 100+uint64(i) {
			t.Fatalf("ack %d offset = %d, want %d (FIFO order)", i, a.Offset, 100+uint64(i))
		}
	}
}

// TestProduceWindowEmptyIsNoOp pins that an empty window returns nil without
// touching the wire (so it is safe to call on a drained batch).
func TestProduceWindowEmptyIsNoOp(t *testing.T) {
	addr := startStalledBroker(t) // never replies; a wire touch would hang/deadline
	c, err := Connect(context.Background(), Config{Addr: addr})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()

	acks, err := c.ProduceWindow(context.Background(), nil)
	if acks != nil || err != nil {
		t.Fatalf("empty window = (%v, %v), want (nil, nil)", acks, err)
	}
}
