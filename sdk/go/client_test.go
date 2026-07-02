package ironbus

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/ELares/IronBus/sdk/go/internal/wire"
)

// startStalledBroker accepts one connection, answers the Connect handshake
// with an empty Info, then swallows every later frame WITHOUT replying, so a
// caller's context deadline fires while a reply is pending.
func startStalledBroker(t *testing.T) string {
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
		_, _ = io.Copy(io.Discard, conn) // swallow requests, never reply
	}()
	return ln.Addr().String()
}

// discardFrame reads and drops one [len:u32 LE][tag+body] frame.
func discardFrame(conn net.Conn) error {
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return err
	}
	n := binary.LittleEndian.Uint32(lenBuf[:])
	_, err := io.CopyN(io.Discard, conn, int64(n))
	return err
}

// TestProduceTimeoutIsTerminal pins the FIFO-safety posture (the Rust
// reference client's): a context deadline that fires while a Produce reply is
// pending marks the client terminally broken. Retrying on the same connection
// would read the PREVIOUS request's reply (off-by-one forever), so every later
// call must fail fast with the sticky terminal error instead.
func TestProduceTimeoutIsTerminal(t *testing.T) {
	addr := startStalledBroker(t)
	c, err := Connect(context.Background(), Config{Addr: addr})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := c.Produce(ctx, &Message{Payload: []byte("stalls")}); err == nil {
		t.Fatal("produce against a stalled broker returned nil")
	} else if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("produce error = %v, want a deadline error", err)
	}

	// The client is now terminally broken: no request is ever re-sent onto
	// the mispaired FIFO, even with a fresh context.
	if _, err := c.Produce(context.Background(), &Message{Payload: []byte("after")}); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("produce after timeout = %v, want the sticky terminal deadline error", err)
	}
	if err := c.Ping(context.Background()); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ping after timeout = %v, want the sticky terminal deadline error", err)
	}
}

// TestProduceWithAckLevelRejectsUnknownLevel pins the typed reject: a level
// outside the frozen 0/1/2 spectrum never reaches the wire (and is never
// silently folded to another level).
func TestProduceWithAckLevelRejectsUnknownLevel(t *testing.T) {
	c := &Client{}
	_, err := c.ProduceWithAckLevel(context.Background(), &Message{Payload: []byte("x")}, 3)
	var bad *InvalidAckLevelError
	if !errors.As(err, &bad) || bad.Level != 3 {
		t.Fatalf("level-3 produce = %v, want *InvalidAckLevelError with level 3", err)
	}
}
