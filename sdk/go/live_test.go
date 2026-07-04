package ironbus

// Live integration tests against a real `ironbus serve` broker.
//
// Gated by the IRONBUS_LIVE environment variable (any non-empty value): CI
// runs the vector conformance tests only, because it has no release binary.
// Locally:
//
//	cargo build --release
//	cd sdk/go && IRONBUS_LIVE=1 go test ./...
//
// IRONBUS_BIN overrides the broker binary path (default:
// ../../target/release/ironbus relative to this directory).

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// startBroker launches a fresh single-node broker on a free port with a
// temporary data directory and waits until it accepts connections.
func startBroker(t *testing.T, extraArgs ...string) string {
	t.Helper()
	if os.Getenv("IRONBUS_LIVE") == "" {
		t.Skip("live broker tests are gated by IRONBUS_LIVE=1 (needs target/release/ironbus)")
	}
	bin := os.Getenv("IRONBUS_BIN")
	if bin == "" {
		bin = filepath.Join("..", "..", "target", "release", "ironbus")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("broker binary not found at %s (set IRONBUS_BIN or run `cargo build --release`)", bin)
	}

	// Reserve a free port, then release it for the broker.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	args := append([]string{"serve", "--data-dir", t.TempDir(), "--addr", addr}, extraArgs...)
	cmd := exec.Command(bin, args...)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start broker: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return addr
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("broker at %s did not accept connections", addr)
	return ""
}

func liveConnect(t *testing.T, ctx context.Context, addr string) *Client {
	t.Helper()
	c, err := Connect(ctx, Config{Addr: addr})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// fetchAll fetches until n messages arrive (or the deadline), tolerating empty
// windows while deliveries become visible.
func fetchAll(t *testing.T, ctx context.Context, c *Client, n int) []Delivery {
	t.Helper()
	var got []Delivery
	deadline := time.Now().Add(10 * time.Second)
	for len(got) < n && time.Now().Before(deadline) {
		res, err := c.Fetch(ctx, FetchOptions{MaxRecords: 64, NoWait: true})
		if err != nil {
			t.Fatalf("fetch: %v", err)
		}
		got = append(got, res.Messages...)
		if len(res.Messages) == 0 {
			time.Sleep(25 * time.Millisecond)
		}
	}
	if len(got) < n {
		t.Fatalf("fetched %d of %d messages", len(got), n)
	}
	return got
}

// TestLiveProduceConsumeAckLevels exercises the produce/consume/ack loop
// across ack levels 0/1/2 plus the dedup duplicate path.
// TestLiveProduceWindow drives the pipelined windowed produce against a real
// broker: a window of durable records returns FIFO acks with contiguous offsets,
// and every acked record is readable back in order.
func TestLiveProduceWindow(t *testing.T) {
	addr := startBroker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	producer := liveConnect(t, ctx, addr)
	const n = 16
	msgs := make([]*Message, n)
	for i := range msgs {
		msgs[i] = &Message{Payload: []byte(fmt.Sprintf("win-%d", i))}
	}
	acks, err := producer.ProduceWindow(ctx, msgs)
	if err != nil {
		t.Fatalf("produce window: %v", err)
	}
	if len(acks) != n {
		t.Fatalf("got %d acks, want %d", len(acks), n)
	}
	for i := 1; i < n; i++ {
		if acks[i].Offset != acks[i-1].Offset+1 {
			t.Fatalf("ack %d offset = %d, want %d (contiguous FIFO)", i, acks[i].Offset, acks[i-1].Offset+1)
		}
	}

	// Read the window back and confirm each payload landed durably, in order.
	consumer := liveConnect(t, ctx, addr)
	if err := consumer.Subscribe(ctx, "win-verify"); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	got := 0
	for got < n {
		res, err := consumer.Fetch(ctx, FetchOptions{MaxRecords: n, Expires: 2 * time.Second})
		if err != nil {
			t.Fatalf("fetch: %v", err)
		}
		if len(res.Messages) == 0 {
			t.Fatalf("drained early: got %d of %d", got, n)
		}
		for _, m := range res.Messages {
			want := fmt.Sprintf("win-%d", got)
			if string(m.Payload) != want {
				t.Fatalf("record %d payload = %q, want %q", got, m.Payload, want)
			}
			if _, err := consumer.Ack(ctx, m.Offset, m.Generation); err != nil {
				t.Fatalf("ack: %v", err)
			}
			got++
		}
	}
}

func TestLiveProduceConsumeAckLevels(t *testing.T) {
	addr := startBroker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	producer := liveConnect(t, ctx, addr)
	if err := producer.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}

	// Level 1 (default server ack).
	off0, err := producer.Produce(ctx, &Message{Key: []byte("k0"), Payload: []byte("level-1")})
	if err != nil {
		t.Fatalf("produce level 1: %v", err)
	}
	if off0 != 0 {
		t.Fatalf("first offset = %d, want 0", off0)
	}

	// Level 2 (server+client ack bits on the wire; returns at the durability ack).
	off1, err := producer.ProduceWithAckLevel(ctx, &Message{Payload: []byte("level-2")}, AckLevelServerAndClient)
	if err != nil {
		t.Fatalf("produce level 2: %v", err)
	}
	if off1 != off0+1 {
		t.Fatalf("level-2 offset = %d, want %d", off1, off0+1)
	}

	// Level 0 (fire-and-forget: no reply). A follow-up awaited produce
	// serializes it so we can assert it landed.
	if err := producer.ProduceFireAndForget(ctx, &Message{Payload: []byte("level-0")}); err != nil {
		t.Fatalf("produce level 0: %v", err)
	}
	off3, err := producer.Produce(ctx, &Message{Payload: []byte("after-faf")})
	if err != nil {
		t.Fatalf("produce after faf: %v", err)
	}
	if off3 != off1+2 {
		t.Fatalf("post-faf offset = %d, want %d (the faf record must hold %d)", off3, off1+2, off1+1)
	}

	// Dedup: a retried MsgID is a benign duplicate carrying the ORIGINAL offset.
	dedup := Dedup{ProducerID: []byte("go-producer"), Epoch: 1, MsgID: []byte("msg-dup-1")}
	first, err := producer.ProduceDedup(ctx, &Message{Payload: []byte("dedup-payload")}, dedup)
	if err != nil {
		t.Fatalf("produce dedup: %v", err)
	}
	if first.Duplicate {
		t.Fatal("first dedup produce reported duplicate")
	}
	second, err := producer.ProduceDedup(ctx, &Message{Payload: []byte("dedup-payload")}, dedup)
	if err != nil {
		t.Fatalf("produce dedup retry: %v", err)
	}
	if !second.Duplicate || second.Offset != first.Offset {
		t.Fatalf("dedup retry = %+v, want duplicate at offset %d", second, first.Offset)
	}

	// Consume and ack everything on a competing work-group.
	consumer := liveConnect(t, ctx, addr)
	if err := consumer.Subscribe(ctx, "workers"); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	msgs := fetchAll(t, ctx, consumer, 5)
	wantPayloads := [][]byte{
		[]byte("level-1"), []byte("level-2"), []byte("level-0"),
		[]byte("after-faf"), []byte("dedup-payload"),
	}
	for i, m := range msgs {
		if !bytes.Equal(m.Payload, wantPayloads[i]) {
			t.Fatalf("message %d payload = %q, want %q", i, m.Payload, wantPayloads[i])
		}
		committed, err := consumer.Ack(ctx, m.Offset, m.Generation)
		if err != nil {
			t.Fatalf("ack %d: %v", m.Offset, err)
		}
		if !committed {
			t.Fatalf("ack %d was fenced", m.Offset)
		}
	}
	if !bytes.Equal(msgs[0].Key, []byte("k0")) {
		t.Fatalf("message 0 key = %q, want k0", msgs[0].Key)
	}

	// The producer connection survives the whole exchange (any level-2
	// ProduceConfirm push is drained transparently).
	if err := producer.Ping(ctx); err != nil {
		t.Fatalf("final ping: %v", err)
	}
}

// TestLiveProduceConfirmDrainedInFetchWindow reproduces the level-2 confirm
// brick (review finding on #1021): on ONE connection, produce at level 2,
// subscribe, fetch, and ack — the ack completes the level-2 produce, so the
// broker emits the out-of-band ProduceConfirm right behind the AckStatus —
// then Fetch AGAIN. The second fetch must drain the buffered confirm
// transparently; before the fix it failed with an unexpected-frame error and
// terminally bricked the client.
//
// The subscription MUST be the DEFAULT (empty-named) group: it is the broker's
// DESIGNATED level-2 confirm group, and an ack in any other group never fires
// the confirm at all (which would make this test pass vacuously). On the
// default group the broker flushes the tag-22 confirm in the SAME pass as the
// AckStatus, deterministically leaving it buffered in front of fetch 2's
// reply — verified frame-by-frame against the broker during review.
func TestLiveProduceConfirmDrainedInFetchWindow(t *testing.T) {
	addr := startBroker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	c := liveConnect(t, ctx, addr)
	if _, err := c.ProduceWithAckLevel(ctx, &Message{Payload: []byte("l2")}, AckLevelServerAndClient); err != nil {
		t.Fatalf("produce level 2: %v", err)
	}
	if err := c.Subscribe(ctx, ""); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	msgs := fetchAll(t, ctx, c, 1)
	if committed, err := c.Ack(ctx, msgs[0].Offset, msgs[0].Generation); err != nil || !committed {
		t.Fatalf("ack = (%v, %v), want committed", committed, err)
	}
	// The ProduceConfirm is now queued behind the consumed AckStatus. The
	// next fetch window must drain it instead of failing the connection.
	if _, err := c.Fetch(ctx, FetchOptions{MaxRecords: 8, NoWait: true}); err != nil {
		t.Fatalf("fetch after level-2 confirm: %v", err)
	}
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("ping after confirm drain: %v", err)
	}
}

// TestLiveNackTermProgress exercises the remaining settle ops and the fencing
// result shape.
func TestLiveNackTermProgress(t *testing.T) {
	addr := startBroker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	producer := liveConnect(t, ctx, addr)
	for i := 0; i < 3; i++ {
		if _, err := producer.Produce(ctx, &Message{Payload: []byte(fmt.Sprintf("m%d", i))}); err != nil {
			t.Fatalf("produce %d: %v", i, err)
		}
	}

	consumer := liveConnect(t, ctx, addr)
	if err := consumer.Subscribe(ctx, "workers"); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	msgs := fetchAll(t, ctx, consumer, 3)

	// Progress extends the first lease.
	if status, err := consumer.Progress(ctx, msgs[0].Offset, msgs[0].Generation); err != nil {
		t.Fatalf("progress: %v", err)
	} else if status != 1 {
		t.Fatalf("progress status = %d, want 1 (extended)", status)
	}
	// Nack the first for immediate redelivery, term the second, ack the third.
	if ok, err := consumer.Nack(ctx, msgs[0].Offset, msgs[0].Generation, 0); err != nil || !ok {
		t.Fatalf("nack = (%v, %v), want accepted", ok, err)
	}
	if ok, err := consumer.Term(ctx, msgs[1].Offset, msgs[1].Generation); err != nil || !ok {
		t.Fatalf("term = (%v, %v), want accepted", ok, err)
	}
	if ok, err := consumer.Ack(ctx, msgs[2].Offset, msgs[2].Generation); err != nil || !ok {
		t.Fatalf("ack = (%v, %v), want committed", ok, err)
	}

	// The nacked message redelivers with a HIGHER generation; the stale
	// generation is then fenced.
	redelivered := fetchAll(t, ctx, consumer, 1)
	if redelivered[0].Offset != msgs[0].Offset {
		t.Fatalf("redelivered offset = %d, want %d", redelivered[0].Offset, msgs[0].Offset)
	}
	if committed, err := consumer.Ack(ctx, msgs[0].Offset, msgs[0].Generation); err != nil {
		t.Fatalf("stale ack: %v", err)
	} else if committed {
		t.Fatal("stale-generation ack was not fenced")
	}
	if committed, err := consumer.Ack(ctx, redelivered[0].Offset, redelivered[0].Generation); err != nil || !committed {
		t.Fatalf("fresh ack = (%v, %v), want committed", committed, err)
	}
}

// TestLiveDeadLetterAdvisory drives a poison message past max-deliver and
// asserts the in-band DeadLetter advisory decodes.
func TestLiveDeadLetterAdvisory(t *testing.T) {
	addr := startBroker(t, "--max-deliver", "2", "--backoff-ms", "0")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	producer := liveConnect(t, ctx, addr)
	if _, err := producer.Produce(ctx, &Message{Payload: []byte("poison")}); err != nil {
		t.Fatalf("produce: %v", err)
	}

	consumer := liveConnect(t, ctx, addr)
	if err := consumer.Subscribe(ctx, "workers"); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	// Exhaust max-deliver with immediate-redelivery nacks.
	for attempt := 0; attempt < 2; attempt++ {
		msgs := fetchAll(t, ctx, consumer, 1)
		if ok, err := consumer.Nack(ctx, msgs[0].Offset, msgs[0].Generation, 0); err != nil || !ok {
			t.Fatalf("nack attempt %d = (%v, %v)", attempt, ok, err)
		}
	}
	// The next window reports the dead-letter advisory instead of a delivery.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		res, err := consumer.Fetch(ctx, FetchOptions{MaxRecords: 16, NoWait: true})
		if err != nil {
			t.Fatalf("fetch: %v", err)
		}
		if len(res.Messages) != 0 {
			t.Fatalf("poison message redelivered past max-deliver: %+v", res.Messages)
		}
		if len(res.DeadLetters) > 0 {
			if res.DeadLetters[0].Offset != 0 || res.DeadLetters[0].Reason != 0 {
				t.Fatalf("dead letter = %+v, want offset 0 reason 0", res.DeadLetters[0])
			}
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("no dead-letter advisory arrived")
}

// TestLiveStreams exercises declare / query / produce-to / subscribe-to on a
// named stream, including a dedup duplicate on the stream-addressed path.
func TestLiveStreams(t *testing.T) {
	addr := startBroker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	c := liveConnect(t, ctx, addr)
	if !c.Info().Streams {
		t.Fatal("server did not confirm the streams capability")
	}
	if err := c.DeclareStream(ctx, "orders"); err != nil {
		t.Fatalf("declare: %v", err)
	}
	// Idempotent re-declare.
	if err := c.DeclareStream(ctx, "orders"); err != nil {
		t.Fatalf("re-declare: %v", err)
	}
	info, err := c.QueryStream(ctx, "orders")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if !info.Exists || info.Head != 0 {
		t.Fatalf("fresh stream info = %+v, want exists with head 0", info)
	}
	if info, err := c.QueryStream(ctx, "never-declared"); err != nil || info.Exists {
		t.Fatalf("absent stream info = (%+v, %v), want !exists", info, err)
	}

	ack, err := c.ProduceTo(ctx, "orders", &Message{Key: []byte("o1"), Payload: []byte("order-1")})
	if err != nil {
		t.Fatalf("produce to: %v", err)
	}
	if ack.Offset != 0 || ack.Duplicate {
		t.Fatalf("stream produce ack = %+v, want fresh offset 0", ack)
	}
	if _, err := c.ProduceTo(ctx, "orders", &Message{Payload: []byte("order-2")}); err != nil {
		t.Fatalf("produce to second: %v", err)
	}

	info, err = c.QueryStream(ctx, "orders")
	if err != nil {
		t.Fatalf("query after produce: %v", err)
	}
	if info.Head != 2 {
		t.Fatalf("stream head = %d, want 2", info.Head)
	}

	// The named stream's work-group is independent of the default stream's.
	consumer := liveConnect(t, ctx, addr)
	if err := consumer.SubscribeTo(ctx, "orders", "pickers"); err != nil {
		t.Fatalf("subscribe to: %v", err)
	}
	msgs := fetchAll(t, ctx, consumer, 2)
	if !bytes.Equal(msgs[0].Payload, []byte("order-1")) || !bytes.Equal(msgs[1].Payload, []byte("order-2")) {
		t.Fatalf("stream deliveries = %q, %q", msgs[0].Payload, msgs[1].Payload)
	}
	for _, m := range msgs {
		if ok, err := consumer.Ack(ctx, m.Offset, m.Generation); err != nil || !ok {
			t.Fatalf("stream ack %d = (%v, %v)", m.Offset, ok, err)
		}
	}

	// Subscribing to an unknown stream is a typed server error.
	other := liveConnect(t, ctx, addr)
	err = other.SubscribeTo(ctx, "never-declared", "g")
	var serverErr *ServerError
	if !errors.As(err, &serverErr) {
		t.Fatalf("subscribe to unknown stream = %v, want *ServerError", err)
	}
}

// TestLiveSubjectsWildcard exercises the subject verbs: a wildcard BINDING,
// publishes by literal subject, subscribes by two literal subjects the binding
// covers, and the typed rejects for unbound publishes and wildcard subscribes.
func TestLiveSubjectsWildcard(t *testing.T) {
	addr := startBroker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	c := liveConnect(t, ctx, addr)
	if err := c.BindSubject(ctx, "orders", "order.>"); err != nil {
		t.Fatalf("bind: %v", err)
	}

	// An unbound subject is a fail-closed typed reject, never a silent drop.
	_, err := c.ProduceSubject(ctx, "invoices.us", &Message{Payload: []byte("x")})
	var serverErr *ServerError
	if !errors.As(err, &serverErr) || serverErr.Code != ErrCodeNoStreamForSubject {
		t.Fatalf("unbound publish = %v, want %s", err, ErrCodeNoStreamForSubject)
	}

	ack, err := c.ProduceSubject(ctx, "order.us.created", &Message{Payload: []byte("subject-hello")})
	if err != nil {
		t.Fatalf("produce subject: %v", err)
	}
	if ack.Offset != 0 {
		t.Fatalf("subject produce offset = %d, want 0", ack.Offset)
	}
	// The record landed in the BOUND stream, not the default stream.
	info, err := c.QueryStream(ctx, "orders")
	if err != nil || !info.Exists || info.Head != 1 {
		t.Fatalf("bound stream info = (%+v, %v), want head 1", info, err)
	}

	// Subscribe by the literal subject.
	literal := liveConnect(t, ctx, addr)
	if err := literal.SubscribeSubject(ctx, "order.us.created", "workers"); err != nil {
		t.Fatalf("subscribe literal subject: %v", err)
	}
	msgs := fetchAll(t, ctx, literal, 1)
	if !bytes.Equal(msgs[0].Payload, []byte("subject-hello")) {
		t.Fatalf("literal-subject delivery = %q", msgs[0].Payload)
	}
	if ok, err := literal.Ack(ctx, msgs[0].Offset, msgs[0].Generation); err != nil || !ok {
		t.Fatalf("literal-subject ack = (%v, %v)", ok, err)
	}

	// A DIFFERENT literal subject covered by the same wildcard binding
	// resolves to the same stream; a fresh group sees the record again.
	sibling := liveConnect(t, ctx, addr)
	if err := sibling.SubscribeSubject(ctx, "order.eu.shipped", "auditors"); err != nil {
		t.Fatalf("subscribe sibling subject: %v", err)
	}
	msgs = fetchAll(t, ctx, sibling, 1)
	if !bytes.Equal(msgs[0].Payload, []byte("subject-hello")) {
		t.Fatalf("sibling-subject delivery = %q", msgs[0].Payload)
	}

	// A wildcard SUBJECT subscribe is a fail-closed typed reject (wildcards
	// belong in the BIND pattern), decoded through the coded Err path.
	wildcard := liveConnect(t, ctx, addr)
	err = wildcard.SubscribeSubject(ctx, "order.>", "watchers")
	if !errors.As(err, &serverErr) || serverErr.Code != ErrCodeInvalidSubject {
		t.Fatalf("wildcard subscribe = %v, want %s", err, ErrCodeInvalidSubject)
	}
}
