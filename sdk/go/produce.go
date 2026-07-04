package ironbus

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ELares/IronBus/sdk/go/internal/wire"
)

// Produce ack levels (the Cassandra-style produce ack spectrum, #494/#499).
const (
	// AckLevelNone (level 0): fire-and-forget. The producer never waits and
	// accepts loss by contract.
	AckLevelNone uint8 = 0
	// AckLevelServer (level 1): a PubAck once the record is durably accepted.
	// The default.
	AckLevelServer uint8 = 1
	// AckLevelServerAndClient (level 2): the level is recorded on the wire so
	// the broker completes the produce only once a consumer acked it. The MVP
	// returns at the durability ack and does not await the out-of-band
	// ProduceConfirm.
	AckLevelServerAndClient uint8 = 2
)

// Message is a message to produce.
type Message struct {
	// Key is the optional routing/ordering key.
	Key []byte
	// Headers is the optional opaque headers blob.
	Headers []byte
	// Payload is the message payload.
	Payload []byte
	// TimestampMS is the producer timestamp (milliseconds since the Unix
	// epoch). Zero means "now".
	TimestampMS uint64
}

// Dedup is the opt-in effectively-once produce metadata (#33): the broker
// deduplicates on MsgID within the producer's window; Epoch fences a zombie
// session; Seq (optional) is the Kafka-style idempotent-producer sequence.
type Dedup struct {
	ProducerID []byte
	Epoch      uint64
	MsgID      []byte
	Seq        *uint64
}

// ProduceAck is a produce acknowledgement: the assigned durable offset, and
// whether it was a benign dedup hit (the broker appended no second copy and
// returned the ORIGINAL offset).
type ProduceAck struct {
	Offset    uint64
	Duplicate bool
}

func (m *Message) timestamp() uint64 {
	if m.TimestampMS != 0 {
		return m.TimestampMS
	}
	return uint64(time.Now().UnixMilli())
}

// Produce publishes a message at-least-once (ack level 1) and returns the
// assigned durable offset.
func (c *Client) Produce(ctx context.Context, m *Message) (uint64, error) {
	ack, err := c.produceBody(ctx, wire.TagPub, nil, m, nil, AckLevelServer)
	if err != nil {
		return 0, err
	}
	return ack.Offset, nil
}

// ProduceWithAckLevel publishes a message at the given ack level. Level 0 is
// fire-and-forget: no reply is read and the returned offset is zero. Levels 1
// and 2 return at the durability ack. A level above 2 is rejected with a
// *InvalidAckLevelError (never silently folded to another level).
func (c *Client) ProduceWithAckLevel(ctx context.Context, m *Message, level uint8) (uint64, error) {
	if level > AckLevelServerAndClient {
		return 0, &InvalidAckLevelError{Level: level}
	}
	if level == AckLevelNone {
		return 0, c.ProduceFireAndForget(ctx, m)
	}
	ack, err := c.produceBody(ctx, wire.TagPub, nil, m, nil, level)
	if err != nil {
		return 0, err
	}
	return ack.Offset, nil
}

// ProduceDedup publishes with the opt-in dedup block. A retried publish whose
// MsgID was already seen returns the ORIGINAL offset with Duplicate = true; it
// is never an error.
func (c *Client) ProduceDedup(ctx context.Context, m *Message, d Dedup) (ProduceAck, error) {
	return c.produceBody(ctx, wire.TagPub, nil, m, &d, AckLevelServer)
}

// ProduceWindow publishes a WINDOW of messages PIPELINED (#450): every Pub frame
// is written before any ack is awaited, so the broker's group commit covers the
// whole window with ONE fdatasync instead of one per message. It is the
// single-connection durable-throughput lever the awaited Produce cannot reach
// (Produce keeps one record in flight at a time). Size the window for your
// workload: a larger window amortizes more, at the cost of more un-acked records
// in flight (re-delivered, never lost, on a crash).
//
// Replies are FIFO in frame order — the Nth returned ack belongs to the Nth
// message — and every ack keeps its at-least-once meaning: the record is
// fsync-durable before the ack exists. Each message is produced at ack level 1
// (durable); fire-and-forget and per-message dedup are not part of this path.
//
// On a per-slot server rejection (a typed *ServerError) or a cluster
// *NotLeaderError, the REMAINING replies are still drained (one reply per
// message, so the connection stays framed and usable) and the FIRST such error
// is returned. An IO, unexpected-frame, or malformed-reply error is terminal: it
// aborts immediately and the connection is broken (drop it). An empty window
// returns nil without touching the wire.
func (c *Client) ProduceWindow(ctx context.Context, messages []*Message) ([]ProduceAck, error) {
	if c.broken != nil {
		return nil, c.broken
	}
	if len(messages) == 0 {
		return nil, nil
	}

	// Phase 1: encode the WHOLE window into ONE buffer and write it with ONE
	// syscall. This is what puts all N produces in front of the broker's
	// group-commit drain as a single batch; a write() per frame would floor the
	// window's throughput on small payloads.
	c.wbuf = c.wbuf[:0]
	for _, m := range messages {
		body, err := c.encodePub(m, nil, AckLevelServer, false)
		if err != nil {
			return nil, err
		}
		c.wbuf, err = wire.AppendFrame(c.wbuf, wire.TagPub, body)
		if err != nil {
			return nil, err
		}
	}
	restore, err := c.deadlineFromContext(ctx)
	if err != nil {
		return nil, err
	}
	_, werr := c.conn.Write(c.wbuf)
	restore()
	if werr != nil {
		// A short or failed write leaves the peer mid-frame: terminal.
		return nil, c.fail(fmt.Errorf("ironbus: write window: %w", werr))
	}

	// Phase 2: drain exactly one reply per message, FIFO. A per-slot server
	// rejection / redirect is remembered (first wins) and the drain continues so
	// the connection stays framed; any other error is terminal and aborts.
	acks := make([]ProduceAck, len(messages))
	var firstErr error
	for i := range messages {
		ack, err := c.readPubReply(ctx)
		if err != nil {
			var srv *ServerError
			var nl *NotLeaderError
			if errors.As(err, &srv) || errors.As(err, &nl) {
				if firstErr == nil {
					firstErr = err
				}
				continue // leave acks[i] the zero value; keep draining
			}
			return nil, err // terminal: readPubReply already marked the client broken
		}
		acks[i] = ack
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return acks, nil
}

// ProduceFireAndForget publishes at level 0 (QoS-0): the broker may shed the
// produce under load and never replies. Loss is accepted by contract.
func (c *Client) ProduceFireAndForget(ctx context.Context, m *Message) error {
	body, err := c.encodePub(m, nil, AckLevelNone, true)
	if err != nil {
		return err
	}
	return c.send(ctx, wire.TagPub, body)
}

// encodePub builds a PUB body with the ack level bits and optional dedup block.
func (c *Client) encodePub(m *Message, d *Dedup, level uint8, fireAndForget bool) ([]byte, error) {
	var dedup *wire.PubDedup
	if d != nil {
		dedup = &wire.PubDedup{
			ProducerID: d.ProducerID,
			Epoch:      d.Epoch,
			MsgID:      d.MsgID,
			Seq:        d.Seq,
		}
	}
	return wire.AppendPub(nil, &wire.PubBody{
		Flags:         wire.WithAckLevelBits(0, level),
		TimestampMS:   m.timestamp(),
		Key:           m.Key,
		Headers:       m.Headers,
		Dedup:         dedup,
		FireAndForget: fireAndForget,
		Payload:       m.Payload,
	})
}

// produceBody sends one awaited publish (Pub, PubTo, or PubSubject: prefix is
// the verb's stream/subject prefix bytes, nil for a plain Pub) and reads its
// PubAck / PubAckDuplicate / Err / NotLeader reply.
func (c *Client) produceBody(ctx context.Context, tag byte, prefix []byte, m *Message, d *Dedup, level uint8) (ProduceAck, error) {
	pubBody, err := c.encodePub(m, d, level, false)
	if err != nil {
		return ProduceAck{}, err
	}
	body := pubBody
	if prefix != nil {
		body = append(append([]byte(nil), prefix...), pubBody...)
	}
	if err := c.send(ctx, tag, body); err != nil {
		return ProduceAck{}, err
	}
	return c.readPubReply(ctx)
}

// readPubReply reads a produce reply: PubAck (fresh), PubAckDuplicate (benign
// dedup hit), Err (typed rejection), or NotLeader (typed cluster redirect).
func (c *Client) readPubReply(ctx context.Context) (ProduceAck, error) {
	tag, body, err := c.readReply(ctx)
	if err != nil {
		return ProduceAck{}, err
	}
	switch tag {
	case wire.TagPubAck, wire.TagPubAckDuplicate:
		offset, err := wire.DecodePubAck(body)
		if err != nil {
			return ProduceAck{}, c.fail(err)
		}
		return ProduceAck{Offset: offset, Duplicate: tag == wire.TagPubAckDuplicate}, nil
	case wire.TagErr:
		code, message := wire.DecodeErrBody(body)
		return ProduceAck{}, &ServerError{Code: code, Message: message}
	case wire.TagNotLeader:
		hint, err := wire.DecodeNotLeader(body)
		if err != nil {
			return ProduceAck{}, c.fail(&BadResponseError{Reason: "malformed NotLeader redirect body"})
		}
		return ProduceAck{}, &NotLeaderError{LeaderHint: hint}
	default:
		return ProduceAck{}, c.fail(&UnexpectedFrameError{Tag: tag})
	}
}
