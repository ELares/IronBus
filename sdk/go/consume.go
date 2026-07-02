package ironbus

import (
	"context"
	"math"
	"time"

	"github.com/ELares/IronBus/sdk/go/internal/wire"
)

// NackNoDelay is the Nack delay sentinel for "no explicit delay": the broker
// applies its backoff schedule for the attempt.
const NackNoDelay = wire.NackNoDelay

// maxFetchDecompressedBytes is the aggregate materialized-payload ceiling for
// ONE fetch window (#879): the per-record cap bounds one record; this bounds
// the whole window so a credit-bounded fetch of many tiny high-ratio frames
// cannot materialize credit x 8 MiB resident. It is a generous FLOOR: a
// consumer that negotiated a larger byte budget is honored (see
// fetchDecompressedCap).
const maxFetchDecompressedBytes = 256 * 1024 * 1024

// Delivery is one consumed message: the record plus the offset that names it
// and the lease generation (fencing token) to settle it with. A payload the
// broker stored compressed has already been transparently decompressed and the
// compressed flag cleared.
type Delivery struct {
	Offset      uint64
	Generation  uint64
	Flags       byte
	TimestampMS uint64
	Key         []byte
	Headers     []byte
	Payload     []byte
}

// DeadLetter is the in-band advisory that an offset was dead-lettered (poison)
// and skipped from delivery.
type DeadLetter struct {
	Offset uint64
	Reason byte
}

// Truncation is the legacy advisory that the cursor fell below the oldest
// retained record (the disk-full drop-oldest reap).
type Truncation struct {
	EarliestRetained uint64
	Skipped          uint64
}

// Gap is the opt-in richer truncation twin: offsets [From, To) are permanently
// absent from the deliver stream.
type Gap struct {
	From         uint64
	To           uint64
	BytesSkipped uint64
	Reason       byte
}

// FetchResult is one drained fetch window: the deliveries plus any interleaved
// advisories.
type FetchResult struct {
	Messages    []Delivery
	DeadLetters []DeadLetter
	Truncations []Truncation
	Gaps        []Gap
}

// FetchOptions bound one Fetch batch.
type FetchOptions struct {
	// MaxRecords is the most records to drain (capped at the negotiated
	// per-consumer credit when the server advertised one). Zero requests
	// nothing.
	MaxRecords uint32
	// MaxBytes bounds the total payload-equivalent bytes (0 = unbounded by
	// bytes; the server applies a floor of one record).
	MaxBytes uint64
	// Expires is the server-side drain deadline budget (0 = none).
	Expires time.Duration
	// NoWait makes the server return immediately with whatever is ready.
	NoWait bool
}

// Subscribe joins a work-group on the default stream (an empty group selects
// the default group). It clears any prior named-stream binding, exactly like
// the broker does.
func (c *Client) Subscribe(ctx context.Context, group string) error {
	if err := c.send(ctx, wire.TagSub, []byte(group)); err != nil {
		return err
	}
	if err := c.expectTag(ctx, wire.TagOk); err != nil {
		return err
	}
	c.namedBinding = false
	return nil
}

// Unsubscribe cancels the connection's subscription (reverting any
// named-stream binding to the default stream).
func (c *Client) Unsubscribe(ctx context.Context) error {
	if err := c.send(ctx, wire.TagUnsub, nil); err != nil {
		return err
	}
	if err := c.expectTag(ctx, wire.TagOk); err != nil {
		return err
	}
	c.namedBinding = false
	return nil
}

// Fetch drains up to opts.MaxRecords / opts.MaxBytes of deliverable records in
// one round-trip. The response is a run of Deliver frames with any interleaved
// DeadLetter / Truncated / GapMarker advisories, terminated by exactly one
// FlowEnd.
//
// On a default-stream subscription this is the batch-pull Fetch verb (tag 23).
// A connection bound to a NAMED stream (SubscribeTo / SubscribeSubject) is
// drained with the per-record Flow verb (tag 10) instead — the broker's batch
// Fetch polls the default stream only — so opts.MaxBytes, opts.Expires, and
// opts.NoWait do not apply there (a Flow drain is a single immediate pass).
func (c *Client) Fetch(ctx context.Context, opts FetchOptions) (*FetchResult, error) {
	maxRecords := opts.MaxRecords
	if c.info.NegotiatedCredit != nil && maxRecords > *c.info.NegotiatedCredit {
		maxRecords = *c.info.NegotiatedCredit
	}
	if c.namedBinding {
		if err := c.send(ctx, wire.TagFlow, wire.AppendFlow(nil, maxRecords)); err != nil {
			return nil, err
		}
		return c.readFetchResponse(ctx, int(maxRecords))
	}
	expiresMS := uint64(0)
	if opts.Expires > 0 {
		expiresMS = uint64(opts.Expires / time.Millisecond)
	}
	body := wire.AppendFetch(nil, &wire.FetchBody{
		MaxRecords: maxRecords,
		MaxBytes:   opts.MaxBytes,
		ExpiresMS:  expiresMS,
		NoWait:     opts.NoWait,
	})
	if err := c.send(ctx, wire.TagFetch, body); err != nil {
		return nil, err
	}
	return c.readFetchResponse(ctx, int(maxRecords))
}

// fetchDecompressedCap derives the aggregate materialized-bytes ceiling for
// one fetch window: max(negotiated credit bytes, the 256 MiB floor), so an
// un-negotiated or hostile window stays fail-closed while a consumer that
// negotiated a bigger budget is honored (#938). The guard is math.MaxInt (not
// MaxInt64) so a huge advertised budget can never wrap the int cap negative on
// a 32-bit build.
func (c *Client) fetchDecompressedCap() int {
	cap := maxFetchDecompressedBytes
	if b := c.info.NegotiatedCreditBytes; b != nil && *b > uint64(cap) && *b <= math.MaxInt {
		cap = int(*b)
	}
	return cap
}

// readFetchResponse drains one delivery window: Deliver frames plus advisories
// terminated by FlowEnd (or Err). limit bounds the total delivery + advisory
// frames the server may stream before the terminator, so a buggy or hostile
// server cannot stream without bound. A per-record decompression failure or an
// aggregate-cap breach poisons the batch: the remaining frames are DRAINED
// (keeping the connection framed) and the error surfaces after FlowEnd.
func (c *Client) readFetchResponse(ctx context.Context, limit int) (*FetchResult, error) {
	out := &FetchResult{}
	var poison error
	frames := 0
	decompressedBytes := 0
	maxAggregate := c.fetchDecompressedCap()
	for {
		tag, body, err := c.readFrame(ctx)
		if err != nil {
			return nil, err
		}
		if tag == wire.TagProduceConfirm {
			// An out-of-band level-2 ProduceConfirm push. The broker emits it
			// the moment the awaited consumer ack lands, so on a connection
			// that both produces at level 2 and consumes, a confirm can be
			// queued BETWEEN fetch windows and surface here. Drain it exactly
			// like readReply does; it is not part of the delivery window, so
			// it is exempt from the credit-derived frame limit below.
			continue
		}
		if tag != wire.TagFlowEnd && tag != wire.TagErr {
			if frames >= limit {
				return nil, c.fail(&BadResponseError{Reason: "server streamed more frames than the requested credit"})
			}
			frames++
		}
		switch tag {
		case wire.TagDeliver:
			d, err := wire.DecodeDeliver(body)
			if err != nil {
				return nil, c.fail(err)
			}
			if poison != nil {
				// Draining after a poison: the frame is consumed (keeping the
				// connection framed) but dropped un-acked; the broker
				// redelivers it after the visibility timeout.
				continue
			}
			delivery, size, err := decodeDelivery(d)
			if err != nil {
				poison = err
				continue
			}
			decompressedBytes += size
			if decompressedBytes > maxAggregate {
				poison = &BadResponseError{Reason: "fetch response exceeded the aggregate decompressed-bytes cap"}
				continue
			}
			out.Messages = append(out.Messages, delivery)
		case wire.TagDeadLetter:
			dl, err := wire.DecodeDeadLetter(body)
			if err != nil {
				return nil, c.fail(err)
			}
			out.DeadLetters = append(out.DeadLetters, DeadLetter{Offset: dl.Offset, Reason: dl.Reason})
		case wire.TagTruncated:
			tr, err := wire.DecodeTruncated(body)
			if err != nil {
				return nil, c.fail(err)
			}
			out.Truncations = append(out.Truncations, Truncation{
				EarliestRetained: tr.EarliestRetained,
				Skipped:          tr.Skipped,
			})
		case wire.TagGapMarker:
			g, err := wire.DecodeGapMarker(body)
			if err != nil {
				return nil, c.fail(err)
			}
			out.Gaps = append(out.Gaps, Gap{
				From:         g.From,
				To:           g.To,
				BytesSkipped: g.BytesSkipped,
				Reason:       g.Reason,
			})
		case wire.TagFlowEnd:
			if _, err := wire.DecodeFlowEnd(body); err != nil {
				return nil, c.fail(err)
			}
			if poison != nil {
				return nil, poison
			}
			return out, nil
		case wire.TagErr:
			code, message := wire.DecodeErrBody(body)
			return nil, &ServerError{Code: code, Message: message}
		default:
			return nil, c.fail(&UnexpectedFrameError{Tag: tag})
		}
	}
}

// decodeDelivery converts one wire delivery into a Delivery, transparently
// decompressing a compressed payload (per-record 8 MiB cap enforced BEFORE
// allocation) and clearing the compressed flag, exactly like the reference
// client. It returns the materialized payload size for the aggregate cap.
func decodeDelivery(d *wire.DeliverBody) (Delivery, int, error) {
	flags := d.Flags
	var payload []byte
	if flags&wire.RecordFlagCompressed != 0 {
		raw, err := wire.DecompressPayload(d.Payload, wire.MaxDecompressedBytes)
		if err != nil {
			return Delivery{}, 0, err
		}
		payload = raw
		flags &^= wire.RecordFlagCompressed
	} else {
		payload = append([]byte(nil), d.Payload...)
	}
	return Delivery{
		Offset:      d.Offset,
		Generation:  d.Generation,
		Flags:       flags,
		TimestampMS: d.TimestampMS,
		Key:         append([]byte(nil), d.Key...),
		Headers:     append([]byte(nil), d.Headers...),
		Payload:     payload,
	}, len(payload), nil
}

// settle sends one Ack-frame op and reads its AckStatus.
func (c *Client) settle(ctx context.Context, op byte, offset, generation, delayMS uint64) (byte, error) {
	body := wire.AppendAck(nil, &wire.AckBody{
		Op:         op,
		Offset:     offset,
		Generation: generation,
		DelayMS:    delayMS,
	})
	if err := c.send(ctx, wire.TagAck, body); err != nil {
		return 0, err
	}
	tag, reply, err := c.readReply(ctx)
	if err != nil {
		return 0, err
	}
	switch tag {
	case wire.TagAckStatus:
		status, err := wire.DecodeAckStatus(reply)
		if err != nil {
			return 0, c.fail(err)
		}
		return status, nil
	case wire.TagErr:
		code, message := wire.DecodeErrBody(reply)
		return 0, &ServerError{Code: code, Message: message}
	default:
		return 0, c.fail(&UnexpectedFrameError{Tag: tag})
	}
}

// Ack commits a delivered message. It returns true when the ack committed and
// false when it was FENCED (the lease generation was stale: the message had
// already been redelivered elsewhere).
func (c *Client) Ack(ctx context.Context, offset, generation uint64) (bool, error) {
	status, err := c.settle(ctx, wire.AckOpAck, offset, generation, 0)
	return status == wire.AckStatusCommitted, err
}

// Nack requeues a delivered message for redelivery after delayMS milliseconds
// (0 = immediately; NackNoDelay = the broker's backoff schedule). It returns
// true when the requeue was accepted and false when fenced.
func (c *Client) Nack(ctx context.Context, offset, generation, delayMS uint64) (bool, error) {
	status, err := c.settle(ctx, wire.AckOpNack, offset, generation, delayMS)
	return status == wire.AckStatusCommitted, err
}

// Term stops redelivering a message without dead-lettering it. It returns true
// when accepted and false when fenced.
func (c *Client) Term(ctx context.Context, offset, generation uint64) (bool, error) {
	status, err := c.settle(ctx, wire.AckOpTerm, offset, generation, 0)
	return status == wire.AckStatusCommitted, err
}

// Progress extends the lease on a message still being worked. It returns the
// raw ack status (committed / fenced / progress cap reached).
func (c *Client) Progress(ctx context.Context, offset, generation uint64) (byte, error) {
	return c.settle(ctx, wire.AckOpProgress, offset, generation, 0)
}

// CumulativeAck commits a BROADCAST group's single cursor up to the exclusive
// upTo offset. The server hard-rejects it on any competing or key-shared
// group.
func (c *Client) CumulativeAck(ctx context.Context, group string, upTo uint64) error {
	body := wire.AppendCumulativeAck(nil, &wire.CumulativeAckBody{UpTo: upTo, Group: []byte(group)})
	if err := c.send(ctx, wire.TagCumulativeAck, body); err != nil {
		return err
	}
	return c.expectTag(ctx, wire.TagOk)
}
