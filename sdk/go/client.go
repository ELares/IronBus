// Package ironbus is the official Go client SDK for IronBus (issue #1021): a
// minimal, wire-exact client over the frozen versioned protocol.
//
// # Concurrency model
//
// A Client owns ONE TCP connection driven request-response FIFO, mirroring the
// reference clients: it is NOT goroutine-safe. Use one Client per goroutine
// (or add your own external synchronization); there is no multiplexer in the
// MVP.
//
// # Deadlines and cancellation safety
//
// Every method takes a context.Context. A context DEADLINE is mapped onto the
// connection's read/write deadlines for the duration of the call and cleared
// afterwards; a context without a deadline blocks like the underlying socket.
// A deadline (or cancellation) that fires while a reply is pending is TERMINAL
// for the connection, matching the Rust reference client's posture: the
// request-response FIFO is still owed that reply, so reusing the connection
// would pair every later request with the previous request's reply. A
// timed-out client must be discarded and a new one dialed.
//
// # Terminal errors
//
// A malformed frame, an unknown frame tag (per the frozen-wire contract an
// unrecognized tag is TERMINAL, never skipped), an unexpected reply type, a
// deadline or cancellation mid-reply, or a closed connection marks the client
// broken: every later call returns the same error until Close.
package ironbus

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/ELares/IronBus/sdk/go/internal/wire"
)

// readWindow is the smallest socket read while completing a frame.
const readWindow = 4096

// readCap bounds the per-read scratch size so a large frame is assembled in
// capped reads rather than one giant read.
const readCap = 256 * 1024

// Info is the negotiated result of the Connect/Info handshake.
type Info struct {
	// NegotiatedCredit is the per-consumer message credit the server
	// advertised for this connection (nil when it did not advertise).
	NegotiatedCredit *uint32
	// NegotiatedCreditBytes is the per-consumer byte budget the server
	// advertised (nil when it did not advertise).
	NegotiatedCreditBytes *uint64
	// GapMarker reports whether the server CONFIRMED it will send GapMarker
	// advisories in place of legacy Truncated ones (the AND of both peers'
	// capability bits).
	GapMarker bool
	// Streams reports whether the server CONFIRMED the named-stream and
	// subject addressing verbs for this connection.
	Streams bool
	// DefaultAckLevel is the connection-wide default produce ack level the
	// server echoed, if any.
	DefaultAckLevel *uint8
}

// Client is an IronBus connection. NOT goroutine-safe: one Client per
// goroutine (see the package documentation).
type Client struct {
	conn net.Conn
	// buf is the persistent framing buffer. It is extended ONLY after a
	// socket read SUCCEEDS (scratch-then-extend), so a propagated error never
	// pollutes it with partial placeholder bytes.
	buf     []byte
	scratch []byte
	wbuf    []byte
	info    Info
	broken  error
	// namedBinding tracks whether the connection's consume path is bound to a
	// NAMED stream (via SubscribeTo / SubscribeSubject). A named binding is
	// consumed with the per-record Flow verb: the broker's batch Fetch verb
	// polls the default stream only. Fetch routes on this transparently.
	namedBinding bool
}

// Connect dials the broker, completes the Connect/Info handshake, and adopts
// the negotiated capabilities.
func Connect(ctx context.Context, cfg Config) (*Client, error) {
	// Symmetric client-side validation (#1039): the connection-wide default ack
	// level must be one of the three frozen wire levels (0, 1, 2), exactly as
	// ProduceWithAckLevel rejects an out-of-range per-publish level. Reject it here
	// rather than dialing and sending an invalid byte the broker would refuse at the
	// handshake — a config mistake surfaces as a clear typed error, not a wire error.
	if cfg.DefaultAckLevel != nil && *cfg.DefaultAckLevel > AckLevelServerAndClient {
		return nil, &InvalidAckLevelError{Level: *cfg.DefaultAckLevel}
	}
	addr := cfg.Addr
	if addr == "" {
		addr = DefaultAddr
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("ironbus: dial %s: %w", addr, err)
	}
	c := &Client{conn: conn}

	body := wire.AppendConnect(nil, &wire.ConnectBody{
		RequestedCredit:      cfg.RequestedCredit,
		RequestedCreditBytes: cfg.RequestedCreditBytes,
		WantsGapMarker:       !cfg.NoGapMarker,
		DefaultAckLevel:      cfg.DefaultAckLevel,
		UnderstandsStreams:   !cfg.NoStreams,
		// Deliberately OFF in the MVP: the Tier-S streaming tier and the
		// raw-framed DeliverBatch decode (see issue #1021). With these bits
		// clear the server never sends a DeliverBatch frame.
		UnderstandsStreaming:    false,
		UnderstandsDeliverBatch: false,
	})
	if cfg.Credential.isSet() {
		body, err = wire.AppendConnectAuth(body, cfg.Credential.mechanism, cfg.Credential.material)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	if err := c.send(ctx, wire.TagConnect, body); err != nil {
		_ = conn.Close()
		return nil, err
	}
	tag, reply, err := c.readFrame(ctx)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	switch tag {
	case wire.TagInfo:
		info, err := wire.DecodeInfo(reply)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		if info.Credit != nil {
			v := info.Credit.Negotiated
			c.info.NegotiatedCredit = &v
		}
		if info.CreditBytes != nil {
			v := info.CreditBytes.Negotiated
			c.info.NegotiatedCreditBytes = &v
		}
		c.info.GapMarker = info.GapMarker
		c.info.Streams = info.Streams
		c.info.DefaultAckLevel = info.DefaultAckLevel
		return c, nil
	case wire.TagErr:
		code, message := wire.DecodeErrBody(reply)
		_ = conn.Close()
		return nil, &ServerError{Code: code, Message: message}
	default:
		_ = conn.Close()
		return nil, &UnexpectedFrameError{Tag: tag}
	}
}

// Info returns the negotiated handshake result.
func (c *Client) Info() Info {
	return c.info
}

// Close closes the connection. The client is unusable afterwards.
func (c *Client) Close() error {
	if c.broken == nil {
		c.broken = ErrClosed
	}
	return c.conn.Close()
}

// Ping round-trips a keepalive.
func (c *Client) Ping(ctx context.Context) error {
	if err := c.send(ctx, wire.TagPing, nil); err != nil {
		return err
	}
	return c.expectTag(ctx, wire.TagPong)
}

// fail marks the client terminally broken and returns err.
func (c *Client) fail(err error) error {
	if c.broken == nil {
		c.broken = err
	}
	return err
}

// deadlineFromContext applies ctx's deadline (if any) to the whole connection
// for one operation and returns a restore func that clears it. Mapping the
// context deadline onto SetReadDeadline/SetWriteDeadline is the documented
// cancellation model of the MVP.
func (c *Client) deadlineFromContext(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := c.conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
		return func() { _ = c.conn.SetDeadline(time.Time{}) }, nil
	}
	return func() {}, nil
}

// send frames and writes one request.
func (c *Client) send(ctx context.Context, tag byte, body []byte) error {
	if c.broken != nil {
		return c.broken
	}
	restore, err := c.deadlineFromContext(ctx)
	if err != nil {
		return err
	}
	defer restore()
	c.wbuf, err = wire.AppendFrame(c.wbuf[:0], tag, body)
	if err != nil {
		return err
	}
	if _, err := c.conn.Write(c.wbuf); err != nil {
		// A short or failed write leaves the peer mid-frame: terminal.
		return c.fail(fmt.Errorf("ironbus: write: %w", err))
	}
	return nil
}

// readFrame buffers and returns one complete frame. The returned body is a
// copy (it never aliases the framing buffer). Read discipline: bytes go into
// a scratch buffer first and are appended to the persistent buffer only after
// the read SUCCEEDS, so an error return never pollutes the framing buffer.
// EVERY error here — including a context deadline or cancellation — is
// terminal for the connection: readFrame runs only while the FIFO is owed a
// reply, and abandoning that reply would mispair every later exchange.
func (c *Client) readFrame(ctx context.Context) (byte, []byte, error) {
	if c.broken != nil {
		return 0, nil, c.broken
	}
	restore, err := c.deadlineFromContext(ctx)
	if err != nil {
		// The request was already sent: giving up on its reply is terminal.
		return 0, nil, c.fail(err)
	}
	defer restore()
	for {
		tag, body, consumed, needed, err := wire.DecodeFrame(c.buf)
		if err != nil {
			return 0, nil, c.fail(err)
		}
		if consumed > 0 {
			if _, known := knownTags[tag]; !known {
				// An unknown tag from a newer (or hostile) server is TERMINAL
				// by the frozen-wire contract: never skip it.
				return 0, nil, c.fail(&UnknownFrameError{Tag: tag})
			}
			out := append([]byte(nil), body...)
			c.buf = append(c.buf[:0], c.buf[consumed:]...)
			return tag, out, nil
		}
		readSize := needed - len(c.buf)
		if readSize < readWindow {
			readSize = readWindow
		}
		if readSize > readCap {
			readSize = readCap
		}
		if cap(c.scratch) < readSize {
			c.scratch = make([]byte, readSize)
		}
		n, err := c.conn.Read(c.scratch[:readSize])
		if n > 0 {
			c.buf = append(c.buf, c.scratch[:n]...)
		}
		if err != nil {
			// Terminal even when err is a deadline: the pending reply is
			// abandoned, so a retried request on this connection would read
			// the PREVIOUS request's reply (off-by-one forever). The caller
			// must discard the client and redial.
			return 0, nil, c.fail(fmt.Errorf("ironbus: read: %w", err))
		}
	}
}

// knownTags is the set of frame tags this client recognizes. Anything else is
// a terminal UnknownFrameError. The peer/cluster verbs and the tags of
// capabilities this client deliberately does not advertise are intentionally
// ABSENT here, so receiving one is terminal too (fail-closed).
var knownTags = map[byte]struct{}{
	wire.TagConnect: {}, wire.TagInfo: {}, wire.TagPing: {}, wire.TagPong: {},
	wire.TagPub: {}, wire.TagSub: {}, wire.TagUnsub: {}, wire.TagAck: {},
	wire.TagNack: {}, wire.TagOk: {}, wire.TagErr: {}, wire.TagDeliver: {},
	wire.TagPubAck: {}, wire.TagAckStatus: {}, wire.TagFlowEnd: {},
	wire.TagDeadLetter: {}, wire.TagTruncated: {}, wire.TagCumulativeAck: {},
	wire.TagPubAckDuplicate: {}, wire.TagGapMarker: {}, wire.TagProduceConfirm: {},
	wire.TagFetch: {}, wire.TagStreamDeclare: {}, wire.TagStreamInfo: {},
	wire.TagPubTo: {}, wire.TagSubTo: {}, wire.TagBindSubject: {},
	wire.TagPubSubject: {}, wire.TagSubSubject: {}, wire.TagNotLeader: {},
}

// readReply reads the next reply frame, draining any interleaved
// ProduceConfirm (tag 22) pushes. A confirm is the broker's out-of-band
// level-2 produce notification; the MVP records the level on the wire but does
// not await confirms, so they are consumed without disturbing the FIFO.
func (c *Client) readReply(ctx context.Context) (byte, []byte, error) {
	for {
		tag, body, err := c.readFrame(ctx)
		if err != nil {
			return 0, nil, err
		}
		if tag == wire.TagProduceConfirm {
			continue
		}
		return tag, body, nil
	}
}

// expectTag reads the reply and requires exactly the given body-less tag,
// mapping an Err reply to a ServerError.
func (c *Client) expectTag(ctx context.Context, want byte) error {
	tag, body, err := c.readReply(ctx)
	if err != nil {
		return err
	}
	switch tag {
	case want:
		return nil
	case wire.TagErr:
		code, message := wire.DecodeErrBody(body)
		return &ServerError{Code: code, Message: message}
	default:
		return c.fail(&UnexpectedFrameError{Tag: tag})
	}
}
