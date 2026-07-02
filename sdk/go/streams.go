package ironbus

import (
	"context"

	"github.com/ELares/IronBus/sdk/go/internal/wire"
)

// StreamInfo is the reply to a named-stream query.
type StreamInfo struct {
	// Exists reports whether the stream has been declared (or produced to).
	// The default stream "" always exists.
	Exists bool
	// Head is the stream's durable head (flushed) offset; 0 when absent.
	Head uint64
}

// DeclareStream creates-or-ensures a named stream (idempotent). The empty name
// is rejected by the broker: the default stream always exists and is never
// declared. Requires the streams capability (on by default; see
// Config.NoStreams).
func (c *Client) DeclareStream(ctx context.Context, stream string) error {
	body, err := wire.AppendStreamDeclare(nil, []byte(stream))
	if err != nil {
		return err
	}
	if err := c.send(ctx, wire.TagStreamDeclare, body); err != nil {
		return err
	}
	return c.expectTag(ctx, wire.TagOk)
}

// QueryStream reports whether a named stream exists and, if so, its durable
// head offset.
func (c *Client) QueryStream(ctx context.Context, stream string) (StreamInfo, error) {
	body, err := wire.AppendStreamInfoRequest(nil, []byte(stream))
	if err != nil {
		return StreamInfo{}, err
	}
	if err := c.send(ctx, wire.TagStreamInfo, body); err != nil {
		return StreamInfo{}, err
	}
	tag, reply, err := c.readReply(ctx)
	if err != nil {
		return StreamInfo{}, err
	}
	switch tag {
	case wire.TagStreamInfo:
		resp, err := wire.DecodeStreamInfoResponse(reply)
		if err != nil {
			return StreamInfo{}, c.fail(err)
		}
		return StreamInfo{Exists: resp.Exists, Head: resp.Head}, nil
	case wire.TagErr:
		code, message := wire.DecodeErrBody(reply)
		return StreamInfo{}, &ServerError{Code: code, Message: message}
	default:
		return StreamInfo{}, c.fail(&UnexpectedFrameError{Tag: tag})
	}
}

// ProduceTo publishes a message to a NAMED stream (the stream-addressed twin
// of Produce). The empty stream name routes to the default stream. The broker
// declares the stream on first produce.
func (c *Client) ProduceTo(ctx context.Context, stream string, m *Message) (ProduceAck, error) {
	prefix, err := streamPrefix(stream)
	if err != nil {
		return ProduceAck{}, err
	}
	return c.produceBody(ctx, wire.TagPubTo, prefix, m, nil, AckLevelServer)
}

// SubscribeTo joins a NAMED stream's own work-group: the connection's
// subsequent Fetch/Ack are bound to that stream (the same group name in two
// streams is two unrelated cursors). The stream must already exist. A
// named-stream binding is drained with the per-record Flow verb (see Fetch).
func (c *Client) SubscribeTo(ctx context.Context, stream, group string) error {
	body, err := wire.AppendSubTo(nil, &wire.SubToBody{
		StreamID: []byte(stream),
		Group:    []byte(group),
	})
	if err != nil {
		return err
	}
	if err := c.send(ctx, wire.TagSubTo, body); err != nil {
		return err
	}
	if err := c.expectTag(ctx, wire.TagOk); err != nil {
		return err
	}
	c.namedBinding = stream != ""
	return nil
}

// streamPrefix encodes the version + field_len + stream-id prefix a PubTo body
// places before the verbatim PUB tail.
func streamPrefix(stream string) ([]byte, error) {
	body, err := wire.AppendPubTo(nil, &wire.PubToBody{StreamID: []byte(stream)})
	if err != nil {
		return nil, err
	}
	return body, nil
}
