package ironbus

import (
	"context"

	"github.com/ELares/IronBus/sdk/go/internal/wire"
)

// BindSubject binds a subject PATTERN (wildcards * and > allowed) to a named
// stream (the empty stream name binds the default stream). Idempotent.
// Resolution is fail-closed single-home: a publish whose subject resolves to
// zero bound streams is ErrCodeNoStreamForSubject and to two or more is
// ErrCodeAmbiguousSubject.
func (c *Client) BindSubject(ctx context.Context, stream, pattern string) error {
	body, err := wire.AppendBindSubject(nil, &wire.BindSubjectBody{
		StreamID: []byte(stream),
		Pattern:  []byte(pattern),
	})
	if err != nil {
		return err
	}
	if err := c.send(ctx, wire.TagBindSubject, body); err != nil {
		return err
	}
	return c.expectTag(ctx, wire.TagOk)
}

// ProduceSubject publishes a message BY SUBJECT: the broker resolves the
// literal subject through the binding trie to exactly one bound stream and
// appends there.
func (c *Client) ProduceSubject(ctx context.Context, subject string, m *Message) (ProduceAck, error) {
	prefix, err := subjectPrefix(subject)
	if err != nil {
		return ProduceAck{}, err
	}
	return c.produceBody(ctx, wire.TagPubSubject, prefix, m, nil, AckLevelServer)
}

// SubscribeSubject subscribes BY SUBJECT: a LITERAL subject that resolves
// single-home through the binding trie to one bound stream, binding this
// connection's subsequent Fetch/Ack to that stream's work-group. A wildcard
// SUBJECT is a typed ErrCodeInvalidSubject reject (wildcards belong in the
// BIND pattern; fanning a wildcard subscribe over streams is a flagged broker
// follow-up). The resolved binding is drained with the per-record Flow verb
// (see Fetch).
func (c *Client) SubscribeSubject(ctx context.Context, subject, group string) error {
	body, err := wire.AppendSubSubject(nil, &wire.SubSubjectBody{
		Subject: []byte(subject),
		Group:   []byte(group),
	})
	if err != nil {
		return err
	}
	if err := c.send(ctx, wire.TagSubSubject, body); err != nil {
		return err
	}
	if err := c.expectTag(ctx, wire.TagOk); err != nil {
		return err
	}
	// The broker binds the RESOLVED stream, which may be the default stream;
	// the Flow verb routes correctly for both, so a subject binding always
	// drains via Flow.
	c.namedBinding = true
	return nil
}

// subjectPrefix encodes the version + field_len + subject prefix a PubSubject
// body places before the verbatim PUB tail.
func subjectPrefix(subject string) ([]byte, error) {
	body, err := wire.AppendPubSubject(nil, &wire.PubSubjectBody{Subject: []byte(subject)})
	if err != nil {
		return nil, err
	}
	return body, nil
}
