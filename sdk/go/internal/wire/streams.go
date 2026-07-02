package wire

import "encoding/binary"

// StreamWireBodyVersion is the version of the explicit-stream-id verb bodies
// (StreamDeclare / StreamInfo / PubTo / SubTo) and the subject-addressed verb
// bodies (BindSubject / PubSubject / SubSubject).
const StreamWireBodyVersion = 1

// MaxStreamIDLen is the hard wire-boundary cap on a stream-id (and subject /
// pattern) byte length, enforced at decode time BEFORE the bytes are taken.
const MaxStreamIDLen = 1024

// readCapped reads a u16-length-prefixed field enforcing MaxStreamIDLen.
func readCapped(r *reader) ([]byte, error) {
	n, err := r.u16()
	if err != nil {
		return nil, err
	}
	if int(n) > MaxStreamIDLen {
		return nil, ErrBadLength
	}
	return r.take(int(n))
}

// appendNamePrefixed encodes the shared version + field_len + one
// u16-length-prefixed name block used by StreamDeclare and StreamInfo.
func appendNamePrefixed(dst []byte, name []byte) ([]byte, error) {
	if len(name) > 0xFFFF-2 {
		return dst, ErrFieldTooLarge
	}
	dst = append(dst, StreamWireBodyVersion)
	dst = binary.LittleEndian.AppendUint16(dst, uint16(2+len(name)))
	dst = binary.LittleEndian.AppendUint16(dst, uint16(len(name)))
	return append(dst, name...), nil
}

// decodeNamePrefixed decodes the shared one-name block layout.
func decodeNamePrefixed(body []byte) ([]byte, error) {
	r := &reader{buf: body}
	version, err := r.u8()
	if err != nil {
		return nil, err
	}
	if version != StreamWireBodyVersion {
		return nil, &BadVersionError{Version: version}
	}
	fieldLen, err := r.u16()
	if err != nil {
		return nil, err
	}
	block, err := r.take(int(fieldLen))
	if err != nil {
		return nil, err
	}
	fr := &reader{buf: block}
	return readCapped(fr)
}

// AppendStreamDeclare encodes a StreamDeclare body (tag 28) onto dst.
func AppendStreamDeclare(dst []byte, streamID []byte) ([]byte, error) {
	return appendNamePrefixed(dst, streamID)
}

// DecodeStreamDeclare decodes a StreamDeclare body into its stream id.
func DecodeStreamDeclare(body []byte) ([]byte, error) {
	return decodeNamePrefixed(body)
}

// AppendStreamInfoRequest encodes a StreamInfo REQUEST body (tag 29) onto dst.
func AppendStreamInfoRequest(dst []byte, streamID []byte) ([]byte, error) {
	return appendNamePrefixed(dst, streamID)
}

// DecodeStreamInfoRequest decodes a StreamInfo REQUEST body.
func DecodeStreamInfoRequest(body []byte) ([]byte, error) {
	return decodeNamePrefixed(body)
}

// streamInfoRespV1FieldLen is the StreamInfo RESPONSE v1 block length:
// exists(u8) + head(u64).
const streamInfoRespV1FieldLen = 1 + 8

// StreamInfoResponse is the server's reply to a StreamInfo query: whether the
// stream exists and, if so, its durable head offset.
type StreamInfoResponse struct {
	Exists bool
	Head   uint64
}

// AppendStreamInfoResponse encodes a StreamInfo RESPONSE body onto dst.
func AppendStreamInfoResponse(dst []byte, resp *StreamInfoResponse) []byte {
	dst = append(dst, StreamWireBodyVersion)
	dst = binary.LittleEndian.AppendUint16(dst, streamInfoRespV1FieldLen)
	var exists byte
	if resp.Exists {
		exists = 1
	}
	dst = append(dst, exists)
	return binary.LittleEndian.AppendUint64(dst, resp.Head)
}

// DecodeStreamInfoResponse decodes a StreamInfo RESPONSE body. A non-0/1
// exists byte folds to false (forward-compatible, never an error).
func DecodeStreamInfoResponse(body []byte) (*StreamInfoResponse, error) {
	r := &reader{buf: body}
	version, err := r.u8()
	if err != nil {
		return nil, err
	}
	if version != StreamWireBodyVersion {
		return nil, &BadVersionError{Version: version}
	}
	fieldLen, err := r.u16()
	if err != nil {
		return nil, err
	}
	block, err := r.take(int(fieldLen))
	if err != nil {
		return nil, err
	}
	fr := &reader{buf: block}
	exists, _ := fr.u8()
	head, _ := fr.u64()
	return &StreamInfoResponse{Exists: exists == 1, Head: head}, nil
}

// PubToBody is a publish to a named stream (tag 30): the stream id prefix then
// the verbatim PubBody bytes as the remainder after the declared block.
type PubToBody struct {
	StreamID []byte
	// PubBodyBytes is the verbatim PUB body tail, encoded/decoded with
	// AppendPub / DecodePub (the publish body codec is shared unchanged).
	PubBodyBytes []byte
}

// AppendPubTo encodes a PubTo body onto dst.
func AppendPubTo(dst []byte, b *PubToBody) ([]byte, error) {
	dst, err := appendNamePrefixed(dst, b.StreamID)
	if err != nil {
		return dst, err
	}
	return append(dst, b.PubBodyBytes...), nil
}

// DecodePubTo decodes a PubTo body into its stream id and verbatim PUB tail.
func DecodePubTo(body []byte) (*PubToBody, error) {
	r := &reader{buf: body}
	version, err := r.u8()
	if err != nil {
		return nil, err
	}
	if version != StreamWireBodyVersion {
		return nil, &BadVersionError{Version: version}
	}
	fieldLen, err := r.u16()
	if err != nil {
		return nil, err
	}
	block, err := r.take(int(fieldLen))
	if err != nil {
		return nil, err
	}
	tail := r.rest()
	fr := &reader{buf: block}
	streamID, err := readCapped(fr)
	if err != nil {
		return nil, err
	}
	return &PubToBody{StreamID: streamID, PubBodyBytes: tail}, nil
}

// SubToBody is a subscribe to a named stream's work-group (tag 31).
type SubToBody struct {
	StreamID []byte
	Group    []byte
}

// AppendSubTo encodes a SubTo body onto dst.
func AppendSubTo(dst []byte, b *SubToBody) ([]byte, error) {
	return appendTwoFieldBlock(dst, b.StreamID, b.Group)
}

// DecodeSubTo decodes a SubTo body.
func DecodeSubTo(body []byte) (*SubToBody, error) {
	first, second, err := decodeTwoFieldBlock(body)
	if err != nil {
		return nil, err
	}
	return &SubToBody{StreamID: first, Group: second}, nil
}

// appendTwoFieldBlock encodes the shared version + field_len block carrying
// two u16-length-prefixed fields (SubTo, BindSubject, SubSubject).
func appendTwoFieldBlock(dst []byte, first, second []byte) ([]byte, error) {
	fieldLen := 2 + len(first) + 2 + len(second)
	if len(first) > 0xFFFF || len(second) > 0xFFFF || fieldLen > 0xFFFF {
		return dst, ErrFieldTooLarge
	}
	dst = append(dst, StreamWireBodyVersion)
	dst = binary.LittleEndian.AppendUint16(dst, uint16(fieldLen))
	dst = binary.LittleEndian.AppendUint16(dst, uint16(len(first)))
	dst = append(dst, first...)
	dst = binary.LittleEndian.AppendUint16(dst, uint16(len(second)))
	return append(dst, second...), nil
}

// decodeTwoFieldBlock decodes the shared two-field block layout. The first
// field is capped at MaxStreamIDLen; the second is a plain u16 var field.
func decodeTwoFieldBlock(body []byte) (first, second []byte, err error) {
	r := &reader{buf: body}
	version, err := r.u8()
	if err != nil {
		return nil, nil, err
	}
	if version != StreamWireBodyVersion {
		return nil, nil, &BadVersionError{Version: version}
	}
	fieldLen, err := r.u16()
	if err != nil {
		return nil, nil, err
	}
	block, err := r.take(int(fieldLen))
	if err != nil {
		return nil, nil, err
	}
	fr := &reader{buf: block}
	first, err = readCapped(fr)
	if err != nil {
		return nil, nil, err
	}
	second, err = fr.varField()
	if err != nil {
		return nil, nil, err
	}
	return first, second, nil
}

// BindSubjectBody binds a subject PATTERN to a stream (tag 34).
type BindSubjectBody struct {
	StreamID []byte
	Pattern  []byte
}

// AppendBindSubject encodes a BindSubject body onto dst.
func AppendBindSubject(dst []byte, b *BindSubjectBody) ([]byte, error) {
	return appendTwoFieldBlock(dst, b.StreamID, b.Pattern)
}

// DecodeBindSubject decodes a BindSubject body. Both fields are capped at
// MaxStreamIDLen, matching the Rust decoder.
func DecodeBindSubject(body []byte) (*BindSubjectBody, error) {
	r := &reader{buf: body}
	version, err := r.u8()
	if err != nil {
		return nil, err
	}
	if version != StreamWireBodyVersion {
		return nil, &BadVersionError{Version: version}
	}
	fieldLen, err := r.u16()
	if err != nil {
		return nil, err
	}
	block, err := r.take(int(fieldLen))
	if err != nil {
		return nil, err
	}
	fr := &reader{buf: block}
	streamID, err := readCapped(fr)
	if err != nil {
		return nil, err
	}
	pattern, err := readCapped(fr)
	if err != nil {
		return nil, err
	}
	return &BindSubjectBody{StreamID: streamID, Pattern: pattern}, nil
}

// PubSubjectBody is a publish by subject (tag 35): the subject prefix then the
// verbatim PubBody bytes as the remainder.
type PubSubjectBody struct {
	Subject      []byte
	PubBodyBytes []byte
}

// AppendPubSubject encodes a PubSubject body onto dst.
func AppendPubSubject(dst []byte, b *PubSubjectBody) ([]byte, error) {
	dst, err := appendNamePrefixed(dst, b.Subject)
	if err != nil {
		return dst, err
	}
	return append(dst, b.PubBodyBytes...), nil
}

// DecodePubSubject decodes a PubSubject body.
func DecodePubSubject(body []byte) (*PubSubjectBody, error) {
	inner, err := DecodePubTo(body)
	if err != nil {
		return nil, err
	}
	return &PubSubjectBody{Subject: inner.StreamID, PubBodyBytes: inner.PubBodyBytes}, nil
}

// SubSubjectBody is a subscribe by subject (tag 36): a literal or wildcard
// subject plus the work-group name.
type SubSubjectBody struct {
	Subject []byte
	Group   []byte
}

// AppendSubSubject encodes a SubSubject body onto dst.
func AppendSubSubject(dst []byte, b *SubSubjectBody) ([]byte, error) {
	return appendTwoFieldBlock(dst, b.Subject, b.Group)
}

// DecodeSubSubject decodes a SubSubject body.
func DecodeSubSubject(body []byte) (*SubSubjectBody, error) {
	first, second, err := decodeTwoFieldBlock(body)
	if err != nil {
		return nil, err
	}
	return &SubSubjectBody{Subject: first, Group: second}, nil
}
