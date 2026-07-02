package wire

import (
	"encoding/binary"
	"unicode/utf8"
)

// PUB body wire flag bits. Dedup / fire-and-forget / sequence / ack-level are
// WIRE-ONLY bits the server masks off before the byte becomes a stored record
// flag; the low bits (RecordFlag*) are storage flags.
const (
	PubFlagHasDedup      = 0b1000_0000
	PubFlagFireAndForget = 0b0100_0000
	PubFlagHasSeq        = 0b0010_0000
	PubFlagAckLevelMask  = 0b0001_1000
	PubFlagAckLevelShift = 3
)

// Stored record flag bits carried on a Deliver body's flags byte.
const (
	// RecordFlagCompressed marks a payload stored compressed: the payload
	// bytes are a [codec:u8][dict:u32 LE][uncompressed_len:u32 LE] descriptor
	// followed by the codec stream. See DecompressPayload.
	RecordFlagCompressed = 0b0000_0001
	// RecordFlagHasKey marks a record that carries a non-empty key.
	RecordFlagHasKey = 0b0000_0010
)

// PubAckLevel reads the produce ack level a PUB flags byte requests, folding
// the canonical fire-and-forget bit and the 2-bit ack-level field exactly as
// ironbus-proto's pub_ack_level does: faf or field 1 => 0 (no ack), field 2 =>
// 2 (server+client ack), field 0 or the reserved 3 => 1 (server ack).
func PubAckLevel(flags byte) uint8 {
	if flags&PubFlagFireAndForget != 0 {
		return 0
	}
	switch (flags & PubFlagAckLevelMask) >> PubFlagAckLevelShift {
	case 1:
		return 0
	case 2:
		return 2
	default:
		return 1
	}
}

// WithAckLevelBits writes an ack level into the 2-bit ack-level field of a PUB
// flags byte, mirroring the reference client: level 2 encodes field 2; levels
// 0 and 1 encode the canonical field 0 (level 0's canonical encoding is the
// fire-and-forget bit, set separately).
func WithAckLevelBits(flags byte, level uint8) byte {
	var field byte
	if level == 2 {
		field = 2
	}
	bits := (field << PubFlagAckLevelShift) & PubFlagAckLevelMask
	return (flags &^ PubFlagAckLevelMask) | bits
}

// PubDedup is the opt-in dedup block of a PUB body. Seq is the opt-in
// idempotent-producer sequence riding inside the block (nil = absent).
type PubDedup struct {
	ProducerID []byte
	Epoch      uint64
	MsgID      []byte
	Seq        *uint64
}

// PubBody is a producer's published message (the PUB frame body). The dedup,
// fire-and-forget, and sequence wire bits are DERIVED from the fields at
// encode time so the flags byte and the body can never disagree; the ack-level
// field is carried in Flags and preserved.
type PubBody struct {
	Flags         byte
	TimestampMS   uint64
	Key           []byte
	Headers       []byte
	Dedup         *PubDedup
	FireAndForget bool
	Payload       []byte
}

// AppendPub encodes a PUB body onto dst.
func AppendPub(dst []byte, m *PubBody) ([]byte, error) {
	flags := m.Flags &^ (PubFlagHasDedup | PubFlagFireAndForget | PubFlagHasSeq)
	if m.Dedup != nil {
		flags |= PubFlagHasDedup
		if m.Dedup.Seq != nil {
			flags |= PubFlagHasSeq
		}
	}
	if m.FireAndForget {
		flags |= PubFlagFireAndForget
	}
	dst = append(dst, flags)
	dst = binary.LittleEndian.AppendUint64(dst, m.TimestampMS)
	dst, err := appendVar(dst, m.Key)
	if err != nil {
		return dst, err
	}
	dst, err = appendVar(dst, m.Headers)
	if err != nil {
		return dst, err
	}
	if m.Dedup != nil {
		dst, err = appendVar(dst, m.Dedup.ProducerID)
		if err != nil {
			return dst, err
		}
		dst = binary.LittleEndian.AppendUint64(dst, m.Dedup.Epoch)
		dst, err = appendVar(dst, m.Dedup.MsgID)
		if err != nil {
			return dst, err
		}
		if m.Dedup.Seq != nil {
			dst = binary.LittleEndian.AppendUint64(dst, *m.Dedup.Seq)
		}
	}
	return append(dst, m.Payload...), nil
}

// DecodePub decodes a PUB body. The payload is whatever remains after the
// framed fields, so body must be exactly one frame's body.
func DecodePub(body []byte) (*PubBody, error) {
	r := &reader{buf: body}
	flags, err := r.u8()
	if err != nil {
		return nil, err
	}
	timestampMS, err := r.u64()
	if err != nil {
		return nil, err
	}
	key, err := r.varField()
	if err != nil {
		return nil, err
	}
	headers, err := r.varField()
	if err != nil {
		return nil, err
	}
	out := &PubBody{
		Flags:         flags,
		TimestampMS:   timestampMS,
		Key:           key,
		Headers:       headers,
		FireAndForget: flags&PubFlagFireAndForget != 0,
	}
	if flags&PubFlagHasDedup != 0 {
		producerID, err := r.varField()
		if err != nil {
			return nil, err
		}
		epoch, err := r.u64()
		if err != nil {
			return nil, err
		}
		msgID, err := r.varField()
		if err != nil {
			return nil, err
		}
		dedup := &PubDedup{ProducerID: producerID, Epoch: epoch, MsgID: msgID}
		if flags&PubFlagHasSeq != 0 {
			seq, err := r.u64()
			if err != nil {
				return nil, err
			}
			dedup.Seq = &seq
		}
		out.Dedup = dedup
	} else if flags&PubFlagHasSeq != 0 {
		// A seq bit without a dedup block is a protocol violation: fail closed
		// rather than fold the would-be sequence into the payload.
		return nil, ErrBadLength
	}
	out.Payload = r.rest()
	return out, nil
}

// Acknowledgement op bytes carried in an ACK body.
const (
	AckOpAck      = 0
	AckOpNack     = 1
	AckOpTerm     = 2
	AckOpProgress = 3
)

// NackNoDelay is the delay_ms sentinel for "no explicit delay": the broker
// applies its backoff schedule for the attempt.
const NackNoDelay = ^uint64(0)

// AckBody is a consumer acknowledgement (a fixed 25-byte layout). DelayMS is
// meaningful only for a nack (zero otherwise).
type AckBody struct {
	Op         byte
	Offset     uint64
	Generation uint64
	DelayMS    uint64
}

// AppendAck encodes an ACK body onto dst.
func AppendAck(dst []byte, a *AckBody) []byte {
	dst = append(dst, a.Op)
	dst = binary.LittleEndian.AppendUint64(dst, a.Offset)
	dst = binary.LittleEndian.AppendUint64(dst, a.Generation)
	return binary.LittleEndian.AppendUint64(dst, a.DelayMS)
}

// DecodeAck decodes an ACK body; trailing bytes and unknown ops are rejected.
func DecodeAck(body []byte) (*AckBody, error) {
	r := &reader{buf: body}
	op, err := r.u8()
	if err != nil {
		return nil, err
	}
	if op > AckOpProgress {
		return nil, &BadAckOpError{Op: op}
	}
	offset, err := r.u64()
	if err != nil {
		return nil, err
	}
	generation, err := r.u64()
	if err != nil {
		return nil, err
	}
	delayMS, err := r.u64()
	if err != nil {
		return nil, err
	}
	if !r.atEnd() {
		return nil, ErrTrailingBytes
	}
	return &AckBody{Op: op, Offset: offset, Generation: generation, DelayMS: delayMS}, nil
}

// DeliverBody is a message delivered to a consumer: the record plus the offset
// that names it and the lease generation (fencing token) to ack it with. The
// payload is the STORED bytes; a flags byte carrying RecordFlagCompressed
// means the payload is a compression descriptor + codec stream (see
// DecompressPayload).
type DeliverBody struct {
	Offset      uint64
	Generation  uint64
	Flags       byte
	TimestampMS uint64
	Key         []byte
	Headers     []byte
	Payload     []byte
}

// AppendDeliver encodes a DELIVER body onto dst (used by the conformance
// re-encode checks; the client only decodes deliveries).
func AppendDeliver(dst []byte, d *DeliverBody) ([]byte, error) {
	dst = binary.LittleEndian.AppendUint64(dst, d.Offset)
	dst = binary.LittleEndian.AppendUint64(dst, d.Generation)
	dst = append(dst, d.Flags)
	dst = binary.LittleEndian.AppendUint64(dst, d.TimestampMS)
	dst, err := appendVar(dst, d.Key)
	if err != nil {
		return dst, err
	}
	dst, err = appendVar(dst, d.Headers)
	if err != nil {
		return dst, err
	}
	return append(dst, d.Payload...), nil
}

// DecodeDeliver decodes a DELIVER body.
func DecodeDeliver(body []byte) (*DeliverBody, error) {
	r := &reader{buf: body}
	offset, err := r.u64()
	if err != nil {
		return nil, err
	}
	generation, err := r.u64()
	if err != nil {
		return nil, err
	}
	flags, err := r.u8()
	if err != nil {
		return nil, err
	}
	timestampMS, err := r.u64()
	if err != nil {
		return nil, err
	}
	key, err := r.varField()
	if err != nil {
		return nil, err
	}
	headers, err := r.varField()
	if err != nil {
		return nil, err
	}
	return &DeliverBody{
		Offset:      offset,
		Generation:  generation,
		Flags:       flags,
		TimestampMS: timestampMS,
		Key:         key,
		Headers:     headers,
		Payload:     r.rest(),
	}, nil
}

// DecodePubAck decodes the shared PubAck / PubAckDuplicate body: a fixed
// 8-byte LE offset. The frame tag alone distinguishes a fresh ack from a
// benign dedup hit.
func DecodePubAck(body []byte) (uint64, error) {
	if len(body) != 8 {
		if len(body) < 8 {
			return 0, ErrTruncated
		}
		return 0, ErrTrailingBytes
	}
	return binary.LittleEndian.Uint64(body), nil
}

// AppendPubAck encodes a PubAck body onto dst.
func AppendPubAck(dst []byte, offset uint64) []byte {
	return binary.LittleEndian.AppendUint64(dst, offset)
}

// AppendFlow encodes a Flow (per-record credit pull, tag 10) body onto dst:
// the credit grant as a fixed 4-byte LE u32. The response is a run of Deliver
// frames plus advisories terminated by one FlowEnd, byte-for-byte the Fetch
// response shape. Flow is the consume verb that routes through a named-stream
// binding (the batch Fetch polls the default stream only).
func AppendFlow(dst []byte, credit uint32) []byte {
	return binary.LittleEndian.AppendUint32(dst, credit)
}

// DecodeFlow decodes a Flow body (a fixed 4-byte LE u32 credit grant).
func DecodeFlow(body []byte) (uint32, error) {
	return DecodeFlowEnd(body)
}

// DecodeFlowEnd decodes a FlowEnd body: the batch's delivered count as a
// fixed 4-byte LE u32.
func DecodeFlowEnd(body []byte) (uint32, error) {
	if len(body) != 4 {
		if len(body) < 4 {
			return 0, ErrTruncated
		}
		return 0, ErrTrailingBytes
	}
	return binary.LittleEndian.Uint32(body), nil
}

// AppendFlowEnd encodes a FlowEnd body onto dst.
func AppendFlowEnd(dst []byte, count uint32) []byte {
	return binary.LittleEndian.AppendUint32(dst, count)
}

// AckStatus bytes carried in an AckStatus body (the response to an
// Ack/Nack/Term/Progress).
const (
	AckStatusFenced      = 0
	AckStatusCommitted   = 1
	AckStatusProgressCap = 2
)

// DecodeAckStatus decodes an AckStatus body: a one-byte status.
func DecodeAckStatus(body []byte) (byte, error) {
	if len(body) != 1 {
		if len(body) < 1 {
			return 0, ErrTruncated
		}
		return 0, ErrTrailingBytes
	}
	return body[0], nil
}

// DeadLetterBody is the in-band advisory that a message was dead-lettered and
// skipped from delivery (a fixed 9-byte layout).
type DeadLetterBody struct {
	Offset uint64
	Reason byte
}

// AppendDeadLetter encodes a DeadLetter body onto dst.
func AppendDeadLetter(dst []byte, d *DeadLetterBody) []byte {
	dst = binary.LittleEndian.AppendUint64(dst, d.Offset)
	return append(dst, d.Reason)
}

// DecodeDeadLetter decodes a DeadLetter body.
func DecodeDeadLetter(body []byte) (*DeadLetterBody, error) {
	r := &reader{buf: body}
	offset, err := r.u64()
	if err != nil {
		return nil, err
	}
	reason, err := r.u8()
	if err != nil {
		return nil, err
	}
	if !r.atEnd() {
		return nil, ErrTrailingBytes
	}
	return &DeadLetterBody{Offset: offset, Reason: reason}, nil
}

// TruncatedBody is the legacy truncation advisory: the consumer's cursor fell
// below the oldest retained record (a fixed 16-byte layout).
type TruncatedBody struct {
	EarliestRetained uint64
	Skipped          uint64
}

// AppendTruncated encodes a Truncated body onto dst.
func AppendTruncated(dst []byte, t *TruncatedBody) []byte {
	dst = binary.LittleEndian.AppendUint64(dst, t.EarliestRetained)
	return binary.LittleEndian.AppendUint64(dst, t.Skipped)
}

// DecodeTruncated decodes a Truncated body.
func DecodeTruncated(body []byte) (*TruncatedBody, error) {
	r := &reader{buf: body}
	earliest, err := r.u64()
	if err != nil {
		return nil, err
	}
	skipped, err := r.u64()
	if err != nil {
		return nil, err
	}
	if !r.atEnd() {
		return nil, ErrTrailingBytes
	}
	return &TruncatedBody{EarliestRetained: earliest, Skipped: skipped}, nil
}

// Gap reasons carried in a GapMarker body. An unknown value is tolerated by a
// reader as "absent for an unspecified reason", never an error.
const (
	GapReasonTrimmed   = 1
	GapReasonCompacted = 2
)

// GapMarkerBody is the opt-in richer twin of Truncated: the half-open offset
// span [From, To) is permanently absent from the deliver stream (a fixed
// 25-byte layout).
type GapMarkerBody struct {
	From         uint64
	To           uint64
	BytesSkipped uint64
	Reason       byte
}

// AppendGapMarker encodes a GapMarker body onto dst.
func AppendGapMarker(dst []byte, g *GapMarkerBody) []byte {
	dst = binary.LittleEndian.AppendUint64(dst, g.From)
	dst = binary.LittleEndian.AppendUint64(dst, g.To)
	dst = binary.LittleEndian.AppendUint64(dst, g.BytesSkipped)
	return append(dst, g.Reason)
}

// DecodeGapMarker decodes a GapMarker body. The reason byte is NOT validated
// (an unknown reason is a valid, tolerated marker).
func DecodeGapMarker(body []byte) (*GapMarkerBody, error) {
	r := &reader{buf: body}
	from, err := r.u64()
	if err != nil {
		return nil, err
	}
	to, err := r.u64()
	if err != nil {
		return nil, err
	}
	bytesSkipped, err := r.u64()
	if err != nil {
		return nil, err
	}
	reason, err := r.u8()
	if err != nil {
		return nil, err
	}
	if !r.atEnd() {
		return nil, ErrTrailingBytes
	}
	return &GapMarkerBody{From: from, To: to, BytesSkipped: bytesSkipped, Reason: reason}, nil
}

// CumulativeAckBody commits a BROADCAST group's cursor up to an exclusive
// offset. The group name is the remainder of the body (empty selects the
// default group).
type CumulativeAckBody struct {
	UpTo  uint64
	Group []byte
}

// AppendCumulativeAck encodes a CumulativeAck body onto dst.
func AppendCumulativeAck(dst []byte, c *CumulativeAckBody) []byte {
	dst = binary.LittleEndian.AppendUint64(dst, c.UpTo)
	return append(dst, c.Group...)
}

// DecodeCumulativeAck decodes a CumulativeAck body.
func DecodeCumulativeAck(body []byte) (*CumulativeAckBody, error) {
	r := &reader{buf: body}
	upTo, err := r.u64()
	if err != nil {
		return nil, err
	}
	return &CumulativeAckBody{UpTo: upTo, Group: r.rest()}, nil
}

// FetchBodyVersion is the version of the Fetch (batch-pull) body framing.
const FetchBodyVersion = 1

// FetchFlagNoWait marks the request no-wait: the server returns immediately
// with whatever records are ready.
const FetchFlagNoWait = 0b0000_0001

// fetchV1FieldLen is the Fetch v1 known-field block length:
// flags(u8) + max_records(u32) + max_bytes(u64) + expires_ms(u64).
const fetchV1FieldLen = 1 + 4 + 8 + 8

// FetchBody is a consumer batch-pull request draining up to MaxRecords /
// MaxBytes of deliverable records in one round-trip.
type FetchBody struct {
	MaxRecords uint32
	MaxBytes   uint64
	ExpiresMS  uint64
	NoWait     bool
}

// AppendFetch encodes a Fetch body onto dst.
func AppendFetch(dst []byte, f *FetchBody) []byte {
	dst = append(dst, FetchBodyVersion)
	dst = binary.LittleEndian.AppendUint16(dst, fetchV1FieldLen)
	var flags byte
	if f.NoWait {
		flags |= FetchFlagNoWait
	}
	dst = append(dst, flags)
	dst = binary.LittleEndian.AppendUint32(dst, f.MaxRecords)
	dst = binary.LittleEndian.AppendUint64(dst, f.MaxBytes)
	return binary.LittleEndian.AppendUint64(dst, f.ExpiresMS)
}

// DecodeFetch decodes a Fetch body.
func DecodeFetch(body []byte) (*FetchBody, error) {
	r := &reader{buf: body}
	version, err := r.u8()
	if err != nil {
		return nil, err
	}
	if version != FetchBodyVersion {
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
	flags, _ := fr.u8()
	maxRecords, _ := fr.u32()
	maxBytes, _ := fr.u64()
	expiresMS, _ := fr.u64()
	return &FetchBody{
		MaxRecords: maxRecords,
		MaxBytes:   maxBytes,
		ExpiresMS:  expiresMS,
		NoWait:     flags&FetchFlagNoWait != 0,
	}, nil
}

// NotLeaderBodyVersion is the version of the NotLeader redirect body.
const NotLeaderBodyVersion = 1

// AppendNotLeader encodes a NotLeader body onto dst: the version byte then the
// u16-length-prefixed leader-hint address.
func AppendNotLeader(dst []byte, leaderHint string) ([]byte, error) {
	dst = append(dst, NotLeaderBodyVersion)
	return appendVar(dst, []byte(leaderHint))
}

// DecodeNotLeader decodes a NotLeader body into its leader hint (empty when
// the current leader's client address is not yet known). An unknown future
// body version still carries the v1 address field first, and trailing bytes
// are tolerated, so the decode stays forward-compatible. A non-UTF-8 hint is
// rejected fail-closed, matching the Rust reference's String::from_utf8.
func DecodeNotLeader(body []byte) (string, error) {
	r := &reader{buf: body}
	if _, err := r.u8(); err != nil {
		return "", err
	}
	hint, err := r.varField()
	if err != nil {
		return "", err
	}
	if !utf8.Valid(hint) {
		return "", ErrInvalidUTF8
	}
	return string(hint), nil
}
