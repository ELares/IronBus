// Package wire implements the frozen IronBus wire protocol: the
// [len:u32 LE][tag:u8][body] frame envelope and the per-verb body codecs, ported
// byte-exactly from crates/ironbus-proto (the normative Rust implementation).
//
// Every multi-byte integer is little-endian and every variable-length field is
// u16-length-prefixed unless a codec documents otherwise. Decoders are
// cap-before-alloc: a hostile length prefix is rejected BEFORE any allocation.
// An unknown frame tag is a TERMINAL, connection-ending error for the client
// (never a forward-compatible skip); that policy lives in the client, this
// package only reports the raw tag.
package wire

import (
	"encoding/binary"
	"fmt"
)

// MaxFrameLen is the largest a single frame (type byte plus body) may be:
// 16 MiB plus 64 KiB of protocol overhead, sized for a max-size record payload
// plus its frame fields. A frame whose length prefix exceeds this is rejected
// without allocating. Mirrors ironbus-proto's MAX_FRAME_LEN.
const MaxFrameLen = 16*1024*1024 + 64*1024

// lenPrefix is the number of bytes in the length prefix.
const lenPrefix = 4

// The frozen one-byte frame tags this client understands (the client-relevant
// subset of the ironbus-proto FrameType vocabulary). The numbers are part of
// the frozen wire contract and never change.
const (
	TagConnect         = 1
	TagInfo            = 2
	TagPing            = 3
	TagPong            = 4
	TagPub             = 5
	TagSub             = 6
	TagUnsub           = 7
	TagAck             = 8
	TagNack            = 9
	TagFlow            = 10
	TagOk              = 11
	TagErr             = 12
	TagDeliver         = 13
	TagPubAck          = 14
	TagAckStatus       = 15
	TagFlowEnd         = 16
	TagDeadLetter      = 17
	TagTruncated       = 18
	TagCumulativeAck   = 19
	TagPubAckDuplicate = 20
	TagGapMarker       = 21
	TagProduceConfirm  = 22
	TagFetch           = 23
	TagStreamDeclare   = 28
	TagStreamInfo      = 29
	TagPubTo           = 30
	TagSubTo           = 31
	TagBindSubject     = 34
	TagPubSubject      = 35
	TagSubSubject      = 36
	TagNotLeader       = 42
)

// FrameError is a malformed frame envelope (a zero or over-cap length prefix).
type FrameError struct {
	// Len is the frame length that was attempted or seen (0 for an empty frame).
	Len uint64
}

func (e *FrameError) Error() string {
	if e.Len == 0 {
		return "ironbus: frame length prefix is zero"
	}
	return fmt.Sprintf("ironbus: frame length %d exceeds the %d-byte cap", e.Len, MaxFrameLen)
}

// AppendFrame encodes one frame (type tag plus body) onto the end of dst and
// returns the extended slice. The frame length (1 + len(body)) is validated
// against MaxFrameLen before anything is written.
func AppendFrame(dst []byte, tag byte, body []byte) ([]byte, error) {
	frameLen := uint64(1) + uint64(len(body))
	if frameLen > MaxFrameLen {
		return dst, &FrameError{Len: frameLen}
	}
	dst = binary.LittleEndian.AppendUint32(dst, uint32(frameLen))
	dst = append(dst, tag)
	dst = append(dst, body...)
	return dst, nil
}

// DecodeFrame decodes one frame from the front of input, validating the length
// prefix against MaxFrameLen BEFORE trusting it.
//
// When a complete frame is present it returns (tag, body, consumed, 0, nil);
// body aliases input (zero-copy) and consumed is the total bytes the frame
// occupied. When more bytes are needed it returns (0, nil, 0, needed, nil)
// where needed is the minimum total input length required to make progress.
// A zero or over-cap length prefix returns a *FrameError.
func DecodeFrame(input []byte) (tag byte, body []byte, consumed int, needed int, err error) {
	if len(input) < lenPrefix {
		return 0, nil, 0, lenPrefix, nil
	}
	frameLen := binary.LittleEndian.Uint32(input)
	if frameLen == 0 {
		return 0, nil, 0, 0, &FrameError{Len: 0}
	}
	if frameLen > MaxFrameLen {
		return 0, nil, 0, 0, &FrameError{Len: uint64(frameLen)}
	}
	total := lenPrefix + int(frameLen)
	if len(input) < total {
		return 0, nil, 0, total, nil
	}
	return input[lenPrefix], input[lenPrefix+1 : total], total, 0, nil
}
