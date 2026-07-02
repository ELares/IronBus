package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Body decode errors, mirroring ironbus-proto's BodyError variants. They are
// sentinel values so callers can branch with errors.Is.
var (
	// ErrTruncated reports a body shorter than a fixed field requires.
	ErrTruncated = errors.New("ironbus: body truncated")
	// ErrBadLength reports a length field inconsistent with the body (or over a wire cap).
	ErrBadLength = errors.New("ironbus: body length field inconsistent")
	// ErrTrailingBytes reports unexpected bytes after a fixed-layout body.
	ErrTrailingBytes = errors.New("ironbus: trailing bytes after body")
	// ErrFieldTooLarge reports a variable field longer than its u16 wire slot.
	ErrFieldTooLarge = errors.New("ironbus: field exceeds the u16 wire limit")
	// ErrInvalidUTF8 reports a string-typed wire field that is not valid
	// UTF-8 (rejected fail-closed, matching the Rust reference decoders).
	ErrInvalidUTF8 = errors.New("ironbus: string field is not valid UTF-8")
)

// BadVersionError reports an unknown body version byte.
type BadVersionError struct {
	Version byte
}

func (e *BadVersionError) Error() string {
	return fmt.Sprintf("ironbus: unknown body version %d", e.Version)
}

// BadAckOpError reports an unknown acknowledgement op byte.
type BadAckOpError struct {
	Op byte
}

func (e *BadAckOpError) Error() string {
	return fmt.Sprintf("ironbus: unknown ack op %d", e.Op)
}

// reader is a bounds-checked, panic-free cursor over a frame body, mirroring
// ironbus-proto's Reader. Returned slices alias the input (zero-copy).
type reader struct {
	buf []byte
	pos int
}

func (r *reader) u8() (byte, error) {
	if r.pos+1 > len(r.buf) {
		return 0, ErrTruncated
	}
	b := r.buf[r.pos]
	r.pos++
	return b, nil
}

func (r *reader) u16() (uint16, error) {
	if r.pos+2 > len(r.buf) {
		return 0, ErrTruncated
	}
	v := binary.LittleEndian.Uint16(r.buf[r.pos:])
	r.pos += 2
	return v, nil
}

func (r *reader) u32() (uint32, error) {
	if r.pos+4 > len(r.buf) {
		return 0, ErrTruncated
	}
	v := binary.LittleEndian.Uint32(r.buf[r.pos:])
	r.pos += 4
	return v, nil
}

func (r *reader) u64() (uint64, error) {
	if r.pos+8 > len(r.buf) {
		return 0, ErrTruncated
	}
	v := binary.LittleEndian.Uint64(r.buf[r.pos:])
	r.pos += 8
	return v, nil
}

// take returns the next n bytes, bounds-checked BEFORE any slice is formed so a
// hostile declared length is a typed error, never an over-read.
func (r *reader) take(n int) ([]byte, error) {
	if n < 0 || r.pos+n > len(r.buf) {
		return nil, ErrTruncated
	}
	s := r.buf[r.pos : r.pos+n]
	r.pos += n
	return s, nil
}

// varField reads a u16-length-prefixed variable field.
func (r *reader) varField() ([]byte, error) {
	n, err := r.u16()
	if err != nil {
		return nil, err
	}
	s, err := r.take(int(n))
	if err != nil {
		return nil, ErrBadLength
	}
	return s, nil
}

// rest returns everything not yet consumed.
func (r *reader) rest() []byte {
	return r.buf[r.pos:]
}

func (r *reader) atEnd() bool {
	return r.pos == len(r.buf)
}

// appendVar appends a u16-length-prefixed variable field to dst.
func appendVar(dst []byte, field []byte) ([]byte, error) {
	if len(field) > 0xFFFF {
		return dst, ErrFieldTooLarge
	}
	dst = binary.LittleEndian.AppendUint16(dst, uint16(len(field)))
	return append(dst, field...), nil
}
