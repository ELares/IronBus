package wire

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/pierrec/lz4/v4"
)

// Frozen compression codec ids carried in a compressed payload's descriptor.
const (
	CodecIDNone = 0
	CodecIDLZ4  = 1
	CodecIDZstd = 2
)

// DescriptorLen is the fixed length of a compressed record's descriptor:
// codec_id(u8) + dict_id(u32 LE) + uncompressed_len(u32 LE).
const DescriptorLen = 1 + 4 + 4

// MaxDecompressedBytes is the per-record decompressed-size cap (8 MiB),
// checked against the descriptor's claimed uncompressed_len BEFORE any
// allocation, then enforced again by decompressing into a buffer sized to
// exactly that length. Mirrors ironbus-core's DEFAULT_MAX_DECOMPRESSED_BYTES.
const MaxDecompressedBytes = 8 * 1024 * 1024

// Decompression errors.
var (
	// ErrTruncatedDescriptor reports a compressed payload shorter than its descriptor.
	ErrTruncatedDescriptor = errors.New("ironbus: compressed payload shorter than its descriptor")
	// ErrCorruptStream reports an lz4 stream that failed to decompress to exactly its claim.
	ErrCorruptStream = errors.New("ironbus: corrupt compressed stream")
	// ErrBadRawLength reports a none-codec descriptor whose stored length mismatched its claim.
	ErrBadRawLength = errors.New("ironbus: raw-codec stored length mismatches the descriptor claim")
)

// PoisonError reports a compressed record this client can never decode: an
// unknown codec id or an unresolvable dictionary id. The record is poison, not
// a connection fault.
type PoisonError struct {
	CodecID uint8
	DictID  uint32
}

func (e *PoisonError) Error() string {
	if e.DictID != 0 {
		return fmt.Sprintf("ironbus: poison record: unresolved dictionary id %d", e.DictID)
	}
	return fmt.Sprintf("ironbus: poison record: unknown compression codec %d", e.CodecID)
}

// TooLargeError reports a descriptor claiming a decompressed size over the cap
// (a decompression bomb), rejected before any allocation.
type TooLargeError struct {
	Claimed uint32
	Cap     uint32
}

func (e *TooLargeError) Error() string {
	return fmt.Sprintf("ironbus: claimed decompressed size %d exceeds the %d-byte cap", e.Claimed, e.Cap)
}

// DecompressPayload decodes a stored compressed payload (the payload bytes of
// a Deliver whose flags carry RecordFlagCompressed) back to the original raw
// payload, mirroring ironbus-core's decompress_payload with the NoDictionaries
// resolver: the descriptor is parsed, an unknown codec or a non-zero dict_id
// is poison, the claimed length is capped BEFORE allocation, and the lz4 BLOCK
// stream is decompressed into a buffer sized to exactly the claim.
func DecompressPayload(stored []byte, maxDecompressed uint32) ([]byte, error) {
	if len(stored) < DescriptorLen {
		return nil, ErrTruncatedDescriptor
	}
	codecID := stored[0]
	dictID := binary.LittleEndian.Uint32(stored[1:5])
	uncompressedLen := binary.LittleEndian.Uint32(stored[5:9])
	stream := stored[DescriptorLen:]
	if codecID != CodecIDNone && codecID != CodecIDLZ4 {
		return nil, &PoisonError{CodecID: codecID}
	}
	if dictID != 0 {
		return nil, &PoisonError{CodecID: codecID, DictID: dictID}
	}
	if uncompressedLen > maxDecompressed {
		return nil, &TooLargeError{Claimed: uncompressedLen, Cap: maxDecompressed}
	}
	outLen := int(uncompressedLen)
	if codecID == CodecIDNone {
		if len(stream) != outLen {
			return nil, ErrBadRawLength
		}
		out := make([]byte, outLen)
		copy(out, stream)
		return out, nil
	}
	out := make([]byte, outLen)
	written, err := lz4.UncompressBlock(stream, out)
	if err != nil || written != outLen {
		return nil, ErrCorruptStream
	}
	return out, nil
}
