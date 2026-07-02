package wire

import (
	"errors"
	"testing"
)

// TestDecodeNotLeaderRejectsInvalidUTF8 pins the fail-closed posture on a
// non-UTF-8 leader hint, matching the Rust reference's String::from_utf8.
func TestDecodeNotLeaderRejectsInvalidUTF8(t *testing.T) {
	body := []byte{NotLeaderBodyVersion, 2, 0, 0xff, 0xfe} // 2-byte hint, invalid UTF-8
	if _, err := DecodeNotLeader(body); !errors.Is(err, ErrInvalidUTF8) {
		t.Fatalf("decode not leader = %v, want ErrInvalidUTF8", err)
	}
}

// TestParseConnectAuthRejectsUnknownMechanism pins the dedicated typed error
// for an auth mechanism byte outside the Bearer/Password/Mtls vocabulary.
func TestParseConnectAuthRejectsUnknownMechanism(t *testing.T) {
	body := AppendConnect(nil, &ConnectBody{})
	body = append(body, ConnectAuthSectionMarker, 9, 0, 0) // mechanism 9, empty material
	_, _, err := ParseConnectAuth(body)
	var bad *BadAuthMechanismError
	if !errors.As(err, &bad) || bad.Mechanism != 9 {
		t.Fatalf("parse connect auth = %v, want *BadAuthMechanismError with mechanism 9", err)
	}
}
