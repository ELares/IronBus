package ironbus

import (
	"fmt"
	"io"

	"github.com/ELares/IronBus/sdk/go/internal/wire"
)

// Credential is a connection-scoped authentication credential carried in the
// Connect handshake. The zero value means "no credential" (an anonymous
// connect, byte-identical to the historical wire).
//
// The secret material is deliberately unexported, and String, GoString, and
// Format (fmt.Formatter, which intercepts EVERY verb — including numeric ones
// like %d that bypass Stringer and reflect into the struct) are hand-written
// to REDACT it, so no fmt verb, logging, or error wrapping can ever leak a
// token or password.
type Credential struct {
	mechanism byte
	material  []byte
}

// Bearer builds a bearer-token credential: the raw token bytes travel in the
// Connect auth section (mechanism 1) and the server compares its SHA-256
// constant-time. Returns an error if the token exceeds the u16 wire field.
func Bearer(token string) (Credential, error) {
	if len(token) > 0xFFFF {
		return Credential{}, wire.ErrFieldTooLarge
	}
	return Credential{mechanism: wire.AuthMechanismBearer, material: []byte(token)}, nil
}

// Password builds a username+password credential: the two travel as
// u16-length-prefixed fields (username first) in the Connect auth section
// (mechanism 2) and the server verifies the password against its stored
// Argon2id hash. Returns an error if either field exceeds the u16 wire field.
func Password(username, password string) (Credential, error) {
	material, err := wire.PackPasswordMaterial([]byte(username), []byte(password))
	if err != nil {
		return Credential{}, err
	}
	return Credential{mechanism: wire.AuthMechanismPassword, material: material}, nil
}

// isSet reports whether the credential carries anything to send.
func (c Credential) isSet() bool {
	return c.mechanism != 0
}

// String redacts the secret: it never prints the material bytes.
func (c Credential) String() string {
	switch c.mechanism {
	case wire.AuthMechanismBearer:
		return "ironbus.Credential{mechanism: bearer, material: <redacted>}"
	case wire.AuthMechanismPassword:
		return "ironbus.Credential{mechanism: password, material: <redacted>}"
	case 0:
		return "ironbus.Credential{unset}"
	default:
		return "ironbus.Credential{material: <redacted>}"
	}
}

// GoString redacts the secret for %#v formatting, exactly like String.
func (c Credential) GoString() string {
	return c.String()
}

// Format implements fmt.Formatter, which takes priority over EVERY other
// formatting method for EVERY verb. String/GoString alone cover only the
// string-shaped verbs (%v, %s, %q, %x, %X, %#v); a numeric verb like %d
// bypasses them and reflects into the struct, printing the material bytes as
// decimals. Redacting here closes that last leak: every verb renders the
// redacted form.
func (c Credential) Format(f fmt.State, verb rune) {
	_, _ = io.WriteString(f, c.String())
}
