package ironbus

import (
	"fmt"
	"strings"
	"testing"
)

// TestCredentialRedaction pins the no-leak contract: no fmt verb over a
// Credential, or over a Config that carries one, may ever print the secret
// material (the bearer token or the password bytes).
func TestCredentialRedaction(t *testing.T) {
	const token = "bearer-secret-o8N2fQx7"
	const username = "svc-user"
	const password = "password-secret-Zq31xWm4"

	bearer, err := Bearer(token)
	if err != nil {
		t.Fatalf("bearer: %v", err)
	}
	pw, err := Password(username, password)
	if err != nil {
		t.Fatalf("password: %v", err)
	}

	cases := []struct {
		name   string
		value  any
		secret string
	}{
		{"bearer credential", bearer, token},
		{"password credential", pw, password},
		{"config with bearer", Config{Credential: bearer}, token},
		{"config with password", Config{Addr: "127.0.0.1:1", Credential: pw}, password},
	}
	// Every fmt verb, string-shaped or not. String/GoString cover only the
	// string verbs; a numeric verb like %d bypasses them and reflects into
	// the struct, so without fmt.Formatter the material would leak as decimal
	// (or hex) byte renderings. Each rendering is checked against the secret
	// in every encoding a reflected []byte could produce.
	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"}
	for _, tc := range cases {
		leaks := []string{
			tc.secret,
			fmt.Sprintf("%x", tc.secret),
			fmt.Sprintf("%X", tc.secret),
			strings.Trim(fmt.Sprint([]byte(tc.secret)), "[]"),
		}
		for _, verb := range verbs {
			for _, s := range []string{fmt.Sprintf(verb, tc.value), fmt.Sprint(tc.value)} {
				for _, leak := range leaks {
					if strings.Contains(s, leak) {
						t.Fatalf("%s leaks the secret via %s: %q", tc.name, verb, s)
					}
				}
			}
		}
	}

	// The direct formats advertise the redaction rather than printing junk.
	if s := fmt.Sprintf("%v", bearer); !strings.Contains(s, "redacted") {
		t.Fatalf("bearer String() = %q, want a <redacted> marker", s)
	}
	if s := fmt.Sprintf("%#v", pw); !strings.Contains(s, "redacted") {
		t.Fatalf("password GoString() = %q, want a <redacted> marker", s)
	}
}
