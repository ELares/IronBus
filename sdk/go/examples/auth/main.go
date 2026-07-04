// Command auth connects to a broker with an authentication credential — a
// bearer token or a username+password. An auth-enabled broker requires every
// connection to present one in the Connect handshake; the credential material is
// redacted in the Credential/Config String, so logging them never leaks the secret.
//
// The credential is sourced from the environment so the secret is never a literal
// in code or process args. Against a broker with auth DISABLED the credential is
// simply ignored and the connect still succeeds, so this example is safe to run
// either way; a WRONG credential against an auth-REQUIRED broker fails at connect
// with a *ServerError, which the example reports. See docs/AUTHENTICATION.md for
// broker-side setup.
//
// Start a broker (add your auth configuration for a real test):
//
//	ironbus serve --data-dir /tmp/ironbus-demo --addr 127.0.0.1:7777
//
// Then: IRONBUS_TOKEN=the-token go run ./examples/auth [-addr 127.0.0.1:7777]
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	ironbus "github.com/ELares/IronBus/sdk/go"
)

func main() {
	addr := flag.String("addr", ironbus.DefaultAddr, "broker address")
	flag.Parse()

	// A BEARER credential: an opaque token the broker checks. Bearer returns an
	// error only if the token exceeds the wire field cap.
	token := os.Getenv("IRONBUS_TOKEN")
	if token == "" {
		token = "example-bearer-token"
	}
	bearer, err := ironbus.Bearer(token)
	if err != nil {
		log.Fatalf("build bearer credential: %v", err)
	}

	// A PASSWORD credential: username + password, packed into the mechanism's
	// material. The broker verifies the password against an Argon2id hash; the
	// plaintext only travels inside the (ideally TLS-wrapped) handshake. Built here
	// to show the constructor — swap it into the Config below to use it instead.
	if _, err := ironbus.Password("alice", "correct horse battery staple"); err != nil {
		log.Fatalf("build password credential: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Present the credential in the handshake. The credential redacts its secret
	// when formatted, so this is safe to log.
	cfg := ironbus.Config{Addr: *addr, Credential: bearer}
	fmt.Printf("connecting to %s with a bearer credential (secret redacted: %v)\n", *addr, bearer)

	client, err := ironbus.Connect(ctx, cfg)
	if err != nil {
		// An auth-REQUIRED broker rejects a bad/absent credential at connect with a
		// server error. Report it rather than failing hard — the fix is a valid
		// credential, not a code change.
		var srv *ironbus.ServerError
		if errors.As(err, &srv) {
			fmt.Printf("broker rejected the credential: %v (is the token correct for this broker?)\n", srv)
			return
		}
		log.Fatalf("connect: %v", err)
	}
	defer client.Close()

	// Authenticated: produce as usual. On an auth broker, whether this specific
	// action is allowed depends on the credential's granted scopes.
	offset, err := client.Produce(ctx, &ironbus.Message{Payload: []byte("authenticated-hello")})
	if err != nil {
		log.Fatalf("produce: %v", err)
	}
	fmt.Printf("authenticated connect OK; produced at offset %d\n", offset)
}
