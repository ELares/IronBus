// SPDX-License-Identifier: MIT OR Apache-2.0
//! AUTHENTICATED CONNECT: presenting a bearer token or a username+password.
//!
//! An auth-enabled broker requires every connection to present a credential in its `Connect`
//! handshake. A client sets [`ClientConfig::credential`] and connects with [`Client::connect_with`];
//! the credential material is redacted in `Debug`, so logging a `ClientConfig` never leaks the secret.
//!
//! Two of the wire's mechanisms are shown:
//!   * **Bearer** — an opaque token ([`AuthCredential`] with [`AuthMechanism::Bearer`]).
//!   * **Password** — username + password, packed with [`pack_password_material`]
//!     ([`AuthMechanism::Password`]; the broker verifies it against an Argon2id hash).
//!
//! Start an auth-enabled broker and pass a matching token/password. Against a broker with auth
//! DISABLED the credential is simply ignored (the connect still succeeds), so this example is safe to
//! run either way; a WRONG credential against an auth-REQUIRED broker fails at connect with a server
//! error, which the example reports. See `docs/AUTHENTICATION.md` for broker-side setup.
//!
//! ```sh
//! # auth-enabled broker (illustrative — see docs/AUTHENTICATION.md for the real flags):
//! ironbus serve --data-dir /tmp/ironbus-data   # + your auth configuration
//! IRONBUS_TOKEN=the-bearer-token cargo run -p ironbus-client --example auth
//! cargo run -p ironbus-client --example auth -- 127.0.0.1:7777
//! ```

use ironbus_client::{
    pack_password_material, AuthCredential, AuthMechanism, Client, ClientConfig, ClientError,
};
use ironbus_proto::message::PubBody;

/// The broker address: the first CLI argument, else `IRONBUS_ADDR`, else the loopback default.
fn broker_addr() -> String {
    std::env::args()
        .nth(1)
        .or_else(|| std::env::var("IRONBUS_ADDR").ok())
        .unwrap_or_else(|| "127.0.0.1:7777".to_string())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = broker_addr();

    // A BEARER credential: an opaque token the broker checks. Sourced from the environment here so the
    // secret is never a literal in code or process args.
    let token =
        std::env::var("IRONBUS_TOKEN").unwrap_or_else(|_| "example-bearer-token".to_string());
    let bearer = AuthCredential {
        mechanism: AuthMechanism::Bearer,
        material: token.into_bytes(),
    };

    // A PASSWORD credential: username + password packed into the mechanism-specific material. The
    // broker verifies the password against an Argon2id hash server-side; the plaintext only ever
    // travels inside the (ideally TLS-wrapped) handshake.
    let _password = AuthCredential {
        mechanism: AuthMechanism::Password,
        material: pack_password_material(b"alice", b"correct horse battery staple")?,
    };

    // Present the credential in the handshake. `ClientConfig`'s Debug redacts the material, so this is
    // safe to log.
    let config = ClientConfig {
        credential: Some(bearer),
        ..ClientConfig::default()
    };
    println!(
        "connecting to {addr} with a bearer credential (config redacts the secret: {config:?})"
    );

    let mut client = match Client::connect_with(&addr, &config) {
        Ok(client) => client,
        // An auth-REQUIRED broker rejects a bad/absent credential at connect with a server error.
        // Report it rather than panicking — the fix is a valid credential, not a code change.
        Err(ClientError::Server(e)) => {
            eprintln!(
                "broker rejected the credential: {e} (is the token correct for this broker?)"
            );
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    // Authenticated: produce as usual. On an auth broker, whether this specific action is allowed
    // depends on the credential's granted scopes (see docs/AUTHENTICATION.md).
    let offset = client.produce(&PubBody {
        flags: 0,
        timestamp_ms: now_ms(),
        key: b"",
        headers: b"",
        dedup: None,
        fire_and_forget: false,
        payload: b"authenticated-hello",
    })?;
    println!("authenticated connect OK; produced at offset {offset}");
    Ok(())
}
