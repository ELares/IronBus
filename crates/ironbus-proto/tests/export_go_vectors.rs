// SPDX-License-Identifier: MIT OR Apache-2.0
//! TEST-ONLY golden-frame vector exporter for the official Go SDK (#1021).
//!
//! Gated by the `IRONBUS_EXPORT_GO_VECTORS` environment variable: when it names a directory, this
//! test encodes one exemplar frame per client-relevant verb with the NORMATIVE ironbus-proto
//! encoders and writes `golden_vectors.json` — an array of `{name, kind, tag, reencode, frame_hex,
//! fields}` records — into that directory. The committed copy lives at
//! `sdk/go/internal/wire/testdata/golden_vectors.json`, where the Go conformance tests decode every
//! vector, compare the decoded fields, and re-encode it byte-identically. Without the environment
//! variable the test is a no-op success, so per-PR CI cost is zero.
//!
//! The vectors are the language-neutral wire contract: they are produced ONLY by these Rust
//! encoders (never hand-written hex), so a Go/Rust disagreement is always a Go bug or a deliberate,
//! reviewed wire change that regenerates the corpus.

use std::fmt::Write as _;

use ironbus_proto::frame::{encode_frame, FrameType};
use ironbus_proto::message::{
    append_connect_auth, encode_ack, encode_bind_subject, encode_connect, encode_cumulative_ack,
    encode_dead_letter, encode_deliver, encode_fetch, encode_gap_marker, encode_info,
    encode_not_leader, encode_pub, encode_pub_ack, encode_pub_subject, encode_pub_to,
    encode_stream_declare, encode_stream_info, encode_stream_info_response, encode_sub,
    encode_sub_subject, encode_sub_to, encode_truncated, gap_reason, pack_password_material,
    pub_ack_level, AckBody, AckLevel, AckOp, AuthCredential, AuthMechanism, BindSubjectBody,
    ConnectBody, CreditAdvert, CumulativeAckBody, DeadLetterBody, DeliverBody, FetchBody,
    GapMarkerBody, InfoBody, NotLeaderBody, PubAckBody, PubBody, PubDedup, PubSubjectBody,
    PubToBody, StreamDeclareBody, StreamInfoBody, StreamInfoResponseBody, SubBody, SubSubjectBody,
    SubToBody, TruncatedBody, DEAD_LETTER_MAX_DELIVER, PUB_FLAG_ACK_LEVEL_SHIFT,
};

/// One exported vector: the frame bytes plus the decoded-fields JSON the Go test asserts against.
struct Vector {
    name: &'static str,
    /// The Go-side decode dispatch key (which body codec applies).
    kind: &'static str,
    frame_type: FrameType,
    body: Vec<u8>,
    /// The decoded fields as a JSON object string (hand-assembled; every string value is
    /// hex or controlled ASCII, so no escaping is ever needed).
    fields: String,
    /// Whether the Go test must re-encode the body byte-identically (false only for the
    /// historical EMPTY handshake bodies, whose canonical re-encoding is the non-empty v1 form).
    reencode: bool,
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing to a String is infallible.
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn opt_u32(v: Option<u32>) -> String {
    v.map_or_else(|| "null".to_owned(), |v| v.to_string())
}

fn opt_u8(v: Option<u8>) -> String {
    v.map_or_else(|| "null".to_owned(), |v| v.to_string())
}

/// A `u64` as a JSON STRING, so a value above 2^53 survives every JSON parser exactly.
fn u64s(v: u64) -> String {
    format!("\"{v}\"")
}

fn opt_u64s(v: Option<u64>) -> String {
    v.map_or_else(|| "null".to_owned(), u64s)
}

fn connect_fields(req: &ConnectBody, auth: Option<&AuthCredential>) -> String {
    let (mechanism, material) = match auth {
        Some(cred) => (
            cred.mechanism.as_u8().to_string(),
            format!("\"{}\"", hex(&cred.material)),
        ),
        None => ("null".to_owned(), "null".to_owned()),
    };
    format!(
        concat!(
            "{{\"requested_credit\":{},\"requested_credit_bytes\":{},\"wants_gap_marker\":{},",
            "\"default_ack_level\":{},\"understands_streaming\":{},\"default_tier\":{},",
            "\"understands_deliver_batch\":{},\"understands_streams\":{},",
            "\"understands_compressed_delivery\":{},",
            "\"auth_mechanism\":{},\"auth_material_hex\":{}}}"
        ),
        opt_u32(req.requested_credit),
        opt_u64s(req.requested_credit_bytes),
        req.wants_gap_marker,
        opt_u8(req.default_ack_level),
        req.understands_streaming,
        opt_u8(req.default_tier),
        req.understands_deliver_batch,
        req.understands_streams,
        req.understands_compressed_delivery,
        mechanism,
        material,
    )
}

fn info_fields(info: &InfoBody) -> String {
    let credit = info.credit.map_or_else(
        || "null".to_owned(),
        |c| format!("{{\"negotiated\":{},\"cap\":{}}}", c.negotiated, c.cap),
    );
    let credit_bytes = info.credit_bytes.map_or_else(
        || "null".to_owned(),
        |c| {
            format!(
                "{{\"negotiated\":{},\"cap\":{}}}",
                u64s(c.negotiated),
                u64s(c.cap)
            )
        },
    );
    format!(
        concat!(
            "{{\"credit\":{},\"credit_bytes\":{},\"gap_marker\":{},\"default_ack_level\":{},",
            "\"streaming\":{},\"default_tier\":{},\"deliver_batch\":{},\"streams\":{}}}"
        ),
        credit,
        credit_bytes,
        info.gap_marker,
        opt_u8(info.default_ack_level),
        info.streaming,
        opt_u8(info.default_tier),
        info.deliver_batch,
        info.streams,
    )
}

fn pub_fields(msg: &PubBody<'_>, wire_flags: u8) -> String {
    let dedup = msg.dedup.map_or_else(
        || "null".to_owned(),
        |d| {
            format!(
                "{{\"producer_id_hex\":\"{}\",\"epoch\":{},\"msg_id_hex\":\"{}\",\"seq\":{}}}",
                hex(d.producer_id),
                u64s(d.epoch),
                hex(d.msg_id),
                opt_u64s(d.seq),
            )
        },
    );
    format!(
        concat!(
            "{{\"flags\":{},\"timestamp_ms\":{},\"key_hex\":\"{}\",\"headers_hex\":\"{}\",",
            "\"fire_and_forget\":{},\"ack_level\":{},\"dedup\":{},\"payload_hex\":\"{}\"}}"
        ),
        wire_flags,
        u64s(msg.timestamp_ms),
        hex(msg.key),
        hex(msg.headers),
        msg.fire_and_forget,
        pub_ack_level(wire_flags).as_u8(),
        dedup,
        hex(msg.payload),
    )
}

fn deliver_fields(msg: &DeliverBody<'_>, uncompressed: Option<&[u8]>) -> String {
    let uncompressed =
        uncompressed.map_or_else(|| "null".to_owned(), |raw| format!("\"{}\"", hex(raw)));
    format!(
        concat!(
            "{{\"offset\":{},\"generation\":{},\"flags\":{},\"timestamp_ms\":{},",
            "\"key_hex\":\"{}\",\"headers_hex\":\"{}\",\"payload_hex\":\"{}\",",
            "\"payload_uncompressed_hex\":{}}}"
        ),
        u64s(msg.offset),
        u64s(msg.generation),
        msg.flags,
        u64s(msg.timestamp_ms),
        hex(msg.key),
        hex(msg.headers),
        hex(msg.payload),
        uncompressed,
    )
}

fn ack_fields(ack: &AckBody) -> String {
    format!(
        "{{\"op\":{},\"offset\":{},\"generation\":{},\"delay_ms\":{}}}",
        ack.op.as_u8(),
        u64s(ack.offset),
        u64s(ack.generation),
        u64s(ack.delay_ms),
    )
}

/// A PUB body every carrier vector (`PubTo` / `PubSubject`) embeds verbatim.
fn sample_pub_body() -> Vec<u8> {
    let msg = PubBody {
        flags: 0,
        timestamp_ms: 1_719_878_400_123,
        key: b"user-42",
        headers: b"",
        dedup: None,
        fire_and_forget: false,
        payload: b"hello ironbus",
    };
    let mut body = Vec::new();
    encode_pub(&msg, &mut body).expect("sample pub body encodes");
    body
}

/// A compressible payload well over the raw-store threshold, mirroring the
/// ironbus-core compress tests.
fn compressible(len: usize) -> Vec<u8> {
    b"ironbus telemetry record sensor.telemetry.v1 "
        .iter()
        .copied()
        .cycle()
        .take(len)
        .collect()
}

/// Builds a stored compressed payload byte-for-byte the way `ironbus-core`'s
/// `compress_payload` does on the default lz4 path: the frozen 9-byte descriptor
/// (`codec_id = 1`, `dict_id = 0`, `uncompressed_len`) then the raw lz4 BLOCK stream.
fn lz4_stored(raw: &[u8]) -> Vec<u8> {
    let uncompressed_len = u32::try_from(raw.len()).expect("test payload fits u32");
    let mut stored = Vec::new();
    stored.push(1u8); // CODEC_ID_LZ4
    stored.extend_from_slice(&0u32.to_le_bytes()); // DICT_ID_NONE
    stored.extend_from_slice(&uncompressed_len.to_le_bytes());
    stored.extend_from_slice(&lz4_flex::block::compress(raw));
    stored
}

#[allow(clippy::too_many_lines, clippy::items_after_statements)] // one flat, declarative vector table per verb; splitting it would obscure the corpus
fn build_vectors() -> Vec<Vector> {
    let mut vectors: Vec<Vector> = Vec::new();
    fn push_into(
        vectors: &mut Vec<Vector>,
        name: &'static str,
        kind: &'static str,
        frame_type: FrameType,
        body: Vec<u8>,
        fields: String,
    ) {
        vectors.push(Vector {
            name,
            kind,
            frame_type,
            body,
            fields,
            reencode: true,
        });
    }
    macro_rules! push {
        ($($arg:expr),+ $(,)?) => {
            push_into(&mut vectors, $($arg),+)
        };
    }

    // ---- Connect (defaults / full options / bearer / password) ----
    let defaults = ConnectBody::default();
    let mut body = Vec::new();
    encode_connect(&defaults, &mut body);
    push!(
        "connect_defaults",
        "connect",
        FrameType::Connect,
        body,
        connect_fields(&defaults, None),
    );

    let full = ConnectBody {
        requested_credit: Some(4096),
        requested_credit_bytes: Some(1 << 20),
        wants_gap_marker: true,
        default_ack_level: Some(2),
        understands_streaming: true,
        default_tier: Some(1),
        understands_deliver_batch: true,
        understands_streams: true,
        understands_compressed_delivery: true,
        wants_subject_filter: false,
    };
    let mut body = Vec::new();
    encode_connect(&full, &mut body);
    push!(
        "connect_full_options",
        "connect",
        FrameType::Connect,
        body,
        connect_fields(&full, None),
    );

    let mvp = ConnectBody {
        wants_gap_marker: true,
        understands_streams: true,
        ..ConnectBody::default()
    };
    let bearer = AuthCredential {
        mechanism: AuthMechanism::Bearer,
        material: b"s3cr3t-bearer-token".to_vec(),
    };
    let mut body = Vec::new();
    encode_connect(&mvp, &mut body);
    append_connect_auth(&mut body, &bearer).expect("bearer auth appends");
    push!(
        "connect_bearer",
        "connect",
        FrameType::Connect,
        body,
        connect_fields(&mvp, Some(&bearer)),
    );

    let password = AuthCredential {
        mechanism: AuthMechanism::Password,
        material: pack_password_material(b"svc-producer", b"correct horse battery")
            .expect("password material packs"),
    };
    let mut body = Vec::new();
    encode_connect(&mvp, &mut body);
    append_connect_auth(&mut body, &password).expect("password auth appends");
    push!(
        "connect_password",
        "connect",
        FrameType::Connect,
        body,
        connect_fields(&mvp, Some(&password)),
    );

    // ---- Info (an advertising server, and the historical empty body) ----
    let info = InfoBody {
        credit: Some(CreditAdvert {
            negotiated: 2048,
            cap: 8192,
        }),
        credit_bytes: Some(CreditAdvert {
            negotiated: 1 << 20,
            cap: 1 << 26,
        }),
        gap_marker: true,
        default_ack_level: Some(1),
        streaming: false,
        default_tier: Some(0),
        deliver_batch: false,
        streams: true,
    };
    let mut body = Vec::new();
    encode_info(&info, &mut body);
    push!(
        "info_advertised",
        "info",
        FrameType::Info,
        body,
        info_fields(&info),
    );
    vectors.push(Vector {
        name: "info_empty_old_server",
        kind: "info",
        frame_type: FrameType::Info,
        body: Vec::new(),
        fields: info_fields(&InfoBody::default()),
        // The empty body is the historical old-server case; its canonical
        // re-encoding is the non-empty v1 form, so byte-identity does not apply.
        reencode: false,
    });

    // ---- Pub (plain / dedup / dedup+seq / fire-and-forget / ack levels) ----
    let plain = PubBody {
        flags: 0,
        timestamp_ms: 1_719_878_400_123,
        key: b"user-42",
        headers: b"",
        dedup: None,
        fire_and_forget: false,
        payload: b"hello ironbus",
    };
    let mut body = Vec::new();
    encode_pub(&plain, &mut body).expect("plain pub encodes");
    let wire_flags = body[0];
    push!(
        "pub_plain",
        "pub",
        FrameType::Pub,
        body,
        pub_fields(&plain, wire_flags),
    );

    let dedup = PubBody {
        dedup: Some(PubDedup {
            producer_id: b"producer-A",
            epoch: 7,
            msg_id: b"msg-0001",
            seq: None,
        }),
        ..plain
    };
    let mut body = Vec::new();
    encode_pub(&dedup, &mut body).expect("dedup pub encodes");
    let wire_flags = body[0];
    push!(
        "pub_dedup",
        "pub",
        FrameType::Pub,
        body,
        pub_fields(&dedup, wire_flags),
    );

    let dedup_seq = PubBody {
        dedup: Some(PubDedup {
            producer_id: b"producer-A",
            epoch: 7,
            msg_id: b"msg-0002",
            seq: Some(42),
        }),
        ..plain
    };
    let mut body = Vec::new();
    encode_pub(&dedup_seq, &mut body).expect("dedup+seq pub encodes");
    let wire_flags = body[0];
    push!(
        "pub_dedup_seq",
        "pub",
        FrameType::Pub,
        body,
        pub_fields(&dedup_seq, wire_flags),
    );

    let faf = PubBody {
        fire_and_forget: true,
        ..plain
    };
    let mut body = Vec::new();
    encode_pub(&faf, &mut body).expect("faf pub encodes");
    let wire_flags = body[0];
    push!(
        "pub_fire_and_forget",
        "pub",
        FrameType::Pub,
        body,
        pub_fields(&faf, wire_flags),
    );

    // Level 2 (server+client ack) rides the 2-bit ack-level field of the flags byte.
    let level2 = PubBody {
        flags: AckLevel::ServerAndClientAck.as_u8() << PUB_FLAG_ACK_LEVEL_SHIFT,
        ..plain
    };
    let mut body = Vec::new();
    encode_pub(&level2, &mut body).expect("level-2 pub encodes");
    let wire_flags = body[0];
    push!(
        "pub_ack_level2",
        "pub",
        FrameType::Pub,
        body,
        pub_fields(&level2, wire_flags),
    );

    // The Level-0 ALIAS encoding: level field 1 with the faf bit clear.
    let level0_alias = PubBody {
        flags: 1 << PUB_FLAG_ACK_LEVEL_SHIFT,
        ..plain
    };
    let mut body = Vec::new();
    encode_pub(&level0_alias, &mut body).expect("level-0-alias pub encodes");
    let wire_flags = body[0];
    push!(
        "pub_ack_level0_alias",
        "pub",
        FrameType::Pub,
        body,
        pub_fields(&level0_alias, wire_flags),
    );

    // ---- PubAck / PubAckDuplicate (the shared 8-byte-offset body) ----
    let mut body = Vec::new();
    encode_pub_ack(
        &PubAckBody {
            offset: 0x0123_4567_89AB_CDEF,
        },
        &mut body,
    );
    push!(
        "puback",
        "puback",
        FrameType::PubAck,
        body,
        format!("{{\"offset\":{}}}", u64s(0x0123_4567_89AB_CDEF)),
    );
    let mut body = Vec::new();
    encode_pub_ack(&PubAckBody { offset: 7 }, &mut body);
    push!(
        "puback_duplicate",
        "puback",
        FrameType::PubAckDuplicate,
        body,
        format!("{{\"offset\":{}}}", u64s(7)),
    );

    // ---- Sub / Unsub ----
    let mut body = Vec::new();
    encode_sub(&SubBody { group: b"workers" }, &mut body);
    push!(
        "sub",
        "sub",
        FrameType::Sub,
        body,
        format!("{{\"group_hex\":\"{}\"}}", hex(b"workers")),
    );
    push!(
        "unsub",
        "empty",
        FrameType::Unsub,
        Vec::new(),
        "{}".to_owned(),
    );

    // ---- Ack / Nack / Term / Progress (all ride the ACK frame, tag 8) ----
    for (name, ack) in [
        (
            "ack",
            AckBody {
                op: AckOp::Ack,
                offset: 5,
                generation: 3,
                delay_ms: 0,
            },
        ),
        (
            "nack_delay",
            AckBody {
                op: AckOp::Nack,
                offset: 6,
                generation: 3,
                delay_ms: 1500,
            },
        ),
        (
            "nack_no_delay",
            AckBody {
                op: AckOp::Nack,
                offset: 6,
                generation: 3,
                delay_ms: u64::MAX,
            },
        ),
        (
            "term",
            AckBody {
                op: AckOp::Term,
                offset: 9,
                generation: 4,
                delay_ms: 0,
            },
        ),
        (
            "progress",
            AckBody {
                op: AckOp::Progress,
                offset: 9,
                generation: 4,
                delay_ms: 0,
            },
        ),
    ] {
        let mut body = Vec::new();
        encode_ack(&ack, &mut body);
        push!(name, "ack", FrameType::Ack, body, ack_fields(&ack));
    }

    // ---- AckStatus ----
    push!(
        "ack_status_committed",
        "ack_status",
        FrameType::AckStatus,
        vec![1],
        "{\"status\":1}".to_owned(),
    );

    // ---- Fetch ----
    let fetch = FetchBody {
        max_records: 256,
        max_bytes: 1 << 20,
        expires_ms: 5000,
        no_wait: false,
    };
    let mut body = Vec::new();
    encode_fetch(&fetch, &mut body);
    push!(
        "fetch",
        "fetch",
        FrameType::Fetch,
        body,
        format!(
            "{{\"max_records\":256,\"max_bytes\":{},\"expires_ms\":{},\"no_wait\":false}}",
            u64s(1 << 20),
            u64s(5000)
        ),
    );
    let fetch_no_wait = FetchBody {
        max_records: 64,
        max_bytes: 0,
        expires_ms: 0,
        no_wait: true,
    };
    let mut body = Vec::new();
    encode_fetch(&fetch_no_wait, &mut body);
    push!(
        "fetch_no_wait",
        "fetch",
        FrameType::Fetch,
        body,
        format!(
            "{{\"max_records\":64,\"max_bytes\":{},\"expires_ms\":{},\"no_wait\":true}}",
            u64s(0),
            u64s(0)
        ),
    );

    // ---- Deliver (plain + lz4-compressed) ----
    let deliver = DeliverBody {
        offset: 9,
        generation: 2,
        flags: 0b10, // HAS_KEY
        timestamp_ms: 1_719_878_400_456,
        key: b"k1",
        headers: b"trace=abc",
        payload: b"payload-bytes",
    };
    let mut body = Vec::new();
    encode_deliver(&deliver, &mut body).expect("plain deliver encodes");
    push!(
        "deliver_plain",
        "deliver",
        FrameType::Deliver,
        body,
        deliver_fields(&deliver, None),
    );

    let raw = compressible(4096);
    let stored = lz4_stored(&raw);
    let compressed = DeliverBody {
        offset: 10,
        generation: 2,
        flags: 0b01, // COMPRESSED
        timestamp_ms: 1_719_878_400_789,
        key: b"",
        headers: b"",
        payload: &stored,
    };
    let mut body = Vec::new();
    encode_deliver(&compressed, &mut body).expect("compressed deliver encodes");
    push!(
        "deliver_compressed",
        "deliver",
        FrameType::Deliver,
        body,
        deliver_fields(&compressed, Some(&raw)),
    );

    // ---- Flow (the per-record credit pull the named-stream consume rides) ----
    push!(
        "flow",
        "flow",
        FrameType::Flow,
        64u32.to_le_bytes().to_vec(),
        "{\"credit\":64}".to_owned(),
    );

    // ---- FlowEnd ----
    push!(
        "flow_end",
        "flow_end",
        FrameType::FlowEnd,
        3u32.to_le_bytes().to_vec(),
        "{\"count\":3}".to_owned(),
    );

    // ---- CumulativeAck ----
    let mut body = Vec::new();
    encode_cumulative_ack(
        &CumulativeAckBody {
            up_to: 12345,
            group: b"analytics",
        },
        &mut body,
    );
    push!(
        "cumulative_ack",
        "cumulative_ack",
        FrameType::CumulativeAck,
        body,
        format!(
            "{{\"up_to\":{},\"group_hex\":\"{}\"}}",
            u64s(12345),
            hex(b"analytics")
        ),
    );

    // ---- Advisories: DeadLetter / Truncated / GapMarker ----
    let mut body = Vec::new();
    encode_dead_letter(
        &DeadLetterBody {
            offset: 42,
            reason: DEAD_LETTER_MAX_DELIVER,
        },
        &mut body,
    );
    push!(
        "dead_letter",
        "dead_letter",
        FrameType::DeadLetter,
        body,
        format!("{{\"offset\":{},\"reason\":0}}", u64s(42)),
    );

    let mut body = Vec::new();
    encode_truncated(
        &TruncatedBody {
            earliest_retained: 100,
            skipped: 25,
        },
        &mut body,
    );
    push!(
        "truncated",
        "truncated",
        FrameType::Truncated,
        body,
        format!(
            "{{\"earliest_retained\":{},\"skipped\":{}}}",
            u64s(100),
            u64s(25)
        ),
    );

    let mut body = Vec::new();
    encode_gap_marker(
        &GapMarkerBody {
            from: 10,
            to: 20,
            bytes_skipped: 4096,
            reason: gap_reason::TRIMMED,
        },
        &mut body,
    );
    push!(
        "gap_marker",
        "gap_marker",
        FrameType::GapMarker,
        body,
        format!(
            "{{\"from\":{},\"to\":{},\"bytes_skipped\":{},\"reason\":1}}",
            u64s(10),
            u64s(20),
            u64s(4096)
        ),
    );

    // ---- Streams verbs (declare / info request+response / pub-to / sub-to) ----
    let mut body = Vec::new();
    encode_stream_declare(
        &StreamDeclareBody {
            stream_id: b"orders",
        },
        &mut body,
    )
    .expect("stream declare encodes");
    push!(
        "stream_declare",
        "stream_declare",
        FrameType::StreamDeclare,
        body,
        format!("{{\"stream_id_hex\":\"{}\"}}", hex(b"orders")),
    );

    let mut body = Vec::new();
    encode_stream_info(
        &StreamInfoBody {
            stream_id: b"orders",
        },
        &mut body,
    )
    .expect("stream info request encodes");
    push!(
        "stream_info_request",
        "stream_info_request",
        FrameType::StreamInfo,
        body,
        format!("{{\"stream_id_hex\":\"{}\"}}", hex(b"orders")),
    );

    let mut body = Vec::new();
    encode_stream_info_response(
        &StreamInfoResponseBody {
            exists: true,
            head: 17,
        },
        &mut body,
    );
    push!(
        "stream_info_response",
        "stream_info_response",
        FrameType::StreamInfo,
        body,
        format!("{{\"exists\":true,\"head\":{}}}", u64s(17)),
    );

    let pub_body = sample_pub_body();
    let mut body = Vec::new();
    encode_pub_to(
        &PubToBody {
            stream_id: b"orders",
            pub_body: &pub_body,
        },
        &mut body,
    )
    .expect("pub-to encodes");
    push!(
        "pub_to",
        "pub_to",
        FrameType::PubTo,
        body,
        format!(
            "{{\"stream_id_hex\":\"{}\",\"pub_body_hex\":\"{}\"}}",
            hex(b"orders"),
            hex(&pub_body)
        ),
    );

    let mut body = Vec::new();
    encode_sub_to(
        &SubToBody {
            stream_id: b"orders",
            group: b"pickers",
        },
        &mut body,
    )
    .expect("sub-to encodes");
    push!(
        "sub_to",
        "sub_to",
        FrameType::SubTo,
        body,
        format!(
            "{{\"stream_id_hex\":\"{}\",\"group_hex\":\"{}\"}}",
            hex(b"orders"),
            hex(b"pickers")
        ),
    );

    // ---- Subject verbs (bind / pub-subject / sub-subject) ----
    let mut body = Vec::new();
    encode_bind_subject(
        &BindSubjectBody {
            stream_id: b"orders",
            pattern: b"order.>",
        },
        &mut body,
    )
    .expect("bind-subject encodes");
    push!(
        "bind_subject",
        "bind_subject",
        FrameType::BindSubject,
        body,
        format!(
            "{{\"stream_id_hex\":\"{}\",\"pattern_hex\":\"{}\"}}",
            hex(b"orders"),
            hex(b"order.>")
        ),
    );

    let mut body = Vec::new();
    encode_pub_subject(
        &PubSubjectBody {
            subject: b"order.us.created",
            pub_body: &pub_body,
        },
        &mut body,
    )
    .expect("pub-subject encodes");
    push!(
        "pub_subject",
        "pub_subject",
        FrameType::PubSubject,
        body,
        format!(
            "{{\"subject_hex\":\"{}\",\"pub_body_hex\":\"{}\"}}",
            hex(b"order.us.created"),
            hex(&pub_body)
        ),
    );

    let mut body = Vec::new();
    encode_sub_subject(
        &SubSubjectBody {
            subject: b"order.*.created",
            group: b"workers",
            filter_mode: 0,
        },
        &mut body,
    )
    .expect("sub-subject encodes");
    push!(
        "sub_subject",
        "sub_subject",
        FrameType::SubSubject,
        body,
        format!(
            "{{\"subject_hex\":\"{}\",\"group_hex\":\"{}\"}}",
            hex(b"order.*.created"),
            hex(b"workers")
        ),
    );

    // ---- NotLeader (with a hint, and the empty mid-failover hint) ----
    let mut body = Vec::new();
    encode_not_leader(
        &NotLeaderBody {
            leader_hint: "10.0.0.7:7777",
        },
        &mut body,
    )
    .expect("not-leader encodes");
    push!(
        "not_leader",
        "not_leader",
        FrameType::NotLeader,
        body,
        "{\"leader_hint\":\"10.0.0.7:7777\"}".to_owned(),
    );
    let mut body = Vec::new();
    encode_not_leader(&NotLeaderBody { leader_hint: "" }, &mut body)
        .expect("empty not-leader encodes");
    push!(
        "not_leader_empty_hint",
        "not_leader",
        FrameType::NotLeader,
        body,
        "{\"leader_hint\":\"\"}".to_owned(),
    );

    // ---- Err (coded + uncoded) ----
    let mut body = Vec::new();
    ironbus_proto::err::encode_err_body(Some("ERR_AT_CAPACITY"), "log at byte cap", &mut body);
    push!(
        "err_coded",
        "err",
        FrameType::Err,
        body,
        "{\"code\":\"ERR_AT_CAPACITY\",\"message\":\"log at byte cap\"}".to_owned(),
    );
    let mut body = Vec::new();
    ironbus_proto::err::encode_err_body(None, "malformed pub body", &mut body);
    push!(
        "err_uncoded",
        "err",
        FrameType::Err,
        body,
        "{\"code\":\"\",\"message\":\"malformed pub body\"}".to_owned(),
    );

    // ---- Bodyless verbs ----
    push!(
        "ping",
        "empty",
        FrameType::Ping,
        Vec::new(),
        "{}".to_owned(),
    );
    push!(
        "pong",
        "empty",
        FrameType::Pong,
        Vec::new(),
        "{}".to_owned(),
    );
    push!("ok", "empty", FrameType::Ok, Vec::new(), "{}".to_owned());

    vectors
}

#[test]
fn export_go_vectors() {
    // No-op unless the exporter is explicitly requested, so per-PR CI cost is zero.
    let Some(dir) = std::env::var_os("IRONBUS_EXPORT_GO_VECTORS") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    std::fs::create_dir_all(&dir).expect("vector output directory is creatable");

    let vectors = build_vectors();
    let mut json = String::from("[\n");
    for (i, v) in vectors.iter().enumerate() {
        let mut frame = Vec::new();
        encode_frame(v.frame_type, &v.body, &mut frame).expect("vector frame encodes");
        let _ = write!(
            json,
            concat!(
                "  {{\"name\":\"{}\",\"kind\":\"{}\",\"tag\":{},\"reencode\":{},",
                "\"frame_hex\":\"{}\",\"fields\":{}}}"
            ),
            v.name,
            v.kind,
            v.frame_type.as_u8(),
            v.reencode,
            hex(&frame),
            v.fields,
        );
        json.push_str(if i + 1 == vectors.len() { "\n" } else { ",\n" });
    }
    json.push_str("]\n");

    let path = dir.join("golden_vectors.json");
    std::fs::write(&path, json).expect("vector corpus is writable");
    println!(
        "exported {} golden vectors to {}",
        vectors.len(),
        path.display()
    );
}
