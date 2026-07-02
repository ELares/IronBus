package wire

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// vector mirrors one record of testdata/golden_vectors.json, the golden-frame
// corpus exported by the Rust reference encoders
// (crates/ironbus-proto/tests/export_go_vectors.rs). Every u64 field travels
// as a JSON STRING so values above 2^53 survive exactly.
type vector struct {
	Name     string          `json:"name"`
	Kind     string          `json:"kind"`
	Tag      byte            `json:"tag"`
	Reencode bool            `json:"reencode"`
	FrameHex string          `json:"frame_hex"`
	Fields   json.RawMessage `json:"fields"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "golden_vectors.json"))
	if err != nil {
		t.Fatalf("read golden vectors: %v", err)
	}
	var vs []vector
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatalf("parse golden vectors: %v", err)
	}
	if len(vs) == 0 {
		t.Fatal("golden vector corpus is empty")
	}
	return vs
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in vector: %v", err)
	}
	return b
}

func u64Field(t *testing.T, s string) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		t.Fatalf("bad u64 field %q: %v", s, err)
	}
	return v
}

func optU64Field(t *testing.T, s *string) *uint64 {
	t.Helper()
	if s == nil {
		return nil
	}
	v := u64Field(t, *s)
	return &v
}

func mustJSON(t *testing.T, raw json.RawMessage, into any) {
	t.Helper()
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("parse vector fields: %v", err)
	}
}

// TestGoldenVectors decodes every exported frame with the Go codecs, asserts
// the decoded fields match the Rust reference decode, then re-encodes the body
// and the envelope byte-identically.
func TestGoldenVectors(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			frame := mustHex(t, v.FrameHex)
			tag, body, consumed, _, err := DecodeFrame(frame)
			if err != nil {
				t.Fatalf("decode frame: %v", err)
			}
			if consumed != len(frame) {
				t.Fatalf("frame consumed %d of %d bytes", consumed, len(frame))
			}
			if tag != v.Tag {
				t.Fatalf("tag = %d, want %d", tag, v.Tag)
			}

			reencoded := checkBody(t, v, body)
			if !v.Reencode {
				return
			}
			if !bytes.Equal(reencoded, body) {
				t.Fatalf("body re-encode mismatch:\n got %x\nwant %x", reencoded, body)
			}
			reframed, err := AppendFrame(nil, tag, reencoded)
			if err != nil {
				t.Fatalf("re-encode frame: %v", err)
			}
			if !bytes.Equal(reframed, frame) {
				t.Fatalf("frame re-encode mismatch:\n got %x\nwant %x", reframed, frame)
			}
		})
	}
}

// checkBody decodes the body per the vector's kind, asserts every decoded
// field against the reference JSON, and returns the Go re-encoding.
func checkBody(t *testing.T, v vector, body []byte) []byte {
	t.Helper()
	switch v.Kind {
	case "connect":
		return checkConnect(t, v, body)
	case "info":
		return checkInfo(t, v, body)
	case "pub":
		return checkPub(t, v, body)
	case "puback":
		var f struct {
			Offset string `json:"offset"`
		}
		mustJSON(t, v.Fields, &f)
		offset, err := DecodePubAck(body)
		if err != nil {
			t.Fatalf("decode puback: %v", err)
		}
		if offset != u64Field(t, f.Offset) {
			t.Fatalf("offset = %d, want %s", offset, f.Offset)
		}
		return AppendPubAck(nil, offset)
	case "sub":
		var f struct {
			GroupHex string `json:"group_hex"`
		}
		mustJSON(t, v.Fields, &f)
		if !bytes.Equal(body, mustHex(t, f.GroupHex)) {
			t.Fatalf("sub group = %x, want %s", body, f.GroupHex)
		}
		return append([]byte(nil), body...)
	case "ack":
		var f struct {
			Op         byte   `json:"op"`
			Offset     string `json:"offset"`
			Generation string `json:"generation"`
			DelayMS    string `json:"delay_ms"`
		}
		mustJSON(t, v.Fields, &f)
		ack, err := DecodeAck(body)
		if err != nil {
			t.Fatalf("decode ack: %v", err)
		}
		want := AckBody{
			Op:         f.Op,
			Offset:     u64Field(t, f.Offset),
			Generation: u64Field(t, f.Generation),
			DelayMS:    u64Field(t, f.DelayMS),
		}
		if *ack != want {
			t.Fatalf("ack = %+v, want %+v", *ack, want)
		}
		return AppendAck(nil, ack)
	case "ack_status":
		var f struct {
			Status byte `json:"status"`
		}
		mustJSON(t, v.Fields, &f)
		status, err := DecodeAckStatus(body)
		if err != nil {
			t.Fatalf("decode ack status: %v", err)
		}
		if status != f.Status {
			t.Fatalf("status = %d, want %d", status, f.Status)
		}
		return []byte{status}
	case "fetch":
		var f struct {
			MaxRecords uint32 `json:"max_records"`
			MaxBytes   string `json:"max_bytes"`
			ExpiresMS  string `json:"expires_ms"`
			NoWait     bool   `json:"no_wait"`
		}
		mustJSON(t, v.Fields, &f)
		fetch, err := DecodeFetch(body)
		if err != nil {
			t.Fatalf("decode fetch: %v", err)
		}
		want := FetchBody{
			MaxRecords: f.MaxRecords,
			MaxBytes:   u64Field(t, f.MaxBytes),
			ExpiresMS:  u64Field(t, f.ExpiresMS),
			NoWait:     f.NoWait,
		}
		if *fetch != want {
			t.Fatalf("fetch = %+v, want %+v", *fetch, want)
		}
		return AppendFetch(nil, fetch)
	case "deliver":
		return checkDeliver(t, v, body)
	case "flow":
		var f struct {
			Credit uint32 `json:"credit"`
		}
		mustJSON(t, v.Fields, &f)
		credit, err := DecodeFlow(body)
		if err != nil {
			t.Fatalf("decode flow: %v", err)
		}
		if credit != f.Credit {
			t.Fatalf("credit = %d, want %d", credit, f.Credit)
		}
		return AppendFlow(nil, credit)
	case "flow_end":
		var f struct {
			Count uint32 `json:"count"`
		}
		mustJSON(t, v.Fields, &f)
		count, err := DecodeFlowEnd(body)
		if err != nil {
			t.Fatalf("decode flow end: %v", err)
		}
		if count != f.Count {
			t.Fatalf("count = %d, want %d", count, f.Count)
		}
		return AppendFlowEnd(nil, count)
	case "cumulative_ack":
		var f struct {
			UpTo     string `json:"up_to"`
			GroupHex string `json:"group_hex"`
		}
		mustJSON(t, v.Fields, &f)
		ca, err := DecodeCumulativeAck(body)
		if err != nil {
			t.Fatalf("decode cumulative ack: %v", err)
		}
		if ca.UpTo != u64Field(t, f.UpTo) || !bytes.Equal(ca.Group, mustHex(t, f.GroupHex)) {
			t.Fatalf("cumulative ack = %+v, want up_to %s group %s", ca, f.UpTo, f.GroupHex)
		}
		return AppendCumulativeAck(nil, ca)
	case "dead_letter":
		var f struct {
			Offset string `json:"offset"`
			Reason byte   `json:"reason"`
		}
		mustJSON(t, v.Fields, &f)
		dl, err := DecodeDeadLetter(body)
		if err != nil {
			t.Fatalf("decode dead letter: %v", err)
		}
		if dl.Offset != u64Field(t, f.Offset) || dl.Reason != f.Reason {
			t.Fatalf("dead letter = %+v, want offset %s reason %d", dl, f.Offset, f.Reason)
		}
		return AppendDeadLetter(nil, dl)
	case "truncated":
		var f struct {
			EarliestRetained string `json:"earliest_retained"`
			Skipped          string `json:"skipped"`
		}
		mustJSON(t, v.Fields, &f)
		tr, err := DecodeTruncated(body)
		if err != nil {
			t.Fatalf("decode truncated: %v", err)
		}
		if tr.EarliestRetained != u64Field(t, f.EarliestRetained) || tr.Skipped != u64Field(t, f.Skipped) {
			t.Fatalf("truncated = %+v, want %+v", tr, f)
		}
		return AppendTruncated(nil, tr)
	case "gap_marker":
		var f struct {
			From         string `json:"from"`
			To           string `json:"to"`
			BytesSkipped string `json:"bytes_skipped"`
			Reason       byte   `json:"reason"`
		}
		mustJSON(t, v.Fields, &f)
		g, err := DecodeGapMarker(body)
		if err != nil {
			t.Fatalf("decode gap marker: %v", err)
		}
		want := GapMarkerBody{
			From:         u64Field(t, f.From),
			To:           u64Field(t, f.To),
			BytesSkipped: u64Field(t, f.BytesSkipped),
			Reason:       f.Reason,
		}
		if *g != want {
			t.Fatalf("gap marker = %+v, want %+v", *g, want)
		}
		return AppendGapMarker(nil, g)
	case "stream_declare", "stream_info_request":
		var f struct {
			StreamIDHex string `json:"stream_id_hex"`
		}
		mustJSON(t, v.Fields, &f)
		var id []byte
		var err error
		if v.Kind == "stream_declare" {
			id, err = DecodeStreamDeclare(body)
		} else {
			id, err = DecodeStreamInfoRequest(body)
		}
		if err != nil {
			t.Fatalf("decode %s: %v", v.Kind, err)
		}
		if !bytes.Equal(id, mustHex(t, f.StreamIDHex)) {
			t.Fatalf("stream id = %x, want %s", id, f.StreamIDHex)
		}
		out, err := AppendStreamDeclare(nil, id)
		if err != nil {
			t.Fatalf("re-encode %s: %v", v.Kind, err)
		}
		return out
	case "stream_info_response":
		var f struct {
			Exists bool   `json:"exists"`
			Head   string `json:"head"`
		}
		mustJSON(t, v.Fields, &f)
		resp, err := DecodeStreamInfoResponse(body)
		if err != nil {
			t.Fatalf("decode stream info response: %v", err)
		}
		if resp.Exists != f.Exists || resp.Head != u64Field(t, f.Head) {
			t.Fatalf("stream info response = %+v, want %+v", resp, f)
		}
		return AppendStreamInfoResponse(nil, resp)
	case "pub_to", "pub_subject":
		var f struct {
			StreamIDHex string `json:"stream_id_hex"`
			SubjectHex  string `json:"subject_hex"`
			PubBodyHex  string `json:"pub_body_hex"`
		}
		mustJSON(t, v.Fields, &f)
		nameHex := f.StreamIDHex
		if v.Kind == "pub_subject" {
			nameHex = f.SubjectHex
		}
		inner, err := DecodePubTo(body)
		if err != nil {
			t.Fatalf("decode %s: %v", v.Kind, err)
		}
		if !bytes.Equal(inner.StreamID, mustHex(t, nameHex)) {
			t.Fatalf("name = %x, want %s", inner.StreamID, nameHex)
		}
		if !bytes.Equal(inner.PubBodyBytes, mustHex(t, f.PubBodyHex)) {
			t.Fatalf("pub body tail = %x, want %s", inner.PubBodyBytes, f.PubBodyHex)
		}
		// The verbatim tail must decode through the unchanged PUB codec.
		if _, err := DecodePub(inner.PubBodyBytes); err != nil {
			t.Fatalf("embedded pub body does not decode: %v", err)
		}
		out, err := AppendPubTo(nil, inner)
		if err != nil {
			t.Fatalf("re-encode %s: %v", v.Kind, err)
		}
		return out
	case "sub_to", "sub_subject":
		var f struct {
			StreamIDHex string `json:"stream_id_hex"`
			SubjectHex  string `json:"subject_hex"`
			GroupHex    string `json:"group_hex"`
		}
		mustJSON(t, v.Fields, &f)
		nameHex := f.StreamIDHex
		if v.Kind == "sub_subject" {
			nameHex = f.SubjectHex
		}
		st, err := DecodeSubTo(body)
		if err != nil {
			t.Fatalf("decode %s: %v", v.Kind, err)
		}
		if !bytes.Equal(st.StreamID, mustHex(t, nameHex)) || !bytes.Equal(st.Group, mustHex(t, f.GroupHex)) {
			t.Fatalf("%s = %+v, want name %s group %s", v.Kind, st, nameHex, f.GroupHex)
		}
		out, err := AppendSubTo(nil, st)
		if err != nil {
			t.Fatalf("re-encode %s: %v", v.Kind, err)
		}
		return out
	case "bind_subject":
		var f struct {
			StreamIDHex string `json:"stream_id_hex"`
			PatternHex  string `json:"pattern_hex"`
		}
		mustJSON(t, v.Fields, &f)
		b, err := DecodeBindSubject(body)
		if err != nil {
			t.Fatalf("decode bind subject: %v", err)
		}
		if !bytes.Equal(b.StreamID, mustHex(t, f.StreamIDHex)) || !bytes.Equal(b.Pattern, mustHex(t, f.PatternHex)) {
			t.Fatalf("bind subject = %+v, want %+v", b, f)
		}
		out, err := AppendBindSubject(nil, b)
		if err != nil {
			t.Fatalf("re-encode bind subject: %v", err)
		}
		return out
	case "not_leader":
		var f struct {
			LeaderHint string `json:"leader_hint"`
		}
		mustJSON(t, v.Fields, &f)
		hint, err := DecodeNotLeader(body)
		if err != nil {
			t.Fatalf("decode not leader: %v", err)
		}
		if hint != f.LeaderHint {
			t.Fatalf("leader hint = %q, want %q", hint, f.LeaderHint)
		}
		out, err := AppendNotLeader(nil, hint)
		if err != nil {
			t.Fatalf("re-encode not leader: %v", err)
		}
		return out
	case "err":
		var f struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		mustJSON(t, v.Fields, &f)
		code, message := DecodeErrBody(body)
		if code != f.Code || message != f.Message {
			t.Fatalf("err = (%q, %q), want (%q, %q)", code, message, f.Code, f.Message)
		}
		return AppendErrBody(nil, code, message)
	case "empty":
		if len(body) != 0 {
			t.Fatalf("expected an empty body, got %x", body)
		}
		return nil
	default:
		t.Fatalf("unknown vector kind %q", v.Kind)
		return nil
	}
}

type connectFields struct {
	RequestedCredit         *uint32 `json:"requested_credit"`
	RequestedCreditBytes    *string `json:"requested_credit_bytes"`
	WantsGapMarker          bool    `json:"wants_gap_marker"`
	DefaultAckLevel         *uint8  `json:"default_ack_level"`
	UnderstandsStreaming    bool    `json:"understands_streaming"`
	DefaultTier             *uint8  `json:"default_tier"`
	UnderstandsDeliverBatch bool    `json:"understands_deliver_batch"`
	UnderstandsStreams      bool    `json:"understands_streams"`
	AuthMechanism           *uint8  `json:"auth_mechanism"`
	AuthMaterialHex         *string `json:"auth_material_hex"`
}

func checkConnect(t *testing.T, v vector, body []byte) []byte {
	t.Helper()
	var f connectFields
	mustJSON(t, v.Fields, &f)
	c, err := DecodeConnect(body)
	if err != nil {
		t.Fatalf("decode connect: %v", err)
	}
	want := ConnectBody{
		RequestedCredit:         f.RequestedCredit,
		RequestedCreditBytes:    optU64Field(t, f.RequestedCreditBytes),
		WantsGapMarker:          f.WantsGapMarker,
		DefaultAckLevel:         f.DefaultAckLevel,
		UnderstandsStreaming:    f.UnderstandsStreaming,
		DefaultTier:             f.DefaultTier,
		UnderstandsDeliverBatch: f.UnderstandsDeliverBatch,
		UnderstandsStreams:      f.UnderstandsStreams,
	}
	assertOptU32(t, "requested_credit", c.RequestedCredit, want.RequestedCredit)
	assertOptU64(t, "requested_credit_bytes", c.RequestedCreditBytes, want.RequestedCreditBytes)
	assertOptU8(t, "default_ack_level", c.DefaultAckLevel, want.DefaultAckLevel)
	assertOptU8(t, "default_tier", c.DefaultTier, want.DefaultTier)
	if c.WantsGapMarker != want.WantsGapMarker ||
		c.UnderstandsStreaming != want.UnderstandsStreaming ||
		c.UnderstandsDeliverBatch != want.UnderstandsDeliverBatch ||
		c.UnderstandsStreams != want.UnderstandsStreams {
		t.Fatalf("connect capability bits = %+v, want %+v", c, want)
	}

	mech, material, err := ParseConnectAuth(body)
	if err != nil {
		t.Fatalf("parse connect auth: %v", err)
	}
	if f.AuthMechanism == nil {
		if mech != 0 {
			t.Fatalf("unexpected auth mechanism %d", mech)
		}
	} else {
		if mech != *f.AuthMechanism {
			t.Fatalf("auth mechanism = %d, want %d", mech, *f.AuthMechanism)
		}
		if !bytes.Equal(material, mustHex(t, *f.AuthMaterialHex)) {
			t.Fatalf("auth material = %x, want %s", material, *f.AuthMaterialHex)
		}
	}

	out := AppendConnect(nil, c)
	if f.AuthMechanism != nil {
		out, err = AppendConnectAuth(out, mech, material)
		if err != nil {
			t.Fatalf("re-append auth: %v", err)
		}
	}
	return out
}

type infoFields struct {
	Credit *struct {
		Negotiated uint32 `json:"negotiated"`
		Cap        uint32 `json:"cap"`
	} `json:"credit"`
	CreditBytes *struct {
		Negotiated string `json:"negotiated"`
		Cap        string `json:"cap"`
	} `json:"credit_bytes"`
	GapMarker       bool   `json:"gap_marker"`
	DefaultAckLevel *uint8 `json:"default_ack_level"`
	Streaming       bool   `json:"streaming"`
	DefaultTier     *uint8 `json:"default_tier"`
	DeliverBatch    bool   `json:"deliver_batch"`
	Streams         bool   `json:"streams"`
}

func checkInfo(t *testing.T, v vector, body []byte) []byte {
	t.Helper()
	var f infoFields
	mustJSON(t, v.Fields, &f)
	info, err := DecodeInfo(body)
	if err != nil {
		t.Fatalf("decode info: %v", err)
	}
	if (info.Credit == nil) != (f.Credit == nil) {
		t.Fatalf("credit presence = %v, want %v", info.Credit != nil, f.Credit != nil)
	}
	if f.Credit != nil && (info.Credit.Negotiated != f.Credit.Negotiated || info.Credit.Cap != f.Credit.Cap) {
		t.Fatalf("credit = %+v, want %+v", info.Credit, f.Credit)
	}
	if (info.CreditBytes == nil) != (f.CreditBytes == nil) {
		t.Fatalf("credit_bytes presence = %v, want %v", info.CreditBytes != nil, f.CreditBytes != nil)
	}
	if f.CreditBytes != nil &&
		(info.CreditBytes.Negotiated != u64Field(t, f.CreditBytes.Negotiated) ||
			info.CreditBytes.Cap != u64Field(t, f.CreditBytes.Cap)) {
		t.Fatalf("credit_bytes = %+v, want %+v", info.CreditBytes, f.CreditBytes)
	}
	assertOptU8(t, "default_ack_level", info.DefaultAckLevel, f.DefaultAckLevel)
	assertOptU8(t, "default_tier", info.DefaultTier, f.DefaultTier)
	if info.GapMarker != f.GapMarker || info.Streaming != f.Streaming ||
		info.DeliverBatch != f.DeliverBatch || info.Streams != f.Streams {
		t.Fatalf("info capability bits = %+v, want %+v", info, f)
	}
	return AppendInfo(nil, info)
}

type pubFields struct {
	Flags         byte   `json:"flags"`
	TimestampMS   string `json:"timestamp_ms"`
	KeyHex        string `json:"key_hex"`
	HeadersHex    string `json:"headers_hex"`
	FireAndForget bool   `json:"fire_and_forget"`
	AckLevel      uint8  `json:"ack_level"`
	Dedup         *struct {
		ProducerIDHex string  `json:"producer_id_hex"`
		Epoch         string  `json:"epoch"`
		MsgIDHex      string  `json:"msg_id_hex"`
		Seq           *string `json:"seq"`
	} `json:"dedup"`
	PayloadHex string `json:"payload_hex"`
}

func checkPub(t *testing.T, v vector, body []byte) []byte {
	t.Helper()
	var f pubFields
	mustJSON(t, v.Fields, &f)
	p, err := DecodePub(body)
	if err != nil {
		t.Fatalf("decode pub: %v", err)
	}
	if p.Flags != f.Flags {
		t.Fatalf("flags = %#x, want %#x", p.Flags, f.Flags)
	}
	if p.TimestampMS != u64Field(t, f.TimestampMS) {
		t.Fatalf("timestamp = %d, want %s", p.TimestampMS, f.TimestampMS)
	}
	if !bytes.Equal(p.Key, mustHex(t, f.KeyHex)) || !bytes.Equal(p.Headers, mustHex(t, f.HeadersHex)) {
		t.Fatalf("key/headers mismatch: %+v", p)
	}
	if p.FireAndForget != f.FireAndForget {
		t.Fatalf("fire_and_forget = %v, want %v", p.FireAndForget, f.FireAndForget)
	}
	if got := PubAckLevel(p.Flags); got != f.AckLevel {
		t.Fatalf("ack level = %d, want %d", got, f.AckLevel)
	}
	if (p.Dedup == nil) != (f.Dedup == nil) {
		t.Fatalf("dedup presence = %v, want %v", p.Dedup != nil, f.Dedup != nil)
	}
	if f.Dedup != nil {
		if !bytes.Equal(p.Dedup.ProducerID, mustHex(t, f.Dedup.ProducerIDHex)) ||
			p.Dedup.Epoch != u64Field(t, f.Dedup.Epoch) ||
			!bytes.Equal(p.Dedup.MsgID, mustHex(t, f.Dedup.MsgIDHex)) {
			t.Fatalf("dedup = %+v, want %+v", p.Dedup, f.Dedup)
		}
		assertOptU64(t, "seq", p.Dedup.Seq, optU64Field(t, f.Dedup.Seq))
	}
	if !bytes.Equal(p.Payload, mustHex(t, f.PayloadHex)) {
		t.Fatalf("payload = %x, want %s", p.Payload, f.PayloadHex)
	}
	out, err := AppendPub(nil, p)
	if err != nil {
		t.Fatalf("re-encode pub: %v", err)
	}
	return out
}

type deliverFields struct {
	Offset                 string  `json:"offset"`
	Generation             string  `json:"generation"`
	Flags                  byte    `json:"flags"`
	TimestampMS            string  `json:"timestamp_ms"`
	KeyHex                 string  `json:"key_hex"`
	HeadersHex             string  `json:"headers_hex"`
	PayloadHex             string  `json:"payload_hex"`
	PayloadUncompressedHex *string `json:"payload_uncompressed_hex"`
}

func checkDeliver(t *testing.T, v vector, body []byte) []byte {
	t.Helper()
	var f deliverFields
	mustJSON(t, v.Fields, &f)
	d, err := DecodeDeliver(body)
	if err != nil {
		t.Fatalf("decode deliver: %v", err)
	}
	if d.Offset != u64Field(t, f.Offset) || d.Generation != u64Field(t, f.Generation) ||
		d.Flags != f.Flags || d.TimestampMS != u64Field(t, f.TimestampMS) {
		t.Fatalf("deliver header mismatch: %+v", d)
	}
	if !bytes.Equal(d.Key, mustHex(t, f.KeyHex)) || !bytes.Equal(d.Headers, mustHex(t, f.HeadersHex)) {
		t.Fatalf("deliver key/headers mismatch: %+v", d)
	}
	if !bytes.Equal(d.Payload, mustHex(t, f.PayloadHex)) {
		t.Fatalf("deliver stored payload mismatch")
	}
	// A compressed delivery must transparently decompress back to the exact
	// raw payload the broker stored, through the same lz4 BLOCK path.
	if f.PayloadUncompressedHex != nil {
		if d.Flags&RecordFlagCompressed == 0 {
			t.Fatal("vector claims a compressed payload but the flag is clear")
		}
		raw, err := DecompressPayload(d.Payload, MaxDecompressedBytes)
		if err != nil {
			t.Fatalf("decompress payload: %v", err)
		}
		if !bytes.Equal(raw, mustHex(t, *f.PayloadUncompressedHex)) {
			t.Fatal("decompressed payload mismatch")
		}
	}
	out, err := AppendDeliver(nil, d)
	if err != nil {
		t.Fatalf("re-encode deliver: %v", err)
	}
	return out
}

func assertOptU8(t *testing.T, name string, got, want *uint8) {
	t.Helper()
	if (got == nil) != (want == nil) {
		t.Fatalf("%s presence = %v, want %v", name, got != nil, want != nil)
	}
	if got != nil && *got != *want {
		t.Fatalf("%s = %d, want %d", name, *got, *want)
	}
}

func assertOptU32(t *testing.T, name string, got, want *uint32) {
	t.Helper()
	if (got == nil) != (want == nil) {
		t.Fatalf("%s presence = %v, want %v", name, got != nil, want != nil)
	}
	if got != nil && *got != *want {
		t.Fatalf("%s = %d, want %d", name, *got, *want)
	}
}

func assertOptU64(t *testing.T, name string, got, want *uint64) {
	t.Helper()
	if (got == nil) != (want == nil) {
		t.Fatalf("%s presence = %v, want %v", name, got != nil, want != nil)
	}
	if got != nil && *got != *want {
		t.Fatalf("%s = %d, want %d", name, *got, *want)
	}
}
