package wire

import (
	"encoding/binary"
	"fmt"
)

// HandshakeBodyVersion is the version of the Connect/Info handshake body
// framing. Version 1 is the first non-empty layout; an EMPTY body is the
// historical all-absent case and stays valid.
const HandshakeBodyVersion = 1

// Connect flags byte bits (presence flags and capability bits).
const (
	ConnectFlagHasCredit               = 0b0000_0001
	ConnectFlagHasCreditBytes          = 0b0000_0010
	ConnectFlagWantsGapMarker          = 0b0000_0100
	ConnectFlagHasDefaultAckLevel      = 0b0000_1000
	ConnectFlagUnderstandsStreaming    = 0b0001_0000
	ConnectFlagHasDefaultTier          = 0b0010_0000
	ConnectFlagUnderstandsDeliverBatch = 0b0100_0000
	ConnectFlagUnderstandsStreams      = 0b1000_0000
)

// Info flags byte bits (the server's presence flags and capability echoes).
const (
	InfoFlagHasCredit          = 0b0000_0001
	InfoFlagHasCreditBytes     = 0b0000_0010
	InfoFlagGapMarker          = 0b0000_0100
	InfoFlagHasDefaultAckLevel = 0b0000_1000
	InfoFlagStreaming          = 0b0001_0000
	InfoFlagHasDefaultTier     = 0b0010_0000
	InfoFlagDeliverBatch       = 0b0100_0000
	InfoFlagStreams            = 0b1000_0000
)

// connectV1FieldLen is the Connect v1 known-field block length with NO appended
// bytes: flags(u8) + requested_credit(u32) + requested_credit_bytes(u64).
const connectV1FieldLen = 1 + 4 + 8

// infoV1FieldLen is the Info v1 known-field block length with NO appended
// bytes: flags(u8) + credit negotiated/cap (u32 each) + credit_bytes
// negotiated/cap (u64 each).
const infoV1FieldLen = 1 + 4 + 4 + 8 + 8

// ConnectBody is the client's handshake request. Optional fields use pointers:
// nil means "absent on the wire" (defer to the server default), which keeps
// byte-identity with the versioned field_len discipline.
type ConnectBody struct {
	RequestedCredit         *uint32
	RequestedCreditBytes    *uint64
	WantsGapMarker          bool
	DefaultAckLevel         *uint8
	UnderstandsStreaming    bool
	DefaultTier             *uint8
	UnderstandsDeliverBatch bool
	UnderstandsStreams      bool
}

// AppendConnect encodes a Connect body onto dst: the version byte, the u16
// field-block length, then the v1 block. The default_ack_level and
// default_tier bytes are each APPENDED to the block only when present, in that
// fixed order, and field_len grows by exactly the present bytes.
func AppendConnect(dst []byte, b *ConnectBody) []byte {
	dst = append(dst, HandshakeBodyVersion)
	fieldLen := uint16(connectV1FieldLen)
	if b.DefaultAckLevel != nil {
		fieldLen++
	}
	if b.DefaultTier != nil {
		fieldLen++
	}
	dst = binary.LittleEndian.AppendUint16(dst, fieldLen)
	var flags byte
	if b.RequestedCredit != nil {
		flags |= ConnectFlagHasCredit
	}
	if b.RequestedCreditBytes != nil {
		flags |= ConnectFlagHasCreditBytes
	}
	if b.WantsGapMarker {
		flags |= ConnectFlagWantsGapMarker
	}
	if b.DefaultAckLevel != nil {
		flags |= ConnectFlagHasDefaultAckLevel
	}
	if b.UnderstandsStreaming {
		flags |= ConnectFlagUnderstandsStreaming
	}
	if b.DefaultTier != nil {
		flags |= ConnectFlagHasDefaultTier
	}
	if b.UnderstandsDeliverBatch {
		flags |= ConnectFlagUnderstandsDeliverBatch
	}
	if b.UnderstandsStreams {
		flags |= ConnectFlagUnderstandsStreams
	}
	dst = append(dst, flags)
	var credit uint32
	if b.RequestedCredit != nil {
		credit = *b.RequestedCredit
	}
	dst = binary.LittleEndian.AppendUint32(dst, credit)
	var creditBytes uint64
	if b.RequestedCreditBytes != nil {
		creditBytes = *b.RequestedCreditBytes
	}
	dst = binary.LittleEndian.AppendUint64(dst, creditBytes)
	if b.DefaultAckLevel != nil {
		dst = append(dst, *b.DefaultAckLevel)
	}
	if b.DefaultTier != nil {
		dst = append(dst, *b.DefaultTier)
	}
	return dst
}

// DecodeConnect decodes a Connect body. An EMPTY body is the historical
// old-client case and decodes to the all-absent request. Bytes past the v1
// fields inside the declared block, and bytes after the whole block (the
// trailing auth zone), are tolerated and ignored here.
func DecodeConnect(body []byte) (*ConnectBody, error) {
	if len(body) == 0 {
		return &ConnectBody{}, nil
	}
	r := &reader{buf: body}
	version, err := r.u8()
	if err != nil {
		return nil, err
	}
	if version != HandshakeBodyVersion {
		return nil, &BadVersionError{Version: version}
	}
	fieldLen, err := r.u16()
	if err != nil {
		return nil, err
	}
	block, err := r.take(int(fieldLen))
	if err != nil {
		return nil, err
	}
	fr := &reader{buf: block}
	flags, _ := fr.u8()
	credit, _ := fr.u32()
	creditBytes, _ := fr.u64()
	out := &ConnectBody{
		WantsGapMarker:          flags&ConnectFlagWantsGapMarker != 0,
		UnderstandsStreaming:    flags&ConnectFlagUnderstandsStreaming != 0,
		UnderstandsDeliverBatch: flags&ConnectFlagUnderstandsDeliverBatch != 0,
		UnderstandsStreams:      flags&ConnectFlagUnderstandsStreams != 0,
	}
	if flags&ConnectFlagHasDefaultAckLevel != 0 {
		level, _ := fr.u8()
		out.DefaultAckLevel = &level
	}
	if flags&ConnectFlagHasDefaultTier != 0 {
		tier, _ := fr.u8()
		out.DefaultTier = &tier
	}
	if flags&ConnectFlagHasCredit != 0 {
		out.RequestedCredit = &credit
	}
	if flags&ConnectFlagHasCreditBytes != 0 {
		out.RequestedCreditBytes = &creditBytes
	}
	return out, nil
}

// Auth mechanism selector bytes (1/2/3, never 0 so a zero byte can never be
// mistaken for a present-but-default mechanism).
const (
	AuthMechanismBearer   = 1
	AuthMechanismPassword = 2
	AuthMechanismMtls     = 3
)

// BadAuthMechanismError reports an unknown Connect auth mechanism selector
// byte (only Bearer/Password/Mtls are defined).
type BadAuthMechanismError struct {
	Mechanism byte
}

func (e *BadAuthMechanismError) Error() string {
	return fmt.Sprintf("ironbus: unknown connect auth mechanism %d", e.Mechanism)
}

// ConnectAuthSectionMarker is the trailing-section marker byte that introduces
// an appended auth credential in the Connect body. The section layout is
// [marker:u8][mechanism:u8][material: u16-length-prefixed].
const ConnectAuthSectionMarker = 0xA7

// AppendConnectAuth appends a connection-scoped auth section to an
// ALREADY-ENCODED, non-empty Connect body.
func AppendConnectAuth(dst []byte, mechanism byte, material []byte) ([]byte, error) {
	dst = append(dst, ConnectAuthSectionMarker, mechanism)
	return appendVar(dst, material)
}

// PackPasswordMaterial packs a username and password into the Password
// mechanism's credential material: each u16-length-prefixed, username first.
func PackPasswordMaterial(username, password []byte) ([]byte, error) {
	out := make([]byte, 0, 4+len(username)+len(password))
	out, err := appendVar(out, username)
	if err != nil {
		return nil, err
	}
	return appendVar(out, password)
}

// ParseConnectAuth extracts the auth section from a raw Connect body, if one is
// present, mirroring ironbus-proto's parse_connect_auth. It returns
// (0, nil, nil) for the no-auth cases. Used by the conformance tests.
func ParseConnectAuth(body []byte) (mechanism byte, material []byte, err error) {
	if len(body) == 0 {
		return 0, nil, nil
	}
	r := &reader{buf: body}
	version, err := r.u8()
	if err != nil {
		return 0, nil, err
	}
	if version != HandshakeBodyVersion {
		return 0, nil, &BadVersionError{Version: version}
	}
	fieldLen, err := r.u16()
	if err != nil {
		return 0, nil, err
	}
	if _, err := r.take(int(fieldLen)); err != nil {
		return 0, nil, err
	}
	if r.atEnd() {
		return 0, nil, nil
	}
	marker, err := r.u8()
	if err != nil || marker != ConnectAuthSectionMarker {
		return 0, nil, err
	}
	mech, err := r.u8()
	if err != nil {
		return 0, nil, err
	}
	if mech != AuthMechanismBearer && mech != AuthMechanismPassword && mech != AuthMechanismMtls {
		return 0, nil, &BadAuthMechanismError{Mechanism: mech}
	}
	mat, err := r.varField()
	if err != nil {
		return 0, nil, err
	}
	return mech, mat, nil
}

// CreditAdvert32 is one advertised credit dimension of the Info body: the
// negotiated value for this connection and the server's hard cap.
type CreditAdvert32 struct {
	Negotiated uint32
	Cap        uint32
}

// CreditAdvert64 is the byte-budget twin of CreditAdvert32.
type CreditAdvert64 struct {
	Negotiated uint64
	Cap        uint64
}

// InfoBody is the server's handshake advertisement. Capability bools are the
// server's CONFIRMATIONS (the AND of both peers' capability bits).
type InfoBody struct {
	Credit          *CreditAdvert32
	CreditBytes     *CreditAdvert64
	GapMarker       bool
	DefaultAckLevel *uint8
	Streaming       bool
	DefaultTier     *uint8
	DeliverBatch    bool
	Streams         bool
}

// AppendInfo encodes an Info body onto dst (used by the conformance re-encode
// checks; the client only decodes Info).
func AppendInfo(dst []byte, b *InfoBody) []byte {
	dst = append(dst, HandshakeBodyVersion)
	fieldLen := uint16(infoV1FieldLen)
	if b.DefaultAckLevel != nil {
		fieldLen++
	}
	if b.DefaultTier != nil {
		fieldLen++
	}
	dst = binary.LittleEndian.AppendUint16(dst, fieldLen)
	var flags byte
	if b.Credit != nil {
		flags |= InfoFlagHasCredit
	}
	if b.CreditBytes != nil {
		flags |= InfoFlagHasCreditBytes
	}
	if b.GapMarker {
		flags |= InfoFlagGapMarker
	}
	if b.DefaultAckLevel != nil {
		flags |= InfoFlagHasDefaultAckLevel
	}
	if b.Streaming {
		flags |= InfoFlagStreaming
	}
	if b.DefaultTier != nil {
		flags |= InfoFlagHasDefaultTier
	}
	if b.DeliverBatch {
		flags |= InfoFlagDeliverBatch
	}
	if b.Streams {
		flags |= InfoFlagStreams
	}
	dst = append(dst, flags)
	var credit CreditAdvert32
	if b.Credit != nil {
		credit = *b.Credit
	}
	dst = binary.LittleEndian.AppendUint32(dst, credit.Negotiated)
	dst = binary.LittleEndian.AppendUint32(dst, credit.Cap)
	var creditBytes CreditAdvert64
	if b.CreditBytes != nil {
		creditBytes = *b.CreditBytes
	}
	dst = binary.LittleEndian.AppendUint64(dst, creditBytes.Negotiated)
	dst = binary.LittleEndian.AppendUint64(dst, creditBytes.Cap)
	if b.DefaultAckLevel != nil {
		dst = append(dst, *b.DefaultAckLevel)
	}
	if b.DefaultTier != nil {
		dst = append(dst, *b.DefaultTier)
	}
	return dst
}

// DecodeInfo decodes an Info body. An EMPTY body is the historical old-server
// case and decodes to the all-absent advertisement; trailing bytes past the
// declared block are a future version's fields, tolerated and ignored.
func DecodeInfo(body []byte) (*InfoBody, error) {
	if len(body) == 0 {
		return &InfoBody{}, nil
	}
	r := &reader{buf: body}
	version, err := r.u8()
	if err != nil {
		return nil, err
	}
	if version != HandshakeBodyVersion {
		return nil, &BadVersionError{Version: version}
	}
	fieldLen, err := r.u16()
	if err != nil {
		return nil, err
	}
	block, err := r.take(int(fieldLen))
	if err != nil {
		return nil, err
	}
	fr := &reader{buf: block}
	flags, _ := fr.u8()
	creditNegotiated, _ := fr.u32()
	creditCap, _ := fr.u32()
	creditBytesNegotiated, _ := fr.u64()
	creditBytesCap, _ := fr.u64()
	out := &InfoBody{
		GapMarker:    flags&InfoFlagGapMarker != 0,
		Streaming:    flags&InfoFlagStreaming != 0,
		DeliverBatch: flags&InfoFlagDeliverBatch != 0,
		Streams:      flags&InfoFlagStreams != 0,
	}
	if flags&InfoFlagHasDefaultAckLevel != 0 {
		level, _ := fr.u8()
		out.DefaultAckLevel = &level
	}
	if flags&InfoFlagHasDefaultTier != 0 {
		tier, _ := fr.u8()
		out.DefaultTier = &tier
	}
	if flags&InfoFlagHasCredit != 0 {
		out.Credit = &CreditAdvert32{Negotiated: creditNegotiated, Cap: creditCap}
	}
	if flags&InfoFlagHasCreditBytes != 0 {
		out.CreditBytes = &CreditAdvert64{Negotiated: creditBytesNegotiated, Cap: creditBytesCap}
	}
	return out, nil
}
