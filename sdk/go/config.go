package ironbus

// DefaultAddr is the broker's default client listen address.
const DefaultAddr = "127.0.0.1:7777"

// Config configures a Connect. The zero value is usable: it dials DefaultAddr,
// requests no specific credit, and advertises the MVP capability set
// (gap markers and named-stream/subject addressing on; the Tier-S streaming
// and DeliverBatch capabilities are deliberately OFF in this SDK, so the
// server never sends a DeliverBatch frame).
type Config struct {
	// Addr is the broker address (host:port). Empty uses DefaultAddr.
	Addr string

	// RequestedCredit is the per-consumer message credit to request in the
	// Connect handshake, or nil to defer to the server default. The server
	// negotiates min(request, server cap); see Client.NegotiatedCredit.
	RequestedCredit *uint32

	// RequestedCreditBytes is the per-consumer byte budget to request, or nil
	// to defer to the server default.
	RequestedCreditBytes *uint64

	// DefaultAckLevel is the connection-wide default produce ack level to
	// request (0 = no ack, 1 = server ack, 2 = server+client ack), or nil to
	// defer to the server default.
	DefaultAckLevel *uint8

	// NoGapMarker opts OUT of the GapMarker capability: the connection then
	// receives the legacy Truncated advisory across skipped spans. The default
	// (false) advertises gap-marker support.
	NoGapMarker bool

	// NoStreams opts OUT of the named-stream and subject addressing verbs
	// (StreamDeclare/StreamInfo/PubTo/SubTo and BindSubject/PubSubject/
	// SubSubject). The default (false) advertises them.
	NoStreams bool

	// Credential is the optional connection-scoped auth credential (see
	// Bearer and Password). The zero value sends no auth section.
	Credential Credential
}
