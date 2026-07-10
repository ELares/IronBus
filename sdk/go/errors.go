package ironbus

import (
	"errors"
	"fmt"
)

// ErrClosed reports an operation on a closed (or terminally broken) client.
var ErrClosed = errors.New("ironbus: client is closed")

// Stable machine-readable server rejection code tokens (the frozen ErrorCode
// spellings the broker tags an Err reply with). A ServerError's Code is one of
// these, or empty for an uncoded (legacy-shape) rejection or a token this SDK
// build predates.
const (
	ErrCodeAtCapacity              = "ERR_AT_CAPACITY"
	ErrCodeNotEnoughISR            = "ERR_NOT_ENOUGH_ISR"
	ErrCodeStorage                 = "ERR_STORAGE"
	ErrCodeProducerFenced          = "ERR_PRODUCER_FENCED"
	ErrCodeOutOfOrderSequence      = "ERR_OUT_OF_ORDER_SEQUENCE"
	ErrCodeCumulativeAckNotAllowed = "ERR_CUMULATIVE_ACK_NOT_ALLOWED"
	ErrCodeCumulativeAckOutOfRange = "ERR_CUMULATIVE_ACK_OUT_OF_RANGE"
	ErrCodeBroadcastGroupBusy      = "ERR_BROADCAST_GROUP_BUSY"
	ErrCodeBroadcastGroupNotNamed  = "ERR_BROADCAST_GROUP_NOT_NAMED"
	ErrCodeTooManyGroups           = "ERR_TOO_MANY_GROUPS"
	ErrCodeTooManyStreams          = "ERR_TOO_MANY_STREAMS"
	ErrCodeInvalidGroupName        = "ERR_INVALID_GROUP_NAME"
	ErrCodeInvalidStreamName       = "ERR_INVALID_STREAM_NAME"
	ErrCodeUnknownStream           = "ERR_UNKNOWN_STREAM"
	ErrCodeMirrorReadOnly          = "ERR_MIRROR_READ_ONLY"
	ErrCodeInvalidSubject          = "ERR_INVALID_SUBJECT"
	ErrCodeBindRejected            = "ERR_BIND_REJECTED"
	ErrCodeBindingTableFull        = "ERR_BINDING_TABLE_FULL"
	ErrCodeNoStreamForSubject      = "ERR_NO_STREAM_FOR_SUBJECT"
	ErrCodeAmbiguousSubject        = "ERR_AMBIGUOUS_SUBJECT"
	ErrCodeGenerationExhausted     = "ERR_GENERATION_EXHAUSTED"
	ErrCodeMissingRecord           = "ERR_MISSING_RECORD"
	ErrCodeZeroMaxInFlight         = "ERR_ZERO_MAX_IN_FLIGHT"
	ErrCodeTxn                     = "ERR_TXN"
	ErrCodeTxnCheckUnauthorized    = "ERR_TXN_CHECK_UNAUTHORIZED"
)

// ServerError is a typed broker rejection decoded from an Err (tag 12) frame:
// the optional stable machine-readable Code the broker tagged (branch on it
// for retry-vs-fail decisions instead of matching prose) plus the free-form
// human Message for display.
type ServerError struct {
	// Code is the stable token (for example ErrCodeAtCapacity), or empty for
	// an uncoded rejection.
	Code string
	// Message is the human-readable rejection text.
	Message string
}

func (e *ServerError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("ironbus: server error %s: %s", e.Code, e.Message)
	}
	return "ironbus: server error: " + e.Message
}

// NotLeaderError is the typed cluster NotLeader (tag 42) produce redirect: the
// node holds a replica of the target partition but is not its current leader.
// LeaderHint is the current leader's client-facing address, or empty when the
// node does not yet know it (mid-failover); the caller then re-discovers or
// retries its known peers.
type NotLeaderError struct {
	LeaderHint string
}

func (e *NotLeaderError) Error() string {
	if e.LeaderHint == "" {
		return "ironbus: not the partition leader (no leader hint yet)"
	}
	return "ironbus: not the partition leader (leader hint: " + e.LeaderHint + ")"
}

// UnknownFrameError is the TERMINAL error for a frame tag this client does not
// recognize. Per the frozen-wire contract an unrecognized server tag is
// treated as suspicious and ends the connection; it is never skipped.
type UnknownFrameError struct {
	Tag byte
}

func (e *UnknownFrameError) Error() string {
	return fmt.Sprintf("ironbus: unknown frame tag %d (terminal)", e.Tag)
}

// UnexpectedFrameError reports a known frame type that was not a valid reply
// to the request in flight (a request/response FIFO violation). It is terminal
// for the connection.
type UnexpectedFrameError struct {
	Tag byte
}

func (e *UnexpectedFrameError) Error() string {
	return fmt.Sprintf("ironbus: unexpected reply frame tag %d", e.Tag)
}

// InvalidAckLevelError reports a produce ack level outside the frozen 0/1/2
// spectrum. The wire carries the level in a 2-bit field, so an unknown level is
// rejected up front rather than silently encoded as a different level.
type InvalidAckLevelError struct {
	Level uint8
}

func (e *InvalidAckLevelError) Error() string {
	return fmt.Sprintf("ironbus: invalid produce ack level %d (valid levels: 0, 1, 2)", e.Level)
}

// BadResponseError reports a reply frame of the expected type whose body had a
// malformed shape for the request.
type BadResponseError struct {
	Reason string
}

func (e *BadResponseError) Error() string {
	return "ironbus: bad response: " + e.Reason
}
