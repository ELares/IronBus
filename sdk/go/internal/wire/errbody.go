package wire

import "unicode/utf8"

// codedSentinel marks a CODED Err body: a leading NUL that no uncoded human
// message ever begins with.
const codedSentinel = 0x00

// DecodeErrBody decodes an Err frame body into its optional stable code token
// and the human message, mirroring ironbus-proto's decode_err_body:
//
//   - UNCODED: [ message bytes... ]
//   - CODED:   [ 0x00 ][ code_len: u8 ][ code_token ][ message bytes... ]
//
// A malformed coded body falls back to treating the whole body as the message,
// so decode never errors. Code is the raw token spelling (for example
// "ERR_AT_CAPACITY"); empty means uncoded.
func DecodeErrBody(body []byte) (code string, message string) {
	if len(body) >= 2 && body[0] == codedSentinel {
		codeLen := int(body[1])
		if codeLen <= len(body)-2 {
			token := body[2 : 2+codeLen]
			if utf8.Valid(token) {
				return string(token), lossyString(body[2+codeLen:])
			}
			return "", lossyString(body[2+codeLen:])
		}
	}
	return "", lossyString(body)
}

// AppendErrBody encodes an Err body (used by the conformance re-encode
// checks). An empty token writes the raw message, byte-identical to the
// historical uncoded body.
func AppendErrBody(dst []byte, token, message string) []byte {
	if token != "" && len(token) <= 0xFF {
		dst = append(dst, codedSentinel, byte(len(token)))
		dst = append(dst, token...)
		return append(dst, message...)
	}
	return append(dst, message...)
}

// lossyString converts bytes to a string, replacing invalid UTF-8 sequences
// with the replacement character (the from_utf8_lossy twin).
func lossyString(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	out := make([]rune, 0, len(b))
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		out = append(out, r)
		b = b[size:]
	}
	return string(out)
}
