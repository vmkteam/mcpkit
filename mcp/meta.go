package mcp

// The vocabulary of the per-request-metadata era: the headers the Streamable
// HTTP binding mirrors the body into, the reserved _meta keys they mirror, and
// the encoding a header value takes when it will not fit in one.
//
// It lives here, with the wire format, rather than with the server that
// enforces it: a client filling these in and a server checking them have to
// agree on every name, and the only way to keep that true is for there to be
// one list. mcptest fills them from here; the transport checks them from here.

import (
	"encoding/base64"
	"strings"
)

// Headers the Streamable HTTP binding mirrors the body into, so that a proxy
// can route a request without parsing it.
const (
	HeaderProtocolVersion = "Mcp-Protocol-Version"
	HeaderMethod          = "Mcp-Method"
	HeaderName            = "Mcp-Name"
)

// Reserved _meta keys of a request. The prefix io.modelcontextprotocol/ belongs
// to the specification, and an implementation may not invent keys under it.
const (
	MetaProtocolVersion    = "io.modelcontextprotocol/protocolVersion"
	MetaClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
	MetaClientInfo         = "io.modelcontextprotocol/clientInfo"
)

// MetaServerInfo is the reserved _meta key a result reports the server's
// identity under. It moved there in this revision, out of the body it used to
// share with the payload.
const MetaServerInfo = "io.modelcontextprotocol/serverInfo"

// Error codes this revision added. -32020..-32099 is the range the spec keeps
// for itself, and an implementation "MUST NOT emit any code from this sub-range
// that is not defined by this specification".
//
// CodeMissingRequiredClientCapability is defined here and never emitted: this
// server requires no capability of its clients. It is listed so that the range
// is documented in one place rather than rediscovered.
const (
	CodeHeaderMismatch                  = -32020
	CodeMissingRequiredClientCapability = -32021
	CodeUnsupportedProtocolVersion      = -32022
)

// The sentinel wrapping a header value that cannot be written as plain ASCII.
const (
	base64Prefix = "=?base64?"
	base64Suffix = "?="
)

// NamePathFor returns the path, inside the request body, to the value Mcp-Name
// mirrors for this method — or nil when the method carries no name and the
// header must not be sent.
//
// Three methods name a thing they act on, and each names it in its own field.
// Anything else sends no name at all, which is as much a rule as the three: a
// server compares the header to the body, and a header on a method that has no
// name in its body cannot match anything.
func NamePathFor(method string) []string {
	switch method {
	case "tools/call", "prompts/get":
		return []string{"params", "name"}
	case "resources/read":
		return []string{"params", "uri"}
	}
	return nil
}

// EncodeHeaderValue writes s as a header value, wrapping it in the Base64
// sentinel when it cannot be written plainly.
//
// A header carries visible ASCII and spaces in between, so a resource URI with
// non-ASCII characters, a name with a leading space or anything with a control
// character in it has to be encoded. Everything else travels as itself — the
// sentinel is unreadable in a log, and most names never need it.
func EncodeHeaderValue(s string) string {
	if plainHeaderValue(s) {
		return s
	}
	return base64Prefix + base64.StdEncoding.EncodeToString([]byte(s)) + base64Suffix
}

// DecodeHeaderValue unwraps the sentinel. A value without it is returned as is,
// which is what a server must do before comparing: "servers MUST decode an
// encoded Mcp-Name value before comparing it to the corresponding request body
// value".
func DecodeHeaderValue(s string) (string, error) {
	// The length check is not a formality: "=?base64?=" satisfies both HasPrefix
	// and HasSuffix on the same two characters, and the slice below would then
	// read s[9:8] and panic. The value comes from a header, so that was one
	// string away from taking the connection down.
	if len(s) < len(base64Prefix)+len(base64Suffix) ||
		!strings.HasPrefix(s, base64Prefix) || !strings.HasSuffix(s, base64Suffix) {
		return s, nil
	}
	raw, err := base64.StdEncoding.DecodeString(s[len(base64Prefix) : len(s)-len(base64Suffix)])
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// IsTextualMIME reports whether a MIME type names something that belongs in a
// JSON string rather than in a base64 blob. An empty type is treated as text:
// it is what a source says when it does not know, and a UTF-8 check beside this
// one decides the case anyway.
//
// It lives here because two packages need the same answer and neither may
// depend on the other: the catalogue deciding whether a file is worth reading
// for a description, and the transport deciding whether its bytes go in text or
// in blob.
func IsTextualMIME(mimeType string) bool {
	m := strings.ToLower(strings.TrimSpace(mimeType))
	if i := strings.IndexByte(m, ';'); i >= 0 { // strip ;charset=…
		m = strings.TrimSpace(m[:i])
	}
	switch {
	case m == "", strings.HasPrefix(m, "text/"):
		return true
	case strings.HasSuffix(m, "+json"), strings.HasSuffix(m, "+xml"), strings.HasSuffix(m, "+yaml"):
		return true
	}
	switch m {
	case "application/json", "application/xml", "application/yaml", "application/toml",
		"application/javascript", "application/sql", "application/x-sh":
		return true
	}
	return false
}

// plainHeaderValue reports whether s can be sent as itself: printable ASCII
// with no leading or trailing space, and not something that would be read back
// as the sentinel.
func plainHeaderValue(s string) bool {
	if s != strings.TrimSpace(s) || strings.HasPrefix(s, base64Prefix) {
		return false
	}
	for i := range len(s) {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
