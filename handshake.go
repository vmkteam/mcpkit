package mcpkit

// The MCP handshake: initialize and ping, the two calls a server answers before
// it is asked anything about itself.

import (
	"github.com/vmkteam/mcpkit/mcp"

	"github.com/vmkteam/zenrpc/v2"
)

// InitDeps is what the handshake answers with.
type InitDeps struct {
	Info         mcp.ServerInfo
	Capabilities mcp.Capabilities
	// Instructions is the text the model reads before its first call. It is the
	// service's voice, not the library's: everything the model must know about
	// this server and nothing it must not.
	Instructions string
	// CacheHint is how long a client may hold server/discover and who may hold
	// it. The zero value says "do not cache, and never share" — the only answer
	// a library can give for a catalogue whose rate of change it does not know.
	CacheHint mcp.CacheHint
}

// InitService handles the MCP root namespace: initialize and ping.
type InitService struct {
	zenrpc.Service
	deps InitDeps
}

// NewInitService returns the root service answering the handshake.
func NewInitService(d InitDeps) InitService {
	return InitService{deps: d}
}

// Initialize responds to the MCP initialize handshake. Capabilities and server
// info are fixed at startup; the protocol revision is negotiated down to one
// the client understands, so older clients keep working. No session id is
// issued — the 2026-07-28 revision dropped sessions.
//
// The revision is taken as a plain argument rather than through a params
// struct: MCP sends the handshake as a flat object, and a struct argument would
// make zenrpc look for a nested "params" key that no client sends. The other
// fields (capabilities, clientInfo) are ignored — unknown keys cost nothing.
//
// NB: no backticks in this comment, the generator inlines it into a
// backtick-quoted string literal.
//
//zenrpc:protocolVersion revision the client speaks
func (s InitService) Initialize(protocolVersion string) (mcp.InitializeResult, error) {
	return mcp.InitializeResult{
		ProtocolVersion: mcp.NegotiateVersion(protocolVersion),
		Capabilities:    s.deps.Capabilities,
		ServerInfo:      s.deps.Info,
		Instructions:    s.deps.Instructions,
	}, nil
}

// Ping responds to the MCP keep-alive with an empty object, per spec.
func (s InitService) Ping() (mcp.PingResult, error) {
	return mcp.PingResult{}, nil
}
