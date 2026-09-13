package mcpkit

// server/discover: what the modern era asks instead of the handshake.

import (
	"github.com/vmkteam/mcpkit/mcp"

	"github.com/vmkteam/zenrpc/v2"
)

// DiscoverService handles the `server` namespace.
//
// It is a second service on the same InitDeps rather than another method on
// InitService, because the two belong to different eras and only one of them is
// a handshake: initialize opens a session that no longer exists, discover
// answers a question. Registering one without the other is a supported choice —
// a server for modern clients only registers just this.
type DiscoverService struct {
	zenrpc.Service
	deps InitDeps
}

// NewDiscoverService returns the service answering server/discover.
func NewDiscoverService(d InitDeps) DiscoverService {
	return DiscoverService{deps: d}
}

// Discover reports the revisions this server speaks, what it can do, and who it
// says it is.
//
// Unlike initialize it negotiates nothing: the client picks a revision from the
// list and sends it with every request, and a request naming one we do not
// speak is refused with -32022 rather than quietly served under another.
//
// serverInfo travels in _meta, which is where this revision moved it. It is
// self-reported and the spec says so plainly — display, logging and debugging,
// never a security decision.
//
//zenrpc:return supported revisions, capabilities and identity
func (s DiscoverService) Discover() (mcp.DiscoverResult, error) {
	return mcp.DiscoverResult{
		SupportedVersions: mcp.SupportedVersions,
		Capabilities:      s.deps.Capabilities,
		Instructions:      s.deps.Instructions,
		Meta:              &mcp.ResultMeta{ServerInfo: &s.deps.Info},
		CacheHint:         s.deps.CacheHint,
	}, nil
}
