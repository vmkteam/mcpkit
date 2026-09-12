// Package mcpkit is an MCP server for a Go service: the Streamable HTTP
// transport and the three zenrpc services every MCP server registers and none
// of them writes differently.
//
// Transport and handshake live together because neither stands up alone. A
// transport that answers POST but has no `initialize` is not an MCP server, and
// the services that answer `initialize` have nothing to be served over. The
// line between them ran along a technology — HTTP on one side, JSON-RPC on the
// other — and not along a question a consumer answers for itself.
//
// # The transport
//
// The server is stateless: it speaks several protocol revisions, accepts
// `initialize` from older clients and answers with a revision they understand,
// but never issues or requires Mcp-Session-Id. The 2026-07-28 revision removed
// sessions outright, and nothing here needs them — which also means there is no
// SSE resume and no drain to get wrong.
//
// One endpoint (/mcp by convention) accepts:
//
//	POST   — JSON-RPC 2.0 request, always synchronous JSON response.
//	GET    — 405: this server pushes nothing, so it offers no stream.
//	DELETE — session teardown, which a stateless server has nothing to do.
//
// Incoming method names that contain "/" (e.g. tools/list,
// notifications/initialized, resources/read) are rewritten to zenrpc-native "."
// form (tools.list, notifications.initialized, resources.read) before
// dispatching, so handlers are plain zenrpc services registered under the
// namespaces below.
//
// # The services
//
// InitService answers initialize and ping, ResourcesService and PromptsService
// serve a catalogue. Their sources are interfaces rather than a concrete store,
// so a service can keep its own catalogue; doc.Library satisfies both as is.
//
// Tools are not here. What a server can do is the reason it exists, and the
// "tools" namespace is registered by the service with its own code — mcptool
// has the dispatcher for it.
//
// # What this package does not know
//
// Nothing about authentication or rate limiting: the server is an http.Handler,
// and the caller decides what to wrap it with. Of the rest of mcpkit it uses
// only mcp, for the wire types and for the one rule that picks a revision.
package mcpkit

//go:generate go tool zenrpc

// Namespaces the MCP method names map onto after the transport rewrites the
// slash: tools/list arrives as tools.list.
const (
	NamespaceTools     = "tools"
	NamespaceResources = "resources"
	NamespacePrompts   = "prompts"
	// NamespaceServer carries server/discover, which the 2026-07-28 revision
	// requires of every server and which replaced the initialize handshake.
	NamespaceServer = "server"
)

// The two methods a client opens with, one per era. They are named here rather
// than spelt out where they are used, because two places have to agree on them:
// the handshake service that answers and the transport that recognises one.
const (
	MethodInitialize = "initialize"
	MethodDiscover   = NamespaceServer + "/discover"
)
