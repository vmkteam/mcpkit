package mcpkit

// The MCP Streamable HTTP transport on top of a zenrpc.Server. What it is and
// what it refuses is in the package comment; what follows is the handler.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/vmkteam/mcpkit/mcp"

	"github.com/valyala/fastjson"
	"github.com/vmkteam/embedlog"
	"github.com/vmkteam/zenrpc/v2"
)

// DefaultMaxRequestBytes caps the JSON-RPC request body when Options says
// nothing. MCP requests are tool/prompt arguments — KBs in practice. The limit
// prevents a client from forcing the server to allocate gigabytes through
// ReadAll plus the marshalling zenrpc does while decoding arguments.
const DefaultMaxRequestBytes = 4 << 20 // 4 MiB

// Options tunes the transport. The zero value is the production default.
type Options struct {
	// MaxRequestBytes caps the JSON-RPC request body; 0 takes
	// DefaultMaxRequestBytes.
	MaxRequestBytes int64
	// LogHandshake records one line per initialize: the revision the client
	// asks for, whether it sends the header, whether it carries a session id,
	// and who it claims to be. Off by default — it is a debugging aid, and one
	// line per connection is noise once the question it answers is answered.
	LogHandshake bool
	// AllowedOrigins lists the origins a browser may call this endpoint from.
	//
	// The empty list means "no browser clients", and any request that carries an
	// Origin at all is refused with 403. That is the strict reading of the
	// spec — "Servers MUST validate the Origin header on all incoming
	// connections to prevent DNS rebinding attacks" — and it costs an ordinary
	// client nothing: a caller outside a browser sends no Origin and never
	// reaches the check. "*" switches it off for a server that wants the old
	// behaviour.
	AllowedOrigins []string
	// AllowedHosts lists the Host header values this endpoint answers to, port
	// included: "mcp.example.com", "localhost:8075". The empty list — the
	// default — checks nothing.
	//
	// It closes a hole AllowedOrigins does not. In a DNS rebinding attack the
	// page at http://evil.com reaches http://evil.com:8075, which has just been
	// re-resolved to 127.0.0.1. To the browser that is the *same* origin, so no
	// Origin header is sent at all and the origin check has nothing to refuse.
	// Only the Host says what the client thought it was talking to.
	//
	// The default is off because in production the proxy in front already
	// answers this question — an nginx server_name is exactly this check — and a
	// strict default would refuse every deployment that had not listed its own
	// name. A server bound to a developer's loopback has no such proxy, and that
	// is the case worth filling in.
	AllowedHosts []string
}

// Server serves MCP traffic on top of a zenrpc.Server.
type Server struct {
	embedlog.Logger
	zsrv *zenrpc.Server
	opts Options
}

// NewServer wires an MCP transport on top of a configured zenrpc.Server with
// default options. The caller is responsible for registering the `tools`,
// `resources`, `prompts`, `notifications` namespaces and a root service
// handling initialize / ping.
func NewServer(zsrv *zenrpc.Server, sl embedlog.Logger) *Server {
	return NewServerWithOptions(zsrv, sl, Options{})
}

// NewServerWithOptions is NewServer with the knobs. It is a second constructor
// rather than a variadic argument on the first, because NewServer(zsrv, log) is
// the call every service already makes and options are the rare case.
func NewServerWithOptions(zsrv *zenrpc.Server, sl embedlog.Logger, opts Options) *Server {
	if opts.MaxRequestBytes <= 0 {
		opts.MaxRequestBytes = DefaultMaxRequestBytes
	}
	// Publish the refusal counter with every series at zero from the moment a
	// server exists, not from the first request that is turned away.
	registerMetrics()
	return &Server{zsrv: zsrv, Logger: sl, opts: opts}
}

// ServeHTTP routes MCP traffic.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Both asked first, before the method switch and before the body is read: a
	// page in somebody's browser reaching a server on their own machine is the
	// attack these checks exist for, and whether the body parses has nothing to
	// do with the answer.
	//
	// Host before Origin, because it is the one a rebound request cannot get
	// right: such a request carries no Origin at all.
	if !s.hostAllowed(r) {
		rejected(reasonHost)
		http.Error(w, "host not allowed", http.StatusForbidden)
		return
	}
	if !s.originAllowed(r) {
		rejected(reasonOrigin)
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}

	switch r.Method {
	case http.MethodPost:
		s.handlePOST(w, r)
	case http.MethodGet:
		s.handleGET(w, r)
	case http.MethodDelete:
		s.handleDELETE(w, r)
	default:
		rejected(reasonBadMethod)
		methodNotAllowed(w, "method not allowed")
	}
}

// methodNotAllowed answers 405 with the header the status is required to carry:
// "The origin server MUST generate an Allow header field in a 405 response"
// (RFC 9110 §15.5.6). A client is entitled to learn what it should have sent
// instead, and here the answer is always the same one method.
func methodNotAllowed(w http.ResponseWriter, message string) {
	w.Header().Set("Allow", http.MethodPost)
	http.Error(w, message, http.StatusMethodNotAllowed)
}

// hostAllowed reports whether the request may be served under the Host it
// names. An empty AllowedHosts checks nothing — see Options.
func (s *Server) hostAllowed(r *http.Request) bool {
	if len(s.opts.AllowedHosts) == 0 {
		return true
	}
	for _, allowed := range s.opts.AllowedHosts {
		// Case-insensitively, like the origin check: a host name is
		// case-insensitive, and a configured one differing only in case is the
		// same host.
		if allowed == "*" || strings.EqualFold(allowed, r.Host) {
			return true
		}
	}
	return false
}

// readRequest reads the one request a POST carries and parses it, answering
// the refusal itself when there is no such request to read.
func (s *Server) readRequest(w http.ResponseWriter, r *http.Request) (body []byte, v *fastjson.Value, ok bool) {
	r.Body = http.MaxBytesReader(w, r.Body, s.opts.MaxRequestBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			rejected(reasonTooLarge)
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return nil, nil, false
		}
		rejected(reasonReadBody)
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return nil, nil, false
	}

	// One request per POST. MCP dropped JSON-RPC batching in 2025-06-18, and
	// zenrpc would run the members of a batch in parallel while a rate limiter
	// in front counted the POST as one call — ten tool calls for the price of
	// one, on a limit that exists to stop exactly that.
	//
	// Asked before the parse, so a four-megabyte batch is refused without being
	// decoded first.
	if isBatch(body) {
		rejected(reasonBatch)
		http.Error(w, "JSON-RPC batches are not supported: send one request per POST", http.StatusBadRequest)
		return nil, nil, false
	}

	// One parse for the whole path. The three questions this handler asks of the
	// body — does the method carry a slash, is there an id, what did the client
	// say on initialize — used to be three more parses of the same bytes on top
	// of this one.
	v, err = fastjson.ParseBytes(body)
	if err != nil {
		rejected(reasonParse)
		http.Error(w, "parse jsonrpc: "+err.Error(), http.StatusBadRequest)
		return nil, nil, false
	}

	// A member named twice where this handler reads the request has no reading
	// that is safe to pick. fastjson, which answers every question asked here,
	// takes the first, and by exact bytes; encoding/json, which decodes the call
	// for zenrpc, takes the last, and without regard to case. Mcp-Name checked
	// against one name while the other runs is the very hole the header exists
	// to close.
	if repeatsKey(v) {
		rejected(reasonRepeatedKey)
		http.Error(w, "parse jsonrpc: a member is named twice", http.StatusBadRequest)
		return nil, nil, false
	}

	return body, v, true
}

func (s *Server) handlePOST(w http.ResponseWriter, r *http.Request) {
	body, v, ok := s.readRequest(w, r)
	if !ok {
		return
	}

	// A notification is a method that asks for no answer, and MCP names every
	// one of them notifications/…. Anything else without an id is a call whose
	// answer nobody will read, and zenrpc would run it detached, after this
	// handler has returned: outside the limiter's concurrency slot and past the
	// settling of its budget, so a tool called that way ran for free. "If the
	// server cannot accept the input, it MUST return an HTTP error status code."
	if isNotification(v) && !bytes.HasPrefix(v.GetStringBytes("method"), []byte("notifications/")) {
		rejected(reasonMissingID)
		http.Error(w, "a request needs an id: only notifications/* go without one", http.StatusBadRequest)
		return
	}

	// Which era this request speaks decides two things: whether the metadata it
	// carries is checked at all, and whether a JSON-RPC error gets an HTTP
	// status of its own. Asked before the rewrite, because it reads the method
	// as the client wrote it.
	modern := isModern(r, v)
	if modern {
		if f := validateModern(r, v); f != nil {
			rejected(f.reason)
			writeFault(w, v.Get("id"), *f)
			return
		}
	}
	dispatched(era(modern))

	patched := body
	if rewriteValue(v) {
		patched = v.MarshalTo(nil)
	}

	if s.opts.LogHandshake {
		s.logHandshake(r, v)
	}

	// Notifications (no ID, or a null one) short-circuit with 202 Accepted per
	// MCP spec.
	if isNotification(v) {
		// Dispatched on a context detached from the request's cancellation.
		// zenrpc runs a notification in a goroutine of its own and returns
		// before it has started; this handler then writes 202 and returns, and
		// net/http cancels r.Context() the moment it does. Everything the
		// handler might do with a context — a query, an outbound call, a span —
		// was therefore failing on a cancelled context, which is the opposite of
		// what "still dispatch so the side effects run" was meant to achieve.
		//
		// The values survive: the principal and the trace id are what the
		// handler needs. The deadline does not, because nobody is waiting for
		// this work and there is no one to report a timeout to — a notification
		// handler that can block owns its own bound.
		_, _ = s.zsrv.Do(context.WithoutCancel(r.Context()), patched)
		setProtocolVersion(w, r)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	resp, err := s.zsrv.Do(r.Context(), patched)
	if err != nil {
		// The text of a dispatch failure describes the inside of this server
		// and is of no use to the caller; the operator reads it in the log.
		rejected(reasonDispatch)
		s.Errorf("mcp dispatch failed: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	setProtocolVersion(w, r)
	// A legacy client reads every answer out of a 200 and would take a 404 for
	// "this endpoint is not here" — so the status is raised for modern requests
	// only, where the client uses it to tell a modern server from an old one.
	if modern {
		w.WriteHeader(statusForResponse(resp))
	}
	_, _ = w.Write(resp)
}

// era names the label a request is counted under.
func era(modern bool) string {
	if modern {
		return eraModern
	}
	return eraLegacy
}

// originAllowed reports whether a request carrying an Origin may proceed.
//
// A request without the header is not a browser request and passes: the header
// is set by the browser, not by the caller, so its absence is not something an
// attacker gains by omitting it — the page they control cannot suppress it.
func (s *Server) originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	for _, allowed := range s.opts.AllowedOrigins {
		// Compared case-insensitively: a scheme and host are case-insensitive,
		// and a configured origin that differs only in case is the same origin.
		if allowed == "*" || strings.EqualFold(allowed, origin) {
			return true
		}
	}
	return false
}

// handleGET refuses the server→client stream with 405, which the spec offers
// for exactly this case: a server that does not push notifications says so
// instead of opening a stream.
//
// Answering 200 with one ": connected" comment and closing is the worst of
// both: the client is told the stream exists, sees it die, and reconnects —
// once a second, forever. This server sends no server-initiated notifications,
// so saying no is the honest answer.
func (s *Server) handleGET(w http.ResponseWriter, r *http.Request) {
	// Counted like every other refusal. The failure this handler warns about —
	// a client that takes the stream for real and reconnects once a second
	// forever — is invisible unless the refusal it produces shows up somewhere,
	// and this counter is the somewhere.
	rejected(reasonBadMethod)
	setProtocolVersion(w, r)
	methodNotAllowed(w, "this server does not push notifications; POST your requests")
}

// handleDELETE answers the session-teardown call. A stateless server hands out
// no session to delete, and the spec's own answer for that case is 405 — which
// also tells an older client not to expect session semantics here.
func (s *Server) handleDELETE(w http.ResponseWriter, _ *http.Request) {
	rejected(reasonBadMethod)
	methodNotAllowed(w, "sessions are not used by this server")
}

// logHandshake records what a client actually says when it opens. Neither
// Claude Desktop nor Claude Code documents the revision it speaks, and the
// answer decides whether a stateless server is enough for it — so the only way
// to know is to write down what arrives. One line per connection, and only when
// Options.LogHandshake asks for it.
//
// Both openings count. A modern client never sends initialize — it goes
// straight to server/discover — so filtering on initialize alone made this
// option blind to exactly the era it was most needed for, which is the one
// nobody has measured yet. The two carry the same facts in different places:
// the older one in params, the newer one in params._meta.
func (s *Server) logHandshake(r *http.Request, v *fastjson.Value) {
	if v.Type() != fastjson.TypeObject {
		return
	}
	method := string(v.GetStringBytes("method"))
	if method != MethodInitialize && method != MethodDiscover {
		return
	}
	// Where the client's identity lives moved between the eras; read whichever
	// is filled rather than branching on the era a second time.
	clientName := string(v.GetStringBytes("params", "clientInfo", "name"))
	clientVersion := string(v.GetStringBytes("params", "clientInfo", "version"))
	askedVersion := string(v.GetStringBytes("params", "protocolVersion"))
	if clientName == "" {
		clientName = string(v.GetStringBytes("params", "_meta", mcp.MetaClientInfo, "name"))
		clientVersion = string(v.GetStringBytes("params", "_meta", mcp.MetaClientInfo, "version"))
	}
	if askedVersion == "" {
		askedVersion = metaString(v, mcp.MetaProtocolVersion)
	}

	s.Print(r.Context(), "mcp handshake",
		"method", method,
		"asked_version", askedVersion,
		"header_version", r.Header.Get("Mcp-Protocol-Version"),
		"sent_session_id", r.Header.Get("Mcp-Session-Id") != "",
		// Written down because the strict Origin default is only safe as long as
		// no client sends one, and that is a fact to observe rather than assume.
		"origin", r.Header.Get("Origin"),
		"client", clientName,
		"client_version", clientVersion,
		"user_agent", r.UserAgent(),
		// Only initialize negotiates. server/discover hands over the list and
		// lets the client pick, so there is no single answer to write down.
		"answered_version", answeredVersion(method, askedVersion),
	)
}

func answeredVersion(method, asked string) string {
	if method != MethodInitialize {
		return ""
	}
	return mcp.NegotiateVersion(asked)
}

// setProtocolVersion mirrors back the revision the client declared. Before the
// handshake the client declares nothing — the spec has it send the header only
// after initialize — and the initialize response carries the negotiated
// revision in its body. Answering with a header anyway would state a different
// revision than the body of the same response, which is how a strict client
// ends up disagreeing with us about what we just agreed on.
func setProtocolVersion(w http.ResponseWriter, r *http.Request) {
	if v := r.Header.Get("Mcp-Protocol-Version"); v != "" {
		w.Header().Set("Mcp-Protocol-Version", mcp.NegotiateVersion(v))
	}
}

// repeatsKey reports whether the request names a member twice in an object this
// handler reads: the envelope, its params, their _meta. Tool arguments are not
// among them — nothing here reads those, and only zenrpc decodes them.
//
// Twice as encoding/json counts, which matches a member to a field without
// regard to case, Unicode folding included: "name" and "Name", or "params" and
// "paramſ", are one member to the decoder behind and two to fastjson.
func repeatsKey(v *fastjson.Value) bool {
	for _, o := range [...]*fastjson.Value{v, v.Get("params"), v.Get("params", "_meta")} {
		if o != nil && o.Type() == fastjson.TypeObject && repeatsMember(o.GetObject()) {
			return true
		}
	}
	return false
}

// pairwiseMembers is how many members an object can have and still be checked
// by comparing every pair.
const pairwiseMembers = 16

// repeatsMember reports whether two members of o fold to the same name. An
// honest object holds a handful of members and is compared pair by pair, on
// fastjson's own bytes, without an allocation. A larger one is folded into a
// set: a megabyte of distinct members compared pairwise was seconds of CPU.
func repeatsMember(o *fastjson.Object) bool {
	repeated := false
	if o.Len() <= pairwiseMembers {
		var buf [pairwiseMembers][]byte
		seen := buf[:0]
		o.Visit(func(k []byte, _ *fastjson.Value) {
			for _, s := range seen {
				if bytes.EqualFold(s, k) {
					repeated = true
				}
			}
			seen = append(seen, k)
		})
		return repeated
	}

	seen := make(map[string]struct{}, o.Len())
	o.Visit(func(k []byte, _ *fastjson.Value) {
		f := foldName(k)
		if _, ok := seen[f]; ok {
			repeated = true
		}
		seen[f] = struct{}{}
	})
	return repeated
}

// foldName spells k the same way for every name bytes.EqualFold holds equal to
// it: each rune becomes the smallest of its fold orbit, as encoding/json folds.
func foldName(k []byte) string {
	b := make([]byte, 0, len(k))
	for len(k) > 0 {
		r, n := utf8.DecodeRune(k)
		k = k[n:]
		// SimpleFold walks the orbit upward and wraps around to its smallest.
		for next := unicode.SimpleFold(r); next > r; next = unicode.SimpleFold(r) {
			r = next
		}
		b = utf8.AppendRune(b, unicode.SimpleFold(r))
	}
	return string(b)
}

// isBatch reports whether the body is a JSON array — a batch, which this
// server refuses.
//
// The question is only which token opens the document, and the body is already
// parsed twice on this path; a third parse of a four-megabyte request to read
// one byte is work nobody asked for.
func isBatch(body []byte) bool {
	for _, c := range body {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		case '[':
			return true
		default:
			return false
		}
	}
	return false
}

// isNotification returns true for a JSON-RPC request with no usable `id`:
// either the field is absent, or it is null.
//
// The null case is not pedantry. JSON-RPC says an id "SHOULD normally not be
// Null", so implementations differ on it — and zenrpc already treats such a
// request as a notification and produces no response. When this function
// disagreed and called it a request, that empty response was written out as the
// bare literal `null` with a 200: neither a response object a client could
// match to its request nor the silence a notification earns. Agreeing with the
// dispatcher is what makes the answer one of the two.
func isNotification(v *fastjson.Value) bool {
	if v.Type() != fastjson.TypeObject {
		return false
	}
	id := v.Get("id")
	return id == nil || id.Type() == fastjson.TypeNull
}
