// Package mcptest drives an MCP server the way a client would, so that a
// service can test the server it actually assembled — its namespaces, its
// authentication, its rate limiter, its audit — rather than the handlers
// underneath them.
//
// What it exists for is the modern era. A request of revision 2026-07-28 is
// correct only if params._meta carries the protocol version and the client's
// capabilities, and the Mcp-Protocol-Version, Mcp-Method and Mcp-Name headers
// mirror the body exactly — including the Base64 sentinel when a name will not
// fit in a header. Writing that out by hand in every test is how a suite ends
// up asserting against requests no client would send.
//
//	c := mcptest.New(t, h, mcptest.WithHeader("Authorization", "Bearer "+key))
//	tools := c.Tools(t)
//
// The same client speaks the older era on request, which is how a dual-era
// server gets tested as one:
//
//	for _, era := range []mcptest.Era{mcptest.Modern, mcptest.Legacy} { … }
//
// It is a test helper and says so: every method takes a testing.TB and fails
// the test on anything that is not the answer it was asked for. Nothing here
// belongs in production code.
package mcptest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/vmkteam/mcpkit/mcp"

	"github.com/stretchr/testify/require"
)

// Era is which era a client speaks. The type and its two values live in mcp,
// beside the boundary that defines them: a fixture that named its own eras
// would be describing the protocol from the outside, and this one has to agree
// with the transport on every one of them.
type Era = mcp.Era

const (
	Modern = mcp.EraModern
	Legacy = mcp.EraLegacy
)

// Client is a running server and the client that talks to it.
type Client struct {
	// URL is the endpoint the requests go to, so a test that needs to send
	// something this client will not send can do it by hand.
	URL string

	era     Era
	version string
	caps    any
	info    any
	header  http.Header
	path    string
	http    *http.Client
	id      atomic.Int64
}

// Option tunes a Client.
type Option func(*Client)

// WithEra picks the revision the client speaks. The default is Modern: it is
// the current one, and it is the one whose requests are laborious to build by
// hand — which is what this package is for.
func WithEra(e Era) Option { return func(c *Client) { c.era = e } }

// WithProtocolVersion overrides the revision sent in _meta and in the header.
// The default is the newest revision of the chosen era. Setting one the server
// does not support is how a test reaches the -32022 answer.
func WithProtocolVersion(v string) Option { return func(c *Client) { c.version = v } }

// WithHeader adds a header to every request — an Authorization, a trace id.
// Applied after the protocol headers, so a test can deliberately break one of
// them and see what the server does.
func WithHeader(key, value string) Option {
	return func(c *Client) { c.header.Set(key, value) }
}

// WithPath sets the path the requests go to. The default is "/", which is right
// for a bare handler; a service that wired a mux wants its own, usually "/mcp".
func WithPath(p string) Option { return func(c *Client) { c.path = p } }

// implementation is the {name, version} object both sides of the protocol
// identify themselves with.
type implementation struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// WithClientInfo sets what the client calls itself in _meta.
func WithClientInfo(name, version string) Option {
	return func(c *Client) { c.info = implementation{Name: name, Version: version} }
}

// WithClientCapabilities sets what the client declares it can do. The default
// is an empty object: a client that declares nothing, which is still a
// declaration and is what the field requires.
func WithClientCapabilities(v any) Option { return func(c *Client) { c.caps = v } }

// New starts h on a local server and returns a client for it. The server is
// closed when the test ends.
func New(t testing.TB, h http.Handler, opts ...Option) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	c := &Client{
		era:    Modern,
		caps:   map[string]any{},
		info:   implementation{Name: "mcptest", Version: "0"},
		header: http.Header{},
		path:   "/",
		http:   srv.Client(),
	}
	for _, o := range opts {
		o(c)
	}
	// After the options: the default revision depends on the era, and the era
	// is one of the things an option sets.
	if c.version == "" {
		c.version = mcp.NewestRevision(c.era)
	}
	c.URL = srv.URL + "/" + strings.TrimPrefix(c.path, "/")
	return c
}

// Error is a JSON-RPC error as it came back.
type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *Error) String() string { return fmt.Sprintf("%d %s", e.Code, e.Message) }

// Response is one answer, kept whole: the status and the headers matter in this
// revision — an unknown method is a 404, a refused header a 400 — and a test
// that only ever looks at the result would not see either.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
	Result json.RawMessage
	Error  *Error
}

// Decode unmarshals the result into v, failing the test if the call came back
// as an error instead.
func (r Response) Decode(t testing.TB, v any) {
	t.Helper()
	require.Nil(t, r.Error, "expected a result, got error %s", r.Error)
	require.NotEmpty(t, r.Result, "expected a result, got %s", r.Body)
	require.NoError(t, json.Unmarshal(r.Result, v))
}

// Call sends one request and returns the answer. params may be nil, a map or
// any value that marshals to a JSON object; the metadata and the headers the
// era requires are filled in.
func (c *Client) Call(t testing.TB, method string, params any) Response {
	t.Helper()
	return c.send(t, c.body(t, method, params, true))
}

// Notify sends a notification: no id, and no answer to parse. This revision
// "defines no client-to-server notifications over Streamable HTTP", so it is
// here for the older era and for a server that accepts one anyway.
func (c *Client) Notify(t testing.TB, method string, params any) Response {
	t.Helper()
	return c.send(t, c.body(t, method, params, false))
}

// body builds the request document.
func (c *Client) body(t testing.TB, method string, params any, withID bool) map[string]any {
	t.Helper()

	p := map[string]any{}
	if params != nil {
		raw, err := json.Marshal(params)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, &p), "params must marshal to a JSON object")
		// A typed nil — map[string]any(nil) out of a table of cases — is not a
		// nil interface, marshals to null, and unmarshalling null leaves the
		// map nil rather than erroring. Writing _meta into it would panic.
		if p == nil {
			p = map[string]any{}
		}
	}
	if c.era == Modern {
		// Both keys are required of every modern request; clientInfo is not,
		// and is sent because a real client sends it.
		p["_meta"] = map[string]any{
			mcp.MetaProtocolVersion:    c.version,
			mcp.MetaClientCapabilities: c.caps,
			mcp.MetaClientInfo:         c.info,
		}
	}

	body := map[string]any{"jsonrpc": "2.0", "method": method, "params": p}
	if withID {
		body["id"] = c.id.Add(1)
	}
	return body
}

func (c *Client) send(t testing.TB, body map[string]any) Response {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, c.URL, bytes.NewReader(raw))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	c.protocolHeaders(t, req, body)
	// Last, so that a test can override a protocol header on purpose and watch
	// the server refuse the request.
	maps.Copy(req.Header, c.header)

	res, err := c.http.Do(req)
	require.NoError(t, err)
	defer res.Body.Close() //nolint:errcheck // a test client reading a local server

	out := Response{Status: res.StatusCode, Header: res.Header}
	out.Body, err = io.ReadAll(res.Body)
	require.NoError(t, err)
	if len(bytes.TrimSpace(out.Body)) == 0 {
		return out // a notification, or a server that answered 202
	}

	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *Error          `json:"error"`
	}
	// Not a require: a malformed answer is a thing a test may be asserting
	// about, and Body is kept whole so it can.
	if json.Unmarshal(out.Body, &envelope) == nil {
		out.Result, out.Error = envelope.Result, envelope.Error
	}
	return out
}

// protocolHeaders mirrors the body into the headers the binding defines.
//
// Mcp-Method and Mcp-Name exist so that a proxy can route without parsing the
// body, and a server compares them against it; getting them right is most of
// what this package does for a caller.
func (c *Client) protocolHeaders(t testing.TB, req *http.Request, body map[string]any) {
	t.Helper()
	req.Header.Set(mcp.HeaderProtocolVersion, c.version)
	if c.era != Modern {
		return
	}
	method, _ := body["method"].(string)
	req.Header.Set(mcp.HeaderMethod, method)
	if path := mcp.NamePathFor(method); path != nil {
		name, ok := lookup(body, path)
		require.Truef(t, ok, "%s needs %s in the body to mirror into %s",
			method, strings.Join(path, "."), mcp.HeaderName)
		req.Header.Set(mcp.HeaderName, mcp.EncodeHeaderValue(name))
	}
}

// lookup walks the path the server will walk, so the header cannot be built
// from a different field than the one it is compared against.
func lookup(m map[string]any, path []string) (string, bool) {
	var cur any = m
	for _, key := range path {
		obj, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		if cur, ok = obj[key]; !ok {
			return "", false
		}
	}
	s, ok := cur.(string)
	return s, ok
}

// --- the calls a server answers -----------------------------------------------
//
// One page each: a catalogue is a single answer unless the service turned
// paging on, and a test that wants the second page has Call and the NextCursor
// it was given.

// decode makes one call and unmarshals the result into the type that call
// answers with. It is a function rather than a method because a method cannot
// take a type parameter; the methods below are what a test actually calls, and
// they keep the result type in their signature where a reader can see it.
func decode[T any](t testing.TB, c *Client, method string, params any) T {
	t.Helper()
	var out T
	c.Call(t, method, params).Decode(t, &out)
	return out
}

// Discover calls server/discover, which a modern server must implement.
func (c *Client) Discover(t testing.TB) mcp.DiscoverResult {
	t.Helper()
	return decode[mcp.DiscoverResult](t, c, "server/discover", nil)
}

// Initialize calls the handshake of the older era. A modern client has no use
// for it — server/discover replaced it — but a dual-era server still answers.
func (c *Client) Initialize(t testing.TB) mcp.InitializeResult {
	t.Helper()
	return decode[mcp.InitializeResult](t, c, "initialize", map[string]any{"protocolVersion": c.version})
}

// Tools calls tools/list.
func (c *Client) Tools(t testing.TB) mcp.ToolList {
	t.Helper()
	return decode[mcp.ToolList](t, c, "tools/list", nil)
}

// CallTool calls tools/call. A tool that refused still answers here: a refusal
// travels inside a successful response, marked isError.
func (c *Client) CallTool(t testing.TB, name string, args map[string]any) mcp.ToolCallResult {
	t.Helper()
	return decode[mcp.ToolCallResult](t, c, "tools/call", map[string]any{"name": name, "arguments": args})
}

// Resources calls resources/list.
func (c *Client) Resources(t testing.TB) mcp.ResourceList {
	t.Helper()
	return decode[mcp.ResourceList](t, c, "resources/list", nil)
}

// ReadResource calls resources/read.
func (c *Client) ReadResource(t testing.TB, uri string) mcp.ResourceData {
	t.Helper()
	return decode[mcp.ResourceData](t, c, "resources/read", map[string]any{"uri": uri})
}

// Prompts calls prompts/list.
func (c *Client) Prompts(t testing.TB) mcp.PromptList {
	t.Helper()
	return decode[mcp.PromptList](t, c, "prompts/list", nil)
}

// GetPrompt calls prompts/get.
func (c *Client) GetPrompt(t testing.TB, name string, args map[string]string) mcp.RenderedPrompt {
	t.Helper()
	return decode[mcp.RenderedPrompt](t, c, "prompts/get", map[string]any{"name": name, "arguments": args})
}
