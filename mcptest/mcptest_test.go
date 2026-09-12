package mcptest

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/vmkteam/mcpkit/mcp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// record captures what the server was actually sent. The point of this package
// is the request, so that is what its own tests look at.
type record struct {
	header http.Header
	body   map[string]any
	err    error
}

// The handler asserts nothing itself: a failed require inside one calls
// runtime.Goexit on the server's goroutine, which leaves the client waiting on
// a connection nobody will answer. It records what went wrong and the test
// checks it back on its own goroutine.
func recorder(t *testing.T, opts ...Option) (*Client, *record) {
	t.Helper()
	got := &record{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.header = r.Header.Clone()
		raw, err := io.ReadAll(r.Body)
		if err == nil {
			err = json.Unmarshal(raw, &got.body)
		}
		got.err = err
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete"}}`))
	})
	return New(t, h, opts...), got
}

// sent is the request the server received, once it is known to be one.
func (r *record) sent(t *testing.T) map[string]any {
	t.Helper()
	require.NoError(t, r.err)
	require.NotNil(t, r.body, "the server received nothing")
	return r.body
}

// meta is params._meta of the request the server received.
func (r *record) meta(t *testing.T) map[string]any {
	t.Helper()
	params, ok := r.sent(t)["params"].(map[string]any)
	require.True(t, ok, "no params in %v", r.body)
	m, ok := params["_meta"].(map[string]any)
	require.True(t, ok, "no params._meta in %v", r.body)
	return m
}

// Every modern request carries the same two keys, and the headers mirror the
// body rather than being filled in from somewhere else.
func TestModernRequestCarriesWhatTheRevisionRequires(t *testing.T) {
	t.Parallel()
	c, got := recorder(t)
	c.Call(t, "tools/list", nil)

	meta := got.meta(t)
	assert.Equal(t, mcp.ProtocolVersion, meta[mcp.MetaProtocolVersion])
	assert.NotNil(t, meta[mcp.MetaClientCapabilities], "the key is required even when it declares nothing")
	assert.NotNil(t, meta[mcp.MetaClientInfo])

	assert.Equal(t, mcp.ProtocolVersion, got.header.Get(mcp.HeaderProtocolVersion))
	assert.Equal(t, "tools/list", got.header.Get(mcp.HeaderMethod))
	assert.Empty(t, got.header.Get(mcp.HeaderName), "tools/list names nothing")
}

// Mcp-Name is sent for exactly the three methods that name something, and its
// value is read from the field the server will compare it against.
func TestNameHeaderMirrorsTheBody(t *testing.T) {
	t.Parallel()
	cases := []struct {
		method string
		params map[string]any
		want   string
	}{
		{"tools/call", map[string]any{"name": "hello"}, "hello"},
		{"prompts/get", map[string]any{"name": "triage"}, "triage"},
		{"resources/read", map[string]any{"uri": "docs://a.md"}, "docs://a.md"},
		{"tools/list", nil, ""},
		{"server/discover", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			t.Parallel()
			c, got := recorder(t)
			c.Call(t, tc.method, tc.params)
			assert.Equal(t, tc.want, got.header.Get(mcp.HeaderName))
		})
	}
}

// A URI with non-ASCII in it cannot travel in a header as itself, and the
// sentinel is what the spec defines for that. The server decodes before
// comparing, so the round trip is the whole contract.
func TestNonASCIINameTravelsAsTheSentinel(t *testing.T) {
	t.Parallel()
	const uri = "docs://привет.md"
	c, got := recorder(t)
	c.Call(t, "resources/read", map[string]any{"uri": uri})

	raw := got.header.Get(mcp.HeaderName)
	assert.NotEqual(t, uri, raw, "a non-ASCII value cannot be sent plainly")
	decoded, err := mcp.DecodeHeaderValue(raw)
	require.NoError(t, err)
	assert.Equal(t, uri, decoded)
}

// The older era is the absence of all of it: no _meta, no Mcp-Method, and a
// revision the server reads as legacy.
func TestLegacyRequestCarriesNoneOfIt(t *testing.T) {
	t.Parallel()
	c, got := recorder(t, WithEra(Legacy))
	c.Call(t, "resources/read", map[string]any{"uri": "docs://a.md"})

	params, _ := got.sent(t)["params"].(map[string]any)
	assert.NotContains(t, params, "_meta")
	assert.Empty(t, got.header.Get(mcp.HeaderMethod))
	assert.Empty(t, got.header.Get(mcp.HeaderName))
	assert.Equal(t, mcp.Version20251125, got.header.Get(mcp.HeaderProtocolVersion))
	assert.Less(t, got.header.Get(mcp.HeaderProtocolVersion), mcp.ProtocolVersion,
		"revisions are ISO dates, and this one has to read as older")
}

func TestOptions(t *testing.T) {
	t.Parallel()

	// The version is what a test overrides to reach the refusal paths, so it
	// has to reach both places the server compares.
	t.Run("an overridden version goes to the body and the header alike", func(t *testing.T) {
		t.Parallel()
		c, got := recorder(t, WithProtocolVersion("1999-01-01"))
		c.Call(t, "tools/list", nil)
		meta := got.meta(t)
		assert.Equal(t, "1999-01-01", meta[mcp.MetaProtocolVersion])
		assert.Equal(t, "1999-01-01", got.header.Get(mcp.HeaderProtocolVersion))
	})

	// Applied last on purpose: breaking a protocol header is how a test gets at
	// the -32020 answer.
	t.Run("a header of the caller's wins", func(t *testing.T) {
		t.Parallel()
		c, got := recorder(t,
			WithHeader("Authorization", "Bearer k"),
			WithHeader(mcp.HeaderMethod, "something/else"))
		c.Call(t, "tools/list", nil)
		assert.Equal(t, "Bearer k", got.header.Get("Authorization"))
		assert.Equal(t, "something/else", got.header.Get(mcp.HeaderMethod))
	})

	t.Run("client identity and capabilities are the caller's to set", func(t *testing.T) {
		t.Parallel()
		c, got := recorder(t,
			WithClientInfo("ringsrv-test", "2.0"),
			WithClientCapabilities(map[string]any{"roots": map[string]any{}}))
		c.Call(t, "tools/list", nil)
		meta := got.meta(t)
		assert.Equal(t, map[string]any{"name": "ringsrv-test", "version": "2.0"}, meta[mcp.MetaClientInfo])
		assert.Contains(t, meta[mcp.MetaClientCapabilities], "roots")
	})

	t.Run("a service that wired a mux gets its own path", func(t *testing.T) {
		t.Parallel()
		var path string
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path = r.URL.Path
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
		})
		New(t, h, WithPath("/mcp")).Call(t, "tools/list", nil)
		assert.Equal(t, "/mcp", path)
	})
}

// A notification has no id and gets no result. The client must not wait for one
// or try to parse it.
func TestNotifyCarriesNoID(t *testing.T) {
	t.Parallel()
	c, got := recorder(t)
	res := c.Notify(t, "notifications/initialized", nil)
	assert.NotContains(t, got.sent(t), "id")
	assert.Equal(t, http.StatusOK, res.Status)
}

// Ids are what a client matches answers by, so two calls must not share one.
func TestIDsAreDistinct(t *testing.T) {
	t.Parallel()
	c, got := recorder(t)
	c.Call(t, "tools/list", nil)
	first := got.sent(t)["id"]
	c.Call(t, "tools/list", nil)
	assert.NotEqual(t, first, got.sent(t)["id"])
}

// Status, headers and a JSON-RPC error all survive to the caller: in this
// revision the status carries meaning — 404 for an unknown method, 400 for a
// refused header — and a test that could only see the result would miss it.
func TestResponseKeepsTheWholeAnswer(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Mcp-Method", "tools/list")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no such method"}}`))
	})
	res := New(t, h).Call(t, "tools/list", nil)

	assert.Equal(t, http.StatusNotFound, res.Status)
	assert.Equal(t, "tools/list", res.Header.Get("Mcp-Method"))
	require.NotNil(t, res.Error)
	assert.Equal(t, -32601, res.Error.Code)
	assert.Contains(t, res.Error.String(), "no such method")
	assert.NotEmpty(t, res.Body, "the raw answer is kept for whatever the test wants to assert")
}
