package mcpkit

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vmkteam/mcpkit/mcp"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fastjson"
	"github.com/vmkteam/zenrpc/v2"
)

// The version header is client input, not a revision. A plain >= put every
// string sorting above "2026-07-28" on the modern path — "draft", "latest",
// "v2", "9" — and a legacy client with a malformed header was then refused with
// -32602 for metadata its own revision never defined.
func TestIsModernRevision(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		mcp.ProtocolVersion: true,  // the current revision
		"2027-01-01":        true,  // a revision from the future: ISO, and newer
		"2026-07-29":        true,  // one day newer
		mcp.Version20251125: false, // known and older
		mcp.Version20250618: false,
		"2025-03-26":        false, // an ISO date we no longer speak, but still older
		"":                  false,
		"draft":             false, // all of these sort above the revision, and none is one
		"latest":            false,
		"v2":                false,
		"9":                 false,
		"zzz":               false,
		"2026-07-2":         false, // right shape, wrong length
		"2026-07-2a":        false,
		"20260728":          false,
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, want, isModernRevision(in))
		})
	}
}

// The sentinel, spelt out rather than taken from mcp.EncodeHeaderValue: a test
// that builds its input with the code under test agrees with itself whatever
// either of them does.
const (
	base64Prefix = "=?base64?"
	base64Suffix = "?="
)

// parse is what the transport does to a body before anything else looks at it.
func parse(body string) (*fastjson.Value, error) {
	var p fastjson.Parser
	return p.ParseBytes([]byte(body))
}

// meta is the block every modern request carries.
const meta = `"_meta":{` +
	`"io.modelcontextprotocol/protocolVersion":"2026-07-28",` +
	`"io.modelcontextprotocol/clientInfo":{"name":"probe","version":"1.0"},` +
	`"io.modelcontextprotocol/clientCapabilities":{}}`

// modernPing is a well-formed modern request, headers included.
func modernPing(t *testing.T) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping","params":{`+meta+`}}`))
	req.Header.Set(mcp.HeaderProtocolVersion, mcp.ProtocolVersion)
	req.Header.Set(mcp.HeaderMethod, "ping")
	return req
}

// The era is a property of the request, not of the connection — there is no
// connection state either way. Either signal is enough to make it modern: the
// header identifies a client before the body is read, the _meta covers one that
// sends no header.
func TestEraDetection(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		header string
		body   string
		want   bool
	}{
		{"header and meta", mcp.ProtocolVersion, `{"method":"ping","params":{` + meta + `}}`, true},
		{"header only", mcp.ProtocolVersion, `{"method":"ping"}`, true},
		{"meta only", "", `{"method":"ping","params":{` + meta + `}}`, true},
		{"a future revision is still modern", "2027-01-01", `{"method":"ping"}`, true},
		{"legacy header", mcp.Version20251125, `{"method":"ping"}`, false},
		{"no signal at all", "", `{"method":"ping"}`, false},
		{"initialize is legacy by definition", "", `{"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v, err := parse(tc.body)
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(tc.body))
			if tc.header != "" {
				req.Header.Set(mcp.HeaderProtocolVersion, tc.header)
			}
			assert.Equal(t, tc.want, isModern(req, v))
		})
	}
}

// What a modern request must carry, and what it is told when it does not.
//
// The comparison always runs body → header: the body is the source of truth and
// the header is its mirror. Trusting the header instead is the hole the headers
// exist to close — a gateway meters one value while the server executes another.
func TestModernValidation(t *testing.T) {
	t.Parallel()

	const metaNoCaps = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}`

	cases := []struct {
		name    string
		body    string
		headers map[string]string
		code    int // 0 = accepted
	}{
		{
			name:    "well formed",
			body:    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hello",` + meta + `}}`,
			headers: map[string]string{mcp.HeaderMethod: "tools/call", mcp.HeaderName: "hello"},
		},
		{
			name:    "no protocol version in _meta",
			body:    `{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}`,
			headers: map[string]string{mcp.HeaderProtocolVersion: mcp.ProtocolVersion, mcp.HeaderMethod: "ping"},
			code:    zenrpc.InvalidParams,
		},
		{
			name:    "header disagrees with _meta",
			body:    `{"jsonrpc":"2.0","id":1,"method":"ping","params":{` + meta + `}}`,
			headers: map[string]string{mcp.HeaderProtocolVersion: "2027-01-01", mcp.HeaderMethod: "ping"},
			code:    mcp.CodeHeaderMismatch,
		},
		{
			name:    "a revision we do not speak",
			body:    `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2099-01-01","io.modelcontextprotocol/clientCapabilities":{}}}}`,
			headers: map[string]string{mcp.HeaderMethod: "ping"},
			code:    mcp.CodeUnsupportedProtocolVersion,
		},
		{
			name:    "no client capabilities",
			body:    `{"jsonrpc":"2.0","id":1,"method":"ping","params":{` + metaNoCaps + `}}`,
			headers: map[string]string{mcp.HeaderMethod: "ping"},
			code:    zenrpc.InvalidParams,
		},
		{
			name:    "Mcp-Method is missing",
			body:    `{"jsonrpc":"2.0","id":1,"method":"ping","params":{` + meta + `}}`,
			headers: map[string]string{mcp.HeaderProtocolVersion: mcp.ProtocolVersion},
			code:    mcp.CodeHeaderMismatch,
		},
		{
			name:    "Mcp-Method names another method",
			body:    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hello",` + meta + `}}`,
			headers: map[string]string{mcp.HeaderMethod: "tools/list", mcp.HeaderName: "hello"},
			code:    mcp.CodeHeaderMismatch,
		},
		{
			// The attack the header rules exist for: a gateway meters the cheap
			// tool named in the header while the server runs the one in the body.
			name:    "Mcp-Name names another tool",
			body:    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"drop_everything",` + meta + `}}`,
			headers: map[string]string{mcp.HeaderMethod: "tools/call", mcp.HeaderName: "say_hello"},
			code:    mcp.CodeHeaderMismatch,
		},
		{
			name:    "Mcp-Name is missing where it is required",
			body:    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hello",` + meta + `}}`,
			headers: map[string]string{mcp.HeaderMethod: "tools/call"},
			code:    mcp.CodeHeaderMismatch,
		},
		{
			name:    "resources/read takes its name from the uri",
			body:    `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"docs://a.md",` + meta + `}}`,
			headers: map[string]string{mcp.HeaderMethod: "resources/read", mcp.HeaderName: "docs://a.md"},
		},
		{
			name:    "a method that carries no name needs none",
			body:    `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + meta + `}}`,
			headers: map[string]string{mcp.HeaderMethod: "tools/list"},
		},
		{
			// Required, not merely compared. Equality alone let this through:
			// an absent header and an empty name both read as "" and matched,
			// and the request went on to fail somewhere less informative.
			name:    "Mcp-Name is missing and the name is empty",
			body:    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"",` + meta + `}}`,
			headers: map[string]string{mcp.HeaderMethod: "tools/call"},
			code:    mcp.CodeHeaderMismatch,
		},
		{
			name:    "Mcp-Name is missing on prompts/get",
			body:    `{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"triage",` + meta + `}}`,
			headers: map[string]string{mcp.HeaderMethod: "prompts/get"},
			code:    mcp.CodeHeaderMismatch,
		},
		{
			// A URI is the one name here that routinely carries punctuation, and
			// the comparison is byte-for-byte, so the query string has to survive
			// it intact.
			name:    "a resource uri with a query string",
			body:    `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"docs://a.md?v=2&raw=1",` + meta + `}}`,
			headers: map[string]string{mcp.HeaderMethod: "resources/read", mcp.HeaderName: "docs://a.md?v=2&raw=1"},
		},
		{
			// "Servers MUST decode an encoded Mcp-Name value before comparing it
			// to the corresponding request body value."
			name: "a base64 sentinel is decoded before comparing",
			body: `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"docs://привет.md",` + meta + `}}`,
			headers: map[string]string{
				mcp.HeaderMethod: "resources/read",
				mcp.HeaderName:   base64Prefix + base64.StdEncoding.EncodeToString([]byte("docs://привет.md")) + base64Suffix,
			},
		},
		{
			name: "a base64 sentinel that decodes to something else",
			body: `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"docs://a.md",` + meta + `}}`,
			headers: map[string]string{
				mcp.HeaderMethod: "resources/read",
				mcp.HeaderName:   base64Prefix + base64.StdEncoding.EncodeToString([]byte("docs://b.md")) + base64Suffix,
			},
			code: mcp.CodeHeaderMismatch,
		},
		{
			name:    "broken base64 is a mismatch, not a panic",
			body:    `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"docs://a.md",` + meta + `}}`,
			headers: map[string]string{mcp.HeaderMethod: "resources/read", mcp.HeaderName: base64Prefix + "!!!!" + base64Suffix},
			code:    mcp.CodeHeaderMismatch,
		},
		{
			// A notification carries no id and this revision defines none over
			// HTTP; its header rules are explicitly undefined, so nothing here
			// applies to it.
			name: "a notification is exempt",
			body: `{"jsonrpc":"2.0","method":"notifications/initialized","params":{` + meta + `}}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v, err := parse(tc.body)
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(tc.body))
			for k, val := range tc.headers {
				req.Header.Set(k, val)
			}

			f := validateModern(req, v)
			if tc.code == 0 {
				assert.Nil(t, f, "expected the request to be accepted")
				return
			}
			require.NotNil(t, f, "expected a refusal")
			assert.Equal(t, tc.code, f.code)
			assert.NotEmpty(t, f.reason, "every refusal is counted under some label")
		})
	}
}

// "Header names are case-insensitive… Header values (such as method names) are
// case-sensitive." The names are net/http's business — it canonicalises them —
// but the values are ours, and a method that differs only in case is a
// different method.
func TestHeaderValuesAreCaseSensitive(t *testing.T) {
	t.Parallel()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + meta + `}}`
	v, err := parse(body)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set(mcp.HeaderMethod, "Tools/List")
	f := validateModern(req, v)
	require.NotNil(t, f)
	assert.Equal(t, mcp.CodeHeaderMismatch, f.code)
}

// A refusal decided before dispatch says what was wrong, echoes the id it was
// asked with, and travels with the status the spec fixes for it.
func TestUnsupportedVersionAnswer(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t, Options{})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(
		`{"jsonrpc":"2.0","id":7,"method":"ping","params":{"_meta":{`+
			`"io.modelcontextprotocol/protocolVersion":"2099-01-01",`+
			`"io.modelcontextprotocol/clientCapabilities":{}}}}`))
	req.Header.Set(mcp.HeaderMethod, "ping")
	srv.ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
	var out struct {
		ID    int `json:"id"`
		Error struct {
			Code int `json:"code"`
			Data struct {
				Supported []string `json:"supported"`
				Requested string   `json:"requested"`
			} `json:"data"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
	assert.Equal(t, 7, out.ID, "the answer names the request it refuses")
	assert.Equal(t, mcp.CodeUnsupportedProtocolVersion, out.Error.Code)
	assert.Equal(t, mcp.SupportedVersions, out.Error.Data.Supported,
		"the client picks its next attempt from this list")
	assert.Equal(t, "2099-01-01", out.Error.Data.Requested)
}

// Only the two cases whose status the spec fixes are lifted out of 200. A
// legacy client reads every answer out of a 200 and would take a 404 for "this
// endpoint is not here", so the lift happens for modern requests only.
func TestHTTPStatusFollowsErrorCode(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t, Options{})

	send := func(t *testing.T, modern bool, body, method string) int {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
		if modern {
			req.Header.Set(mcp.HeaderProtocolVersion, mcp.ProtocolVersion)
			req.Header.Set(mcp.HeaderMethod, method)
		}
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		return rr.Code
	}

	t.Run("unknown method is 404 for a modern client", func(t *testing.T) {
		t.Parallel()
		body := `{"jsonrpc":"2.0","id":1,"method":"tasks/get","params":{` + meta + `}}`
		assert.Equal(t, http.StatusNotFound, send(t, true, body, "tasks/get"))
	})

	t.Run("unknown method stays 200 for a legacy client", func(t *testing.T) {
		t.Parallel()
		body := `{"jsonrpc":"2.0","id":1,"method":"tasks/get"}`
		assert.Equal(t, http.StatusOK, send(t, false, body, ""),
			"a legacy client would read 404 as 'no MCP endpoint here' and go looking for HTTP+SSE")
	})

	t.Run("a successful call is 200 in either era", func(t *testing.T) {
		t.Parallel()
		body := `{"jsonrpc":"2.0","id":1,"method":"ping","params":{` + meta + `}}`
		assert.Equal(t, http.StatusOK, send(t, true, body, "ping"))
		assert.Equal(t, http.StatusOK, send(t, false, `{"jsonrpc":"2.0","id":1,"method":"ping"}`, ""))
	})
}

// Which era clients speak is the number that decides when the legacy half can
// be switched off, and nothing else records it.
func TestEraIsCounted(t *testing.T) {
	srv, _, _ := newTestServer(t, Options{})
	count := func(era string) float64 { return testutil.ToFloat64(requestsTotal.WithLabelValues(era)) }

	beforeModern, beforeLegacy := count(eraModern), count(eraLegacy)

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, modernPing(t))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	rr = httptest.NewRecorder()
	srv.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)))
	require.Equal(t, http.StatusOK, rr.Code)

	assert.Greater(t, count(eraModern), beforeModern)
	assert.Greater(t, count(eraLegacy), beforeLegacy)
}
