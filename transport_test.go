package mcpkit

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vmkteam/mcpkit/mcp"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
	"github.com/vmkteam/zenrpc/v2"
	"github.com/vmkteam/zenrpc/v2/smd"
)

// probe is a hand-written zenrpc.Invoker: the transport is what is under test,
// and a generated service would only add a code generator to the loop.
type probe struct {
	mu     sync.Mutex
	called []string
	// signal, when set, receives every dispatched method. Notifications are
	// dispatched by zenrpc in a goroutine it does not wait for, so a test that
	// wants to see the side effect has to wait for it itself.
	signal chan string
}

func (p *probe) Invoke(_ context.Context, method string, _ json.RawMessage) zenrpc.Response {
	p.mu.Lock()
	p.called = append(p.called, method)
	p.mu.Unlock()
	if p.signal != nil {
		p.signal <- method
	}
	res := json.RawMessage(`{"ok":true}`)
	return zenrpc.Response{Version: zenrpc.Version, Result: &res}
}

func (p *probe) SMD() smd.ServiceInfo { return smd.ServiceInfo{} }

func (p *probe) methods() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.called...)
}

// newTestServer returns a transport with one probe service registered in the
// root namespace (initialize, ping) and one under `tools`.
func newTestServer(t *testing.T, opts Options) (*Server, *probe, *probe) {
	t.Helper()
	root, tools := &probe{}, &probe{}
	zsrv := zenrpc.NewServer(zenrpc.Options{})
	zsrv.RegisterAll(map[string]zenrpc.Invoker{"": root, "tools": tools})
	return NewServerWithOptions(zsrv, embedlog.Logger{}, opts), root, tools
}

func post(t *testing.T, srv *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body)))
	return rr
}

// The rule for picking a revision is tested in mcp, where it lives. What the
// transport owes it is the header below.

// The header must never state a different revision than the body of the same
// response. Before the handshake the client declares nothing, so we answer
// with nothing — the initialize result carries the negotiated revision itself.
func TestHandlePOST_ProtocolVersionHeader(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t, Options{})

	cases := map[string]string{
		"":                  "",                  // no declaration yet — say nothing
		mcp.Version20250618: mcp.Version20250618, // a revision we speak — echo it
		mcp.Version20251125: mcp.Version20251125, // the one Claude Desktop asks for
		"2025-08-01":        mcp.Version20250618, // unknown — answer below it, not above
		"1999-01-01":        mcp.Version20250618, // older than anything we speak
	}
	for sent, want := range cases {
		t.Run("sent="+sent, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
			if sent != "" {
				req.Header.Set("Mcp-Protocol-Version", sent)
			}
			rr := httptest.NewRecorder()
			srv.ServeHTTP(rr, req)
			assert.Equal(t, want, rr.Header().Get("Mcp-Protocol-Version"))
		})
	}
}

// A plain call: the slashed MCP name reaches the service as a zenrpc method,
// and the answer is the JSON-RPC response, not a stream.
func TestHandlePOST_Dispatches(t *testing.T) {
	t.Parallel()
	srv, root, tools := newTestServer(t, Options{})

	rr := post(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	assert.Contains(t, rr.Body.String(), `"result":{"ok":true}`)
	assert.Equal(t, []string{"list"}, tools.methods(), "tools/list must arrive as tools.list")

	rr = post(t, srv, `{"jsonrpc":"2.0","id":2,"method":"initialize"}`)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, []string{"initialize"}, root.methods(), "unqualified methods go to the root namespace")
}

// 202 is the status, not an excuse to skip the handler:
// notifications/initialized has to reach the service.
func TestHandlePOST_Notification(t *testing.T) {
	t.Parallel()
	notifications := &probe{signal: make(chan string, 1)}
	zsrv := zenrpc.NewServer(zenrpc.Options{})
	zsrv.Register("notifications", notifications)
	srv := NewServer(zsrv, embedlog.Logger{})

	rr := post(t, srv, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	assert.Equal(t, http.StatusAccepted, rr.Code)
	assert.Empty(t, rr.Body.String(), "a notification has no response body")

	// 202 is the status, not permission to skip the handler. zenrpc dispatches
	// a notification in a goroutine it does not wait for, so the side effect
	// lands after the response — the guarantee is that it lands, not when.
	select {
	case method := <-notifications.signal:
		assert.Equal(t, "initialized", method)
	case <-time.After(2 * time.Second):
		t.Fatal("notifications/initialized never reached the handler")
	}
}

// MCP dropped batching in 2025-06-18, and here a batch was ten tool calls for
// one rate-limit token: zenrpc runs the members in parallel while a limiter in
// front counts the POST. One request per POST, or 400.
func TestHandlePOST_RejectsBatch(t *testing.T) {
	t.Parallel()
	srv, _, tools := newTestServer(t, Options{})

	rr := post(t, srv, `[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","id":2,"method":"tools/list"}]`)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "batch")
	assert.Empty(t, tools.methods(), "a refused batch must not reach the services")
}

func TestHandlePOST_BodyTooLarge(t *testing.T) {
	t.Parallel()

	t.Run("default limit", func(t *testing.T) {
		t.Parallel()
		srv, _, _ := newTestServer(t, Options{})
		pad := strings.Repeat("a", DefaultMaxRequestBytes+1)
		body := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"x","params":"` + pad + `"}`)

		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/mcp", body))

		assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code)
	})

	// A service with bigger arguments raises the cap; a zero keeps the default.
	t.Run("configured limit", func(t *testing.T) {
		t.Parallel()
		srv, _, _ := newTestServer(t, Options{MaxRequestBytes: 128})

		assert.Equal(t, http.StatusRequestEntityTooLarge,
			post(t, srv, `{"jsonrpc":"2.0","id":1,"method":"ping","params":"`+strings.Repeat("a", 200)+`"}`).Code)
		assert.Equal(t, http.StatusOK,
			post(t, srv, `{"jsonrpc":"2.0","id":1,"method":"ping"}`).Code)
	})
}

func TestHandlePOST_BrokenJSON(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t, Options{})

	rr := post(t, srv, `{"jsonrpc":"2.0","id":1,"method":`)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "parse jsonrpc")
}

// A request the transport refuses never reaches a handler, so it shows up in no
// other series this library publishes. Without this counter a client that sends
// batches, or one whose JSON is broken, is visible only in somebody else's
// access log — and the question "why is that client silent?" has no answer here.
func TestTransportRejectionsAreCounted(t *testing.T) {
	srv, _, _ := newTestServer(t, Options{})

	count := func(reason string) float64 {
		return testutil.ToFloat64(rejectedTotal.WithLabelValues(reason))
	}

	t.Run("every reason is published from the start", func(t *testing.T) {
		assert.Equal(t, 11, testutil.CollectAndCount(rejectedTotal),
			"rate() cannot tell 'nothing refused' from 'no data'")
		assert.Equal(t, 2, testutil.CollectAndCount(requestsTotal), "both eras are counted from zero")
	})

	t.Run("batch", func(t *testing.T) {
		before := count(reasonBatch)
		post(t, srv, `[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]`)
		assert.Greater(t, count(reasonBatch), before)
	})

	t.Run("parse", func(t *testing.T) {
		before := count(reasonParse)
		post(t, srv, `{"jsonrpc":"2.0","id":1,"method":`)
		assert.Greater(t, count(reasonParse), before)
	})

	t.Run("too large", func(t *testing.T) {
		small, _, _ := newTestServer(t, Options{MaxRequestBytes: 64})
		before := count(reasonTooLarge)
		post(t, small, `{"jsonrpc":"2.0","id":1,"method":"ping","params":"`+strings.Repeat("a", 200)+`"}`)
		assert.Greater(t, count(reasonTooLarge), before)
	})

	t.Run("method not allowed", func(t *testing.T) {
		before := count(reasonBadMethod)
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, httptest.NewRequest(http.MethodPut, "/mcp", nil))
		require.Equal(t, http.StatusMethodNotAllowed, rr.Code)
		assert.Greater(t, count(reasonBadMethod), before)
	})
}

// "Servers MUST validate the Origin header on all incoming connections to
// prevent DNS rebinding attacks" — the attack being a page in the user's own
// browser reaching a server on the user's own machine, with the user's own
// credentials attached by the browser.
func TestOriginValidation(t *testing.T) {
	t.Parallel()

	call := func(t *testing.T, opts Options, origin string) *httptest.ResponseRecorder {
		t.Helper()
		srv, _, _ := newTestServer(t, opts)
		req := httptest.NewRequest(http.MethodPost, "/mcp",
			strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		return rr
	}

	// The ordinary case: mcpurl, Claude Code and every other caller outside a
	// browser send no Origin, so the strict default costs them nothing.
	t.Run("no origin passes", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, http.StatusOK, call(t, Options{}, "").Code)
	})

	t.Run("any origin is refused when none are configured", func(t *testing.T) {
		t.Parallel()
		before := testutil.ToFloat64(rejectedTotal.WithLabelValues(reasonOrigin))
		rr := call(t, Options{}, "https://evil.example")
		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.Greater(t, testutil.ToFloat64(rejectedTotal.WithLabelValues(reasonOrigin)), before)
	})

	t.Run("a configured origin passes, another does not", func(t *testing.T) {
		t.Parallel()
		opts := Options{AllowedOrigins: []string{"https://console.example"}}
		assert.Equal(t, http.StatusOK, call(t, opts, "https://console.example").Code)
		assert.Equal(t, http.StatusOK, call(t, opts, "https://CONSOLE.example").Code,
			"scheme and host are case-insensitive, so the same origin in another case is the same origin")
		assert.Equal(t, http.StatusForbidden, call(t, opts, "https://evil.example").Code)
	})

	t.Run("* switches the check off", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, http.StatusOK, call(t, Options{AllowedOrigins: []string{"*"}}, "https://anything.example").Code)
	})

	// The check has to answer before the method switch: a GET from a browser is
	// refused for being cross-origin, not for being a GET.
	t.Run("applies to every method", func(t *testing.T) {
		t.Parallel()
		srv, _, _ := newTestServer(t, Options{})
		req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		req.Header.Set("Origin", "https://evil.example")
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusForbidden, rr.Code)
	})
}

// The Host check exists for what the Origin check structurally cannot see. A
// DNS-rebound request reaches http://evil.com:8075 after that name has been
// re-resolved to 127.0.0.1; to the browser that is the *same* origin, so no
// Origin header is sent and the origin check has nothing to refuse. The Host is
// the only place the client's belief about who it is talking to survives.
func TestHostValidation(t *testing.T) {
	t.Parallel()

	call := func(t *testing.T, opts Options, host string) *httptest.ResponseRecorder {
		t.Helper()
		srv, _, _ := newTestServer(t, opts)
		req := httptest.NewRequest(http.MethodPost, "/mcp",
			strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		req.Host = host
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		return rr
	}

	// Off by default: in production the proxy in front already answers this, and
	// a strict default would refuse every deployment that had not listed itself.
	t.Run("no list checks nothing", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, http.StatusOK, call(t, Options{}, "evil.com").Code)
	})

	t.Run("a listed host passes, another does not", func(t *testing.T) {
		t.Parallel()
		opts := Options{AllowedHosts: []string{"localhost:8075", "127.0.0.1:8075"}}
		assert.Equal(t, http.StatusOK, call(t, opts, "localhost:8075").Code)
		assert.Equal(t, http.StatusOK, call(t, opts, "127.0.0.1:8075").Code)
		assert.Equal(t, http.StatusOK, call(t, opts, "LOCALHOST:8075").Code,
			"a host name is case-insensitive")

		// The three shapes go-sdk's own suite names, and the reason a prefix or
		// suffix match would not do.
		for _, host := range []string{"evil.com", "evil.com:8075", "localhost.evil.com:8075", "localhost:9999"} {
			assert.Equalf(t, http.StatusForbidden, call(t, opts, host).Code, "host %q", host)
		}
	})

	t.Run("refusals are counted", func(t *testing.T) {
		t.Parallel()
		before := testutil.ToFloat64(rejectedTotal.WithLabelValues(reasonHost))
		call(t, Options{AllowedHosts: []string{"localhost:8075"}}, "evil.com")
		assert.Greater(t, testutil.ToFloat64(rejectedTotal.WithLabelValues(reasonHost)), before)
	})

	t.Run("* switches the check off", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, http.StatusOK, call(t, Options{AllowedHosts: []string{"*"}}, "evil.com").Code)
	})
}

// "The origin server MUST generate an Allow header field in a 405 response"
// (RFC 9110 §15.5.6). Three paths here answer 405, and a client is entitled to
// learn from any of them what it should have sent instead.
func TestMethodNotAllowedCarriesAllow(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t, Options{})
	for _, method := range []string{http.MethodGet, http.MethodDelete, http.MethodPut, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			rr := httptest.NewRecorder()
			srv.ServeHTTP(rr, httptest.NewRequest(method, "/mcp", nil))
			require.Equal(t, http.StatusMethodNotAllowed, rr.Code)
			assert.Equal(t, http.MethodPost, rr.Header().Get("Allow"))
		})
	}
}

// A request whose id is null is one the dispatcher already treats as a
// notification. When this transport disagreed and called it a request, zenrpc's
// empty response was written out as the bare literal `null` with a 200 —
// neither a response a client could match nor the silence a notification earns.
func TestNullIDIsANotification(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t, Options{})

	for name, body := range map[string]string{
		"null id":   `{"jsonrpc":"2.0","id":null,"method":"ping","params":{}}`,
		"absent id": `{"jsonrpc":"2.0","method":"ping","params":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			rr := httptest.NewRecorder()
			srv.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body)))
			assert.Equal(t, http.StatusAccepted, rr.Code)
			assert.Empty(t, rr.Body.String(), "a notification is answered with nothing at all")
		})
	}

	// The control: a real id still gets a real answer.
	t.Run("an id that is there is still a request", func(t *testing.T) {
		t.Parallel()
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/mcp",
			strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}`)))
		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Contains(t, rr.Body.String(), `"result"`)
	})
}

// The robustness table, modelled on go-sdk's bad_requests.txtar — which is not
// a list of hypotheticals but of panics they actually shipped and fixed (their
// issues #194–#197).
//
// Everything here is a body a client can send by mistake, and the only property
// under test is that each one gets a defined answer instead of taking the
// process down. Run by hand once, it found the null-id case; kept as a test, it
// costs ten lines and keeps finding the next one.
func TestMalformedBodiesGetDefinedAnswers(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t, Options{})

	cases := []struct {
		name string
		body string
		code int
	}{
		{"initialize without id", `{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-06-18"}}`, http.StatusAccepted},
		{"initialize without params", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, http.StatusOK},
		{"initialize with null params", `{"jsonrpc":"2.0","id":2,"method":"initialize","params":null}`, http.StatusOK},
		{"ping without id", `{"jsonrpc":"2.0","method":"ping"}`, http.StatusAccepted},
		{"notification carrying an id", `{"jsonrpc":"2.0","id":3,"method":"notifications/initialized"}`, http.StatusOK},
		{"notification without one", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, http.StatusAccepted},
		{"tools/call without params", `{"jsonrpc":"2.0","id":4,"method":"tools/call"}`, http.StatusOK},
		{"tools/call with null params", `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":null}`, http.StatusOK},
		{"positional params", `{"jsonrpc":"2.0","id":6,"method":"resources/read","params":["docs://a.md"]}`, http.StatusOK},
		{"empty body", ``, http.StatusBadRequest},
		{"not json at all", `hello`, http.StatusBadRequest},
		{"a bare string", `"hello"`, http.StatusOK},
		{"a bare number", `42`, http.StatusOK},
		{"a string id", `{"jsonrpc":"2.0","id":"abc","method":"ping","params":{}}`, http.StatusOK},
		{"a null id", `{"jsonrpc":"2.0","id":null,"method":"ping","params":{}}`, http.StatusAccepted},
		{"no jsonrpc member", `{"id":1,"method":"ping","params":{}}`, http.StatusOK},
		{"no method member", `{"jsonrpc":"2.0","id":1,"params":{}}`, http.StatusOK},
		{"deeply nested params", `{"jsonrpc":"2.0","id":1,"method":"ping","params":` + strings.Repeat(`{"a":`, 200) + `1` + strings.Repeat(`}`, 200) + `}`, http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rr := httptest.NewRecorder()
			srv.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(tc.body)))
			assert.Equal(t, tc.code, rr.Code)

			// Whatever came back, it has to be something a client can read: a
			// JSON document, or nothing at all. The literal `null` that the null
			// id used to produce was neither.
			body := strings.TrimSpace(rr.Body.String())
			if rr.Code == http.StatusAccepted {
				assert.Empty(t, body, "a notification is answered with nothing")
				return
			}
			if rr.Code == http.StatusBadRequest {
				return // refused before the parse; the message is plain text on purpose
			}
			var out map[string]any
			require.NoErrorf(t, json.Unmarshal([]byte(body), &out), "not a JSON-RPC document: %s", body)
			_, hasResult := out["result"]
			_, hasError := out["error"]
			assert.Truef(t, hasResult || hasError, "neither a result nor an error: %s", body)
		})
	}
}

// notifyService stands in for a service that actually does something on a
// notification: it records the state of the context after the handler has
// certainly returned.
type notifyService struct {
	zenrpc.Service
	done chan error
}

func (s notifyService) Invoke(ctx context.Context, _ string, _ json.RawMessage) zenrpc.Response {
	// Long enough that handlePOST has written its 202 and returned — which is
	// the moment net/http cancels the request context.
	time.Sleep(50 * time.Millisecond)
	s.done <- ctx.Err()
	return zenrpc.Response{}
}

func (notifyService) SMD() smd.ServiceInfo {
	return smd.ServiceInfo{Methods: map[string]smd.Service{}}
}

// zenrpc runs a notification in a goroutine of its own and returns before it
// has started, so by the time the handler does any work this one has written
// 202 and returned — and net/http cancelled r.Context() as it did. Everything
// the handler might do with a context was failing on a cancelled one, which is
// the opposite of what "still dispatch so the side effects run" promised.
// It has to run against a real server, not a recorder: httptest.NewRequest
// hands the handler a context nobody ever cancels, so this test passed either
// way until it went through a socket. net/http is what cancels the request
// context, and only net/http can show that it does.
func TestNotificationOutlivesTheRequest(t *testing.T) {
	t.Parallel()
	done := make(chan error, 1)

	zsrv := zenrpc.NewServer(zenrpc.Options{})
	zsrv.RegisterAll(map[string]zenrpc.Invoker{
		"notifications": notifyService{done: done},
	})
	srv := httptest.NewServer(NewServer(zsrv, embedlog.Logger{}))
	t.Cleanup(srv.Close)

	res, err := srv.Client().Post(srv.URL, "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`))
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())
	require.Equal(t, http.StatusAccepted, res.StatusCode)

	select {
	case err := <-done:
		require.NoError(t, err, "the notification handler ran on a cancelled context")
	case <-time.After(2 * time.Second):
		t.Fatal("the notification handler never ran")
	}
}

// A server that pushes nothing must say so rather than open a stream and close
// it: a client told the stream exists reconnects when it dies — once a second,
// forever.
func TestGET_RefusesTheStream(t *testing.T) {
	t.Parallel()
	inner, _, _ := newTestServer(t, Options{})
	srv := httptest.NewServer(inner)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Accept", "text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
	assert.NotContains(t, resp.Header.Get("Content-Type"), "text/event-stream",
		"refusing with an SSE content type would still read as a stream")
}

// DELETE is session teardown and there is no session; anything else is not a
// transport this server speaks.
func TestOtherMethods(t *testing.T) {
	t.Parallel()
	srv, _, _ := newTestServer(t, Options{})

	for _, method := range []string{http.MethodDelete, http.MethodPut, http.MethodPatch, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			rr := httptest.NewRecorder()
			srv.ServeHTTP(rr, httptest.NewRequest(method, "/mcp", nil))
			assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
		})
	}
}

// The handshake log is what says which revision each client really speaks, and
// whether a stateless server is enough for it. It is off unless asked for:
// a line per connection is noise once that question is answered.
func TestLogHandshake(t *testing.T) {
	const initialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":` +
		`{"protocolVersion":"2025-06-18","clientInfo":{"name":"probe-client","version":"2.1"}}}`

	handshakes := func(t *testing.T, opts Options) []map[string]any {
		t.Helper()
		r, w, err := os.Pipe()
		require.NoError(t, err)

		// embedlog binds the writer at construction, so the only way to read
		// what it prints is to hand it a pipe as stdout for that instant.
		orig := os.Stdout
		os.Stdout = w
		logger := embedlog.NewLogger(true, true)
		os.Stdout = orig

		zsrv := zenrpc.NewServer(zenrpc.Options{})
		zsrv.Register("", &probe{})
		srv := NewServerWithOptions(zsrv, logger, opts)

		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(initialize))
		req.Header.Set("User-Agent", "probe-client/2.1")
		srv.ServeHTTP(httptest.NewRecorder(), req)

		// A call that is not a handshake must not add a line.
		srv.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/mcp",
			strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"ping"}`)))

		require.NoError(t, w.Close())
		raw, err := io.ReadAll(r)
		require.NoError(t, err)

		var out []map[string]any
		for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
			var rec map[string]any
			if json.Unmarshal([]byte(line), &rec) == nil && rec["msg"] == "mcp handshake" {
				out = append(out, rec)
			}
		}
		return out
	}

	t.Run("off by default", func(t *testing.T) {
		assert.Empty(t, handshakes(t, Options{}), "no line unless the option asks for one")
	})

	t.Run("one line per handshake", func(t *testing.T) {
		hs := handshakes(t, Options{LogHandshake: true})
		require.Len(t, hs, 1, "one line per handshake, none for anything else")

		h := hs[0]
		assert.Equal(t, mcp.Version20250618, h["asked_version"])
		assert.Equal(t, mcp.Version20250618, h["answered_version"])
		assert.Equal(t, "probe-client", h["client"])
		assert.Equal(t, "probe-client/2.1", h["user_agent"])
		assert.Equal(t, false, h["sent_session_id"])
		assert.Empty(t, h["header_version"], "the header is absent before the handshake")
	})
}
