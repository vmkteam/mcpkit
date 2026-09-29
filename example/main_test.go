package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vmkteam/mcpkit"
	"github.com/vmkteam/mcpkit/doc"
	"github.com/vmkteam/mcpkit/mcp"
	"github.com/vmkteam/mcpkit/mcptest"
	"github.com/vmkteam/mcpkit/mcptool"
	"github.com/vmkteam/mcpkit/ratelimit"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
	"github.com/vmkteam/zenrpc/v2"
)

const testKey = "test-token"

// serve builds exactly what main runs — namespaces, authentication, limiter,
// audit — and hands back a client that speaks the requested era.
func serve(t *testing.T, era mcptest.Era) *mcptest.Client {
	t.Helper()
	docs, err := doc.Load(docFS, "md", doc.Options{URIScheme: uriScheme})
	require.NoError(t, err)

	h, stop := newMCP(embedlog.Logger{}, docs, testKey, nil)
	t.Cleanup(stop)

	return mcptest.New(t, h,
		mcptest.WithEra(era),
		mcptest.WithHeader("Authorization", "Bearer "+testKey))
}

// The server is dual-era, so the same catalogue has to come back whichever era
// asks for it. Running the whole thing twice is the only check of that claim
// that cannot pass by accident.
func TestExample(t *testing.T) {
	t.Parallel()
	for _, era := range []mcptest.Era{mcptest.Modern, mcptest.Legacy} {
		t.Run(string(era), func(t *testing.T) {
			t.Parallel()
			c := serve(t, era)

			t.Run("tools", func(t *testing.T) {
				list := c.Tools(t)
				require.Len(t, list.Tools, 1)
				assert.Equal(t, "hello", list.Tools[0].Name)
				assert.Equal(t, "Say hello", list.Tools[0].Title)
				assert.NotEmpty(t, list.Tools[0].OutputSchema, "the tool promises a shape")
				assert.Equal(t, mcp.CacheScopePrivate, list.CacheScope)
				assert.Empty(t, list.NextCursor, "one page, so no cursor")
			})

			// The answer arrives twice on purpose: structuredContent is what a
			// client validates against outputSchema, the text block is what an
			// older client and a model reading the transcript see.
			t.Run("tools/call answers as data and as text", func(t *testing.T) {
				res := c.CallTool(t, "hello", map[string]any{"who": "world"})
				require.False(t, res.IsError)
				require.Len(t, res.Content, 1)
				assert.JSONEq(t, `{"greeting":"hello, world"}`, res.Content[0].Text)
				assert.Equal(t, map[string]any{"greeting": "hello, world"}, res.StructuredContent)
			})

			// A tool that refuses still answers: the refusal travels inside a
			// successful response so the model can read it and try again.
			t.Run("a refusal is an envelope, not a transport error", func(t *testing.T) {
				res := c.CallTool(t, "nope", nil)
				assert.True(t, res.IsError)
				assert.Contains(t, res.Content[0].Text, "E_UNKNOWN_TOOL")
			})

			t.Run("resources", func(t *testing.T) {
				list := c.Resources(t)
				require.NotEmpty(t, list.Resources)
				uri := list.Resources[0].URI
				assert.Equal(t, uriScheme+"hello.md", uri)
				assert.Positive(t, list.Resources[0].Size)

				data := c.ReadResource(t, uri)
				require.Len(t, data.Contents, 1)
				assert.NotEmpty(t, data.Contents[0].Text)
				assert.Empty(t, data.Contents[0].Blob, "markdown is text")
			})

			t.Run("prompts", func(t *testing.T) {
				list := c.Prompts(t)
				require.NotEmpty(t, list.Prompts)
				name := list.Prompts[0].Name

				got := c.GetPrompt(t, name, map[string]string{"who": "world"})
				require.Len(t, got.Messages, 1)
				assert.Equal(t, mcp.RoleUser, got.Messages[0].Role)
				assert.Contains(t, got.Messages[0].Content.Text, "world")
			})
		})
	}
}

// Each era has one call the other does not: the handshake it replaced, and the
// discovery that replaced it. Both are answered, which is what dual-era means.
func TestExampleHandshakes(t *testing.T) {
	t.Parallel()

	t.Run("server/discover", func(t *testing.T) {
		t.Parallel()
		got := serve(t, mcptest.Modern).Discover(t)
		assert.Contains(t, got.SupportedVersions, mcp.ProtocolVersion)
		assert.NotNil(t, got.Capabilities.Tools)
		require.NotNil(t, got.Meta.ServerInfo)
		assert.Equal(t, "mcpkit-example", got.Meta.ServerInfo.Name)
	})

	t.Run("initialize", func(t *testing.T) {
		t.Parallel()
		got := serve(t, mcptest.Legacy).Initialize(t)
		assert.Equal(t, mcp.Version20251125, got.ProtocolVersion)
		assert.Equal(t, "mcpkit-example", got.ServerInfo.Name)
		assert.NotEmpty(t, got.Instructions)
	})
}

// The wiring outside the namespaces is what a copied example gets wrong, and
// it is only visible from a real request: no key, no answer.
func TestExampleRefusesAnUnauthenticatedCall(t *testing.T) {
	t.Parallel()
	docs, err := doc.Load(docFS, "md", doc.Options{URIScheme: uriScheme})
	require.NoError(t, err)
	h, stop := newMCP(embedlog.Logger{}, docs, testKey, nil)
	t.Cleanup(stop)

	res := mcptest.New(t, h).Call(t, "tools/list", nil)
	assert.Equal(t, http.StatusUnauthorized, res.Status)
	assert.NotEmpty(t, res.Header.Get("WWW-Authenticate"), "a 401 has to say how to authenticate")
}

// A denial has to reach the client as an answer to its call, through the
// transport and in either era — the limiter's own tests stop at a stub
// handler. The example allows sixty calls a minute, so the burst runs out
// within the loop.
func TestExampleRefusalAnswersTheCall(t *testing.T) {
	t.Parallel()
	for _, era := range []mcptest.Era{mcptest.Modern, mcptest.Legacy} {
		t.Run(string(era), func(t *testing.T) {
			t.Parallel()
			c := serve(t, era)
			hello := map[string]any{"name": "hello", "arguments": map[string]any{}}

			var res mcptest.Response
			for range 70 {
				if res = c.Call(t, "tools/call", hello); res.Status != http.StatusOK {
					break
				}
			}
			require.Equal(t, http.StatusTooManyRequests, res.Status, "%s", res.Body)
			assert.Equal(t, "application/json", res.Header.Get("Content-Type"))
			assert.NotEmpty(t, res.Header.Get("Retry-After"))
			require.NotNil(t, res.Error, "%s", res.Body)
			assert.Equal(t, mcp.CodeRateLimited, res.Error.Code)
			assert.Contains(t, string(res.Error.Data), `"reason":"rpm"`)
		})
	}
}

// An exempt name cannot be borrowed by repeating the key it is read from, in
// the same case or another: the limiter reads the first, the dispatcher runs
// the last. Built here rather
// than through newMCP, because it needs an exemption and a spent budget.
func TestExampleExemptionCannotBeBorrowed(t *testing.T) {
	t.Parallel()
	zsrv := zenrpc.NewServer(zenrpc.Options{})
	zsrv.RegisterAll(map[string]zenrpc.Invoker{
		mcpkit.NamespaceTools: ToolsService{registry: mcptool.NewRegistry(helloTool{})},
	})
	limiter := ratelimit.New(ratelimit.Config{
		CostBudgetPerHour: time.Nanosecond, // the first call spends it
		Exempt:            func(_, name string) bool { return name == "help" },
	})
	t.Cleanup(limiter.Stop)
	h := limiter.Middleware(mcpkit.NewServer(zsrv, embedlog.Logger{}), embedlog.Logger{})

	post := func(body string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body)))
		return rec.Code
	}
	hello := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hello","arguments":{}}}`
	require.Equal(t, http.StatusOK, post(hello))
	require.Equal(t, http.StatusTooManyRequests, post(hello), "the budget is spent")

	for _, borrowed := range []string{
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"help","name":"hello","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"help","Name":"hello","arguments":{}}}`,
	} {
		assert.NotEqual(t, http.StatusOK, post(borrowed), "hello ran under help's exemption: %s", borrowed)
	}
}
