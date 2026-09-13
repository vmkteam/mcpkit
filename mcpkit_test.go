package mcpkit_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/vmkteam/mcpkit"
	"github.com/vmkteam/mcpkit/doc"
	"github.com/vmkteam/mcpkit/mcp"
	"github.com/vmkteam/mcpkit/mcptest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
	"github.com/vmkteam/zenrpc/v2"
	"github.com/vmkteam/zenrpc/v2/smd"
)

const testScheme = "docs://"

func testLibrary(t *testing.T) *doc.Library {
	t.Helper()
	l, err := doc.Load(fstest.MapFS{
		"md/targets/grafana.md": &fstest.MapFile{Data: []byte("---\nname: grafana\ndescription: Dashboards.\n---\n\nBody.\n")},
		"md/prompts/triage.md": &fstest.MapFile{Data: []byte(
			"---\nname: triage\ndescription: Triage it.\narguments:\n  - name: service\n    required: true\n---\n\nLook at {{service}}.\n")},
	}, "md", doc.Options{URIScheme: testScheme})
	require.NoError(t, err)
	return l
}

// doc.Library is handed to the services as is — that is the point of the
// interfaces, and a compile-time check is the cheapest way to keep it true.
var (
	_ mcpkit.ResourceSource = (*doc.Library)(nil)
	_ mcpkit.PromptSource   = (*doc.Library)(nil)
	_ mcpkit.URINormalizer  = (*doc.Library)(nil)
)

func TestInitialize(t *testing.T) {
	t.Parallel()
	deps := mcpkit.InitDeps{
		Info:         mcp.ServerInfo{Name: "srv", Version: "1.0.0"},
		Capabilities: mcp.Capabilities{Tools: &mcp.ToolsCapability{ListChanged: true}},
		Instructions: "the voice of the service",
	}
	s := mcpkit.NewInitService(deps)

	t.Run("answers with what InitDeps said", func(t *testing.T) {
		t.Parallel()
		res, err := s.Initialize(mcp.ProtocolVersion)
		require.NoError(t, err)
		assert.Equal(t, deps.Info, res.ServerInfo)
		assert.Equal(t, deps.Capabilities, res.Capabilities)
		assert.Equal(t, deps.Instructions, res.Instructions)
	})

	// The revision is negotiated in the body, because at initialize the client
	// has not sent a header yet — it learns our revision from this answer.
	t.Run("negotiates the revision down, never up", func(t *testing.T) {
		t.Parallel()
		cases := map[string]string{
			mcp.ProtocolVersion: mcp.ProtocolVersion,
			mcp.Version20251125: mcp.Version20251125,
			"2025-08-01":        mcp.Version20250618,
			"2030-01-01":        mcp.ProtocolVersion,
			"":                  mcp.Version20250618,
		}
		for asked, want := range cases {
			res, err := s.Initialize(asked)
			require.NoError(t, err)
			assert.Equalf(t, want, res.ProtocolVersion, "asked %q", asked)
		}
	})

	t.Run("ping is an empty object", func(t *testing.T) {
		t.Parallel()
		res, err := s.Ping()
		require.NoError(t, err)
		b, err := json.Marshal(res)
		require.NoError(t, err)
		assert.JSONEq(t, `{"resultType":"complete"}`, string(b))
	})
}

func TestResources(t *testing.T) {
	t.Parallel()
	s := mcpkit.NewResourcesService(testLibrary(t))

	t.Run("list", func(t *testing.T) {
		t.Parallel()
		got, err := s.List(t.Context(), "")
		require.NoError(t, err)
		require.Len(t, got.Resources, 1)
		assert.Equal(t, testScheme+"targets/grafana.md", got.Resources[0].URI)
		assert.Equal(t, "Dashboards.", got.Resources[0].Description)
	})

	t.Run("read by canonical uri", func(t *testing.T) {
		t.Parallel()
		got, err := s.Read(t.Context(), testScheme+"targets/grafana.md")
		require.NoError(t, err)
		require.Len(t, got.Contents, 1)
		assert.Contains(t, got.Contents[0].Text, "Body.")
		assert.Equal(t, doc.MimeMarkdown, got.Contents[0].MimeType)
	})

	// The model types these out of instruction text and drops the scheme; the
	// answer still names the resource the way the catalogue named it.
	t.Run("read by bare path answers with the canonical uri", func(t *testing.T) {
		t.Parallel()
		got, err := s.Read(t.Context(), "targets/grafana.md")
		require.NoError(t, err)
		assert.Equal(t, testScheme+"targets/grafana.md", got.Contents[0].URI)
	})

	t.Run("unknown uri is a plain rpc error, not an isError envelope", func(t *testing.T) {
		t.Parallel()
		_, err := s.Read(t.Context(), "targets/nope.md")
		assert.ErrorContains(t, err, "resources.read")
	})

	// An empty catalogue is [] and not null: clients with strict schemas reject
	// null where an array was promised.
	t.Run("an empty source lists an empty array", func(t *testing.T) {
		t.Parallel()
		empty, err := doc.Load(nil, "", doc.Options{})
		require.NoError(t, err)
		got, err := mcpkit.NewResourcesService(empty).List(t.Context(), "")
		require.NoError(t, err)

		b, err := json.Marshal(got)
		require.NoError(t, err)
		assert.JSONEq(t, `{"resultType":"complete","resources":[],"ttlMs":0,"cacheScope":"private"}`, string(b))
	})

	t.Run("no source configured", func(t *testing.T) {
		t.Parallel()
		s := mcpkit.NewResourcesService(nil)
		got, err := s.List(t.Context(), "")
		require.NoError(t, err)
		assert.Empty(t, got.Resources)

		_, err = s.Read(t.Context(), "x")
		assert.ErrorContains(t, err, "no resource source")
	})
}

// doc indexes every file of the tree it is given, so a resource is not
// necessarily text. Reading one must not depend on that: a PNG pushed through
// the text field reaches the client with U+FFFD in place of every byte that was
// not valid UTF-8 — a document that parses and carries the wrong bytes.
func TestResourceReadEncodesBinary(t *testing.T) {
	t.Parallel()
	png := append([]byte("\x89PNG\r\n\x1a\n"), 0xff, 0xd8, 0x00, 0xfe)
	notUTF8 := []byte{0x48, 0xff, 0xfe, 0x69} // labelled text/plain by extension

	lib, err := doc.Load(fstest.MapFS{
		"md/hello.md":   &fstest.MapFile{Data: []byte("Body.\n")},
		"md/logo.png":   &fstest.MapFile{Data: png},
		"md/broken.txt": &fstest.MapFile{Data: notUTF8},
	}, "md", doc.Options{URIScheme: testScheme})
	require.NoError(t, err)
	s := mcpkit.NewResourcesService(lib)

	read := func(t *testing.T, uri string) mcp.ResourceContent {
		t.Helper()
		got, err := s.Read(t.Context(), uri)
		require.NoError(t, err)
		require.Len(t, got.Contents, 1)

		// Whatever the bytes were, the answer has to survive the encoder that
		// carries it — that is the failure this test exists for.
		raw, err := json.Marshal(got)
		require.NoError(t, err)
		var back mcp.ResourceData
		require.NoError(t, json.Unmarshal(raw, &back))
		// The contents, not the whole result: the cache hint is filled in by the
		// encoder, so a result built with no scope does not round-trip to itself
		// — and what this test is about is the bytes of the resource.
		require.Equal(t, got.Contents, back.Contents)
		return back.Contents[0]
	}

	t.Run("text stays text", func(t *testing.T) {
		t.Parallel()
		c := read(t, "hello.md")
		assert.Equal(t, "Body.\n", c.Text)
		assert.Empty(t, c.Blob)
	})

	t.Run("binary travels as base64", func(t *testing.T) {
		t.Parallel()
		c := read(t, "logo.png")
		assert.Empty(t, c.Text)
		decoded, err := base64.StdEncoding.DecodeString(c.Blob)
		require.NoError(t, err)
		assert.Equal(t, png, decoded, "the bytes come back exactly as they went in")
	})

	// The MIME type alone would not catch this one: .txt is text/plain, and the
	// bytes are still not text.
	t.Run("text/plain that is not valid utf-8 is binary", func(t *testing.T) {
		t.Parallel()
		c := read(t, "broken.txt")
		assert.Empty(t, c.Text)
		decoded, err := base64.StdEncoding.DecodeString(c.Blob)
		require.NoError(t, err)
		assert.Equal(t, notUTF8, decoded)
	})
}

// "Servers MUST include caching hints on results with resultType: complete"
// returned by the list operations and resources/read.
//
// The default scope is private, and that is the decision rather than an
// oversight: public lets any cache between the server and the client serve one
// caller's answer to another, and a catalogue that is the same for everybody is
// something only the service knows.
func TestCacheHints(t *testing.T) {
	t.Parallel()
	lib := testLibrary(t)

	// Scope() rather than the field: the field holds what the service said, which
	// is nothing here, and the default is filled in on the way out. The wire form
	// of that is TestCacheScopeIsFilledInByTheEncoder in mcp.
	t.Run("default is no freshness and private", func(t *testing.T) {
		t.Parallel()
		list, err := mcpkit.NewResourcesService(lib).List(t.Context(), "")
		require.NoError(t, err)
		assert.Equal(t, int64(0), list.TTLMs)
		assert.Equal(t, mcp.CacheScopePrivate, list.Scope())

		read, err := mcpkit.NewResourcesService(lib).Read(t.Context(), "targets/grafana.md")
		require.NoError(t, err)
		assert.Equal(t, mcp.CacheScopePrivate, read.Scope())

		prompts, err := mcpkit.NewPromptsService(lib).List("")
		require.NoError(t, err)
		assert.Equal(t, mcp.CacheScopePrivate, prompts.Scope())
	})

	t.Run("a service may declare its catalogue public", func(t *testing.T) {
		t.Parallel()
		hint := mcp.CacheHint{TTLMs: 300_000, CacheScope: mcp.CacheScopePublic}
		got, err := mcpkit.NewResourcesService(lib, mcpkit.WithResourceCache(hint)).List(t.Context(), "")
		require.NoError(t, err)
		assert.Equal(t, int64(300_000), got.TTLMs)
		assert.Equal(t, mcp.CacheScopePublic, got.CacheScope)
	})

	// The field is required on a cacheable result, so an unset scope has to
	// become a real one rather than travel as "".
	t.Run("an unset scope never reaches the wire", func(t *testing.T) {
		t.Parallel()
		got, err := mcpkit.NewResourcesService(lib, mcpkit.WithResourceCache(mcp.CacheHint{TTLMs: 1000})).List(t.Context(), "")
		require.NoError(t, err)
		b, err := json.Marshal(got)
		require.NoError(t, err)
		assert.NotContains(t, string(b), `"cacheScope":""`)
		assert.Contains(t, string(b), `"cacheScope":"private"`)
	})
}

// The hook is where a service hangs its audit without this package knowing what
// an audit is. It has to fire on the failures too — a trail of successes
// answers none of the questions it is kept for.
func TestReadHook(t *testing.T) {
	t.Parallel()
	type call struct {
		uri      string
		bytesOut int
		failed   bool
	}
	var calls []call
	s := mcpkit.NewResourcesService(testLibrary(t), mcpkit.WithReadHook(
		func(_ context.Context, uri string, bytesOut int, err error) {
			calls = append(calls, call{uri: uri, bytesOut: bytesOut, failed: err != nil})
		}))

	_, err := s.List(t.Context(), "")
	require.NoError(t, err)
	_, err = s.Read(t.Context(), "targets/grafana.md")
	require.NoError(t, err)
	_, err = s.Read(t.Context(), "targets/nope.md")
	require.Error(t, err)

	require.Len(t, calls, 3)
	assert.Empty(t, calls[0].uri, "list reports no uri")
	assert.False(t, calls[0].failed)
	// Canonical, though the caller typed the bare path: an audit that recorded
	// "targets/grafana.md" and "docs://targets/grafana.md" as two things could
	// not be grouped by resource, and neither name would match resources/list.
	assert.Equal(t, testScheme+"targets/grafana.md", calls[1].uri)
	assert.Positive(t, calls[1].bytesOut)
	assert.False(t, calls[1].failed)
	assert.True(t, calls[2].failed, "a refused read is still a read")
	assert.Zero(t, calls[2].bytesOut)
}

func TestPrompts(t *testing.T) {
	t.Parallel()
	s := mcpkit.NewPromptsService(testLibrary(t))

	t.Run("list", func(t *testing.T) {
		t.Parallel()
		got, err := s.List("")
		require.NoError(t, err)
		require.Len(t, got.Prompts, 1)
		assert.Equal(t, "triage", got.Prompts[0].Name)
		require.Len(t, got.Prompts[0].Arguments, 1)
		assert.True(t, got.Prompts[0].Arguments[0].Required)
	})

	t.Run("get renders one user message", func(t *testing.T) {
		t.Parallel()
		got, err := s.Get("triage", map[string]string{"service": "apisrv"})
		require.NoError(t, err)
		assert.Equal(t, "Triage it.", got.Description)
		require.Len(t, got.Messages, 1)
		assert.Equal(t, mcp.RoleUser, got.Messages[0].Role)
		assert.Equal(t, mcp.ContentTypeText, got.Messages[0].Content.Type)
		assert.Contains(t, got.Messages[0].Content.Text, "Look at apisrv.")
	})

	t.Run("a missing required argument is an error", func(t *testing.T) {
		t.Parallel()
		_, err := s.Get("triage", nil)
		assert.ErrorContains(t, err, "missing required argument")
	})

	t.Run("unknown prompt", func(t *testing.T) {
		t.Parallel()
		_, err := s.Get("nope", nil)
		assert.ErrorContains(t, err, "prompts.get")
	})

	t.Run("an empty source lists an empty array", func(t *testing.T) {
		t.Parallel()
		empty, err := doc.Load(nil, "", doc.Options{})
		require.NoError(t, err)
		got, err := mcpkit.NewPromptsService(empty).List("")
		require.NoError(t, err)
		b, err := json.Marshal(got)
		require.NoError(t, err)
		assert.JSONEq(t, `{"resultType":"complete","prompts":[],"ttlMs":0,"cacheScope":"private"}`, string(b))
	})

	t.Run("no source configured", func(t *testing.T) {
		t.Parallel()
		_, err := mcpkit.NewPromptsService(nil).Get("x", nil)
		assert.ErrorContains(t, err, "no prompt source")
	})
}

// What the caller is told when the name they sent is not there.
//
// zenrpc wraps a plain error as -32603 — the server reporting that it broke —
// and that is the wrong thing to say about a request that named a resource or a
// prompt which does not exist. The spec asks for -32602 there; a caller reading
// "internal error" retries the same call instead of correcting the name. The
// code -32002 that earlier revisions used for a missing resource must not be
// emitted at all by this revision.
func TestErrorCodes(t *testing.T) {
	t.Parallel()

	serve := func(rsrc mcpkit.ResourceSource, prompts mcpkit.PromptSource) func(*testing.T, string) map[string]any {
		zsrv := zenrpc.NewServer(zenrpc.Options{})
		zsrv.RegisterAll(map[string]zenrpc.Invoker{
			mcpkit.NamespaceResources: mcpkit.NewResourcesService(rsrc),
			mcpkit.NamespacePrompts:   mcpkit.NewPromptsService(prompts),
		})
		h := mcpkit.NewServer(zsrv, embedlog.Logger{})
		return func(t *testing.T, body string) map[string]any {
			t.Helper()
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body)))
			require.Equal(t, http.StatusOK, rr.Code, "a JSON-RPC error still travels in a 200 in this era")
			var out map[string]any
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
			e, ok := out["error"].(map[string]any)
			require.True(t, ok, "expected an error, got %s", rr.Body.String())
			return e
		}
	}

	lib := testLibrary(t)
	post := serve(lib, lib)

	// -32602 is what the caller can act on: the name was wrong, try another.
	for name, body := range map[string]string{
		"unknown resource":          `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"targets/nope.md"}}`,
		"unknown prompt":            `{"jsonrpc":"2.0","id":2,"method":"prompts/get","params":{"name":"nope"}}`,
		"missing required argument": `{"jsonrpc":"2.0","id":3,"method":"prompts/get","params":{"name":"triage"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := post(t, body)
			assert.InDelta(t, zenrpc.InvalidParams, e["code"], 0, "want -32602, got %v", e)
			assert.NotEqual(t, float64(-32002), e["code"], "the code of earlier revisions must not be emitted")
		})
	}

	// The other half of the rule: a server that really is misconfigured says so.
	// Turning every failure into -32602 would tell the caller to fix a name that
	// was never the problem.
	t.Run("a server-side failure stays -32603", func(t *testing.T) {
		t.Parallel()
		e := serve(nil, nil)(t, `{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"x"}}`)
		assert.InDelta(t, zenrpc.InternalError, e["code"], 0, "want -32603, got %v", e)
	})
}

// Paging is off by default and has to stay off: a service that never asked for
// it must keep answering with the whole catalogue and no nextCursor, because a
// client sees one and comes back for a page that does not exist.
func TestPagination(t *testing.T) {
	t.Parallel()

	files := fstest.MapFS{}
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		files["md/"+n+".md"] = &fstest.MapFile{Data: []byte("---\nname: " + n + "\n---\n\nBody.\n")}
		files["md/prompts/"+n+".md"] = &fstest.MapFile{Data: []byte("---\nname: p" + n + "\n---\n\nSay {{x}}.\n")}
	}
	lib, err := doc.Load(files, "md", doc.Options{URIScheme: testScheme})
	require.NoError(t, err)

	t.Run("off by default", func(t *testing.T) {
		t.Parallel()
		got, err := mcpkit.NewResourcesService(lib).List(t.Context(), "")
		require.NoError(t, err)
		assert.Len(t, got.Resources, 5)
		assert.Empty(t, got.NextCursor)

		b, err := json.Marshal(got)
		require.NoError(t, err)
		assert.NotContains(t, string(b), "nextCursor", "an absent cursor is the end of the enumeration; it must not travel empty")
	})

	// What a client actually does: call, take nextCursor, call again, stop when
	// there is none. Over the wire, because the cursor has to survive the
	// round trip through JSON and zenrpc's parameter decoding.
	t.Run("a client walks the catalogue to the end", func(t *testing.T) {
		t.Parallel()
		zsrv := zenrpc.NewServer(zenrpc.Options{})
		zsrv.RegisterAll(map[string]zenrpc.Invoker{
			mcpkit.NamespaceResources: mcpkit.NewResourcesService(lib, mcpkit.WithResourcePageSize(2)),
			mcpkit.NamespacePrompts:   mcpkit.NewPromptsService(lib, mcpkit.WithPromptPageSize(2)),
		})
		h := mcpkit.NewServer(zsrv, embedlog.Logger{})

		call := func(t *testing.T, method, cursor string) map[string]any {
			t.Helper()
			body, err := json.Marshal(map[string]any{
				"jsonrpc": "2.0", "id": 1, "method": method,
				"params": map[string]any{"cursor": cursor},
			})
			require.NoError(t, err)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(string(body))))
			require.Equal(t, http.StatusOK, rr.Code)
			var out struct {
				Result map[string]any  `json:"result"`
				Error  *map[string]any `json:"error"`
			}
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
			require.Nil(t, out.Error, "unexpected error: %s", rr.Body.String())
			return out.Result
		}

		for _, tc := range []struct{ method, field, key string }{
			{"resources/list", "resources", "uri"},
			{"prompts/list", "prompts", "name"},
		} {
			t.Run(tc.method, func(t *testing.T) {
				t.Parallel()
				var got []string
				cursor := ""
				for i := 0; ; i++ {
					require.Less(t, i, 10, "enumeration did not terminate")
					res := call(t, tc.method, cursor)
					entries, ok := res[tc.field].([]any)
					require.True(t, ok, "no %s in %v", tc.field, res)
					assert.LessOrEqual(t, len(entries), 2)
					for _, e := range entries {
						got = append(got, e.(map[string]any)[tc.key].(string))
					}
					next, _ := res["nextCursor"].(string)
					if next == "" {
						break
					}
					cursor = next
				}
				assert.Len(t, got, 5, "every entry exactly once: %v", got)
				assert.Len(t, slices.Compact(slices.Sorted(slices.Values(got))), 5, "no entry twice: %v", got)
			})
		}

		// A cursor this server did not issue is the caller's mistake, and the
		// caller can act on -32602: start the enumeration again.
		t.Run("an invalid cursor is -32602", func(t *testing.T) {
			t.Parallel()
			for name, cursor := range map[string]string{
				"malformed": "!!!!",
				"stale":     mcp.EncodeCursor(testScheme + "gone.md"),
			} {
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					body := `{"jsonrpc":"2.0","id":1,"method":"resources/list","params":{"cursor":"` + cursor + `"}}`
					rr := httptest.NewRecorder()
					h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body)))
					var out map[string]any
					require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
					e, ok := out["error"].(map[string]any)
					require.True(t, ok, "expected an error, got %s", rr.Body.String())
					assert.InDelta(t, zenrpc.InvalidParams, e["code"], 0, "want -32602, got %v", e)
				})
			}
		})
	})
}

// mcptest and the transport have to agree on every header name, every reserved
// _meta key and the sentinel, or the fixture quietly tests a request no client
// would send. Running the fixture against the real validator is the only check
// of that which cannot drift.
func TestMcptestRequestsPassValidation(t *testing.T) {
	t.Parallel()

	// A Cyrillic filename on purpose: its URI cannot travel in a header as
	// itself, so this is the case that exercises the Base64 sentinel end to end
	// — the fixture encodes, the transport decodes, and they compare equal.
	const cyrillic = "привет.md"
	lib, err := doc.Load(fstest.MapFS{
		"md/" + cyrillic:      &fstest.MapFile{Data: []byte("---\nname: hi\n---\n\nBody.\n")},
		"md/prompts/greet.md": &fstest.MapFile{Data: []byte("---\nname: greet\n---\n\nSay hi.\n")},
	}, "md", doc.Options{URIScheme: testScheme})
	require.NoError(t, err)

	deps := mcpkit.InitDeps{
		Info:         mcp.ServerInfo{Name: "srv", Version: "1.0.0"},
		Capabilities: mcp.Capabilities{Resources: &mcp.ResourcesCapability{}, Prompts: &mcp.PromptsCapability{}},
	}
	zsrv := zenrpc.NewServer(zenrpc.Options{})
	zsrv.RegisterAll(map[string]zenrpc.Invoker{
		"":                        mcpkit.NewInitService(deps),
		mcpkit.NamespaceServer:    mcpkit.NewDiscoverService(deps),
		mcpkit.NamespaceResources: mcpkit.NewResourcesService(lib),
		mcpkit.NamespacePrompts:   mcpkit.NewPromptsService(lib),
	})
	h := mcpkit.NewServer(zsrv, embedlog.Logger{})

	for _, era := range []mcptest.Era{mcptest.Modern, mcptest.Legacy} {
		t.Run(string(era), func(t *testing.T) {
			t.Parallel()
			c := mcptest.New(t, h, mcptest.WithEra(era))

			assert.NotEmpty(t, c.Resources(t).Resources)
			assert.NotEmpty(t, c.Prompts(t).Prompts)
			assert.NotEmpty(t, c.GetPrompt(t, "greet", nil).Messages)

			got := c.ReadResource(t, testScheme+cyrillic)
			require.Len(t, got.Contents, 1)
			assert.Contains(t, got.Contents[0].Text, "Body.")
		})
	}

	// The other direction: a version the server does not speak is refused with
	// the code and the status this revision fixes, which is what a test reaches
	// through WithProtocolVersion.
	t.Run("an unsupported revision is -32022 and a 400", func(t *testing.T) {
		t.Parallel()
		res := mcptest.New(t, h, mcptest.WithProtocolVersion("1999-01-01")).Call(t, "resources/list", nil)
		assert.Equal(t, http.StatusBadRequest, res.Status)
		require.NotNil(t, res.Error)
		assert.Equal(t, mcp.CodeUnsupportedProtocolVersion, res.Error.Code)
	})

	// And a broken mirror: a header that disagrees with the body is -32020,
	// which is the hole those headers exist to close.
	t.Run("a header that disagrees with the body is -32020", func(t *testing.T) {
		t.Parallel()
		c := mcptest.New(t, h, mcptest.WithHeader(mcp.HeaderMethod, "tools/call"))
		res := c.Call(t, "resources/list", nil)
		assert.Equal(t, http.StatusBadRequest, res.Status)
		require.NotNil(t, res.Error)
		assert.Equal(t, mcp.CodeHeaderMismatch, res.Error.Code)
	})
}

// toolsService stands in for the service's own dispatcher: the point of the
// check is that a generated service from this package and one from another
// package register side by side, dispatch, and both appear in SMD.
type toolsService struct{ zenrpc.Service }

func (toolsService) Invoke(_ context.Context, method string, _ json.RawMessage) zenrpc.Response {
	if method != "list" {
		return zenrpc.NewResponseError(nil, zenrpc.MethodNotFound, "no such tool method", nil)
	}
	raw := json.RawMessage(`{"tools":[]}`)
	return zenrpc.Response{Version: zenrpc.Version, Result: &raw}
}

func (toolsService) SMD() smd.ServiceInfo {
	return smd.ServiceInfo{Methods: map[string]smd.Service{"list": {Description: "tools of the service"}}}
}

func TestEndToEndOverTransport(t *testing.T) {
	t.Parallel()
	lib := testLibrary(t)

	zsrv := zenrpc.NewServer(zenrpc.Options{})
	zsrv.RegisterAll(map[string]zenrpc.Invoker{
		"": mcpkit.NewInitService(mcpkit.InitDeps{
			Info:         mcp.ServerInfo{Name: "srv", Version: "1.0.0"},
			Instructions: "hello",
		}),
		mcpkit.NamespaceResources: mcpkit.NewResourcesService(lib),
		mcpkit.NamespacePrompts:   mcpkit.NewPromptsService(lib),
		mcpkit.NamespaceTools:     toolsService{},
	})
	h := mcpkit.NewServer(zsrv, embedlog.Logger{})

	// The older era, because that is what this test is about: a client that
	// sends initialize and then plain requests, with no _meta and no mirrored
	// headers. mcptest builds those, so what is written here is the assertion
	// rather than the envelope around it.
	client := func(t *testing.T, opts ...mcptest.Option) *mcptest.Client {
		t.Helper()
		return mcptest.New(t, h, append([]mcptest.Option{
			mcptest.WithEra(mcptest.Legacy), mcptest.WithPath("/mcp"),
		}, opts...)...)
	}

	// A revision below the era's default on purpose: the answer has to come
	// back negotiated down to the one asked for, not up to ours.
	t.Run("initialize", func(t *testing.T) {
		t.Parallel()
		res := client(t, mcptest.WithProtocolVersion(mcp.Version20250618)).Initialize(t)
		assert.Equal(t, mcp.Version20250618, res.ProtocolVersion)
		assert.Equal(t, "hello", res.Instructions)
	})

	t.Run("resources/list and read", func(t *testing.T) {
		t.Parallel()
		c := client(t)
		require.Len(t, c.Resources(t).Resources, 1)
		// The bare path, without the scheme: the model types these out of the
		// instruction text, and the server is expected to take them.
		require.Len(t, c.ReadResource(t, "targets/grafana.md").Contents, 1)
	})

	t.Run("prompts/get", func(t *testing.T) {
		t.Parallel()
		got := client(t).GetPrompt(t, "triage", map[string]string{"service": "apisrv"})
		require.Len(t, got.Messages, 1)
	})

	// The service's own namespace keeps working beside the library's: each has
	// its own generated file, and SMD collects both.
	t.Run("the service keeps its own tools namespace", func(t *testing.T) {
		t.Parallel()
		res := client(t).Call(t, "tools/list", nil)
		require.Nil(t, res.Error, res.Body)
		assert.NotEmpty(t, res.Result)
	})

	t.Run("SMD describes services from both packages", func(t *testing.T) {
		t.Parallel()
		schema := zsrv.SMD()
		names := make([]string, 0, len(schema.Services))
		for name := range schema.Services {
			names = append(names, name)
		}
		// SMD names methods as they are declared in Go; dispatch lowercases the
		// incoming name, which is why both spellings appear in one server.
		assert.Contains(t, names, "tools.list")
		assert.Contains(t, names, "resources.List")
		assert.Contains(t, names, "prompts.Get")
		assert.Contains(t, names, "Initialize")
	})
}
