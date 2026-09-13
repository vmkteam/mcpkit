# mcpkit

[![Linter Status](https://github.com/vmkteam/mcpkit/actions/workflows/golangci-lint.yml/badge.svg?branch=master)](https://github.com/vmkteam/mcpkit/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/vmkteam/mcpkit)](https://goreportcard.com/report/github.com/vmkteam/mcpkit)
[![Go Reference](https://pkg.go.dev/badge/github.com/vmkteam/mcpkit.svg)](https://pkg.go.dev/github.com/vmkteam/mcpkit)

The frame of an MCP server for Go services: the Streamable HTTP transport, the
way in, and the limits in front of it. The tools are yours — they are the reason
your service exists, and this library deliberately has no opinion about them.

```
go get github.com/vmkteam/mcpkit
```

Go 1.26. No `echo`, no ORM, no config reader: the packages take structs and
return `http.Handler`.

## Where this sits

This is not an SDK. There is no client, no stdio, no SSE, no progress
notifications: one transport, Streamable HTTP, POST only. If you need any of
those, the official [go-sdk](https://github.com/modelcontextprotocol/go-sdk)
has them.

What it has instead is the part around the protocol — who is asking, how often
they may ask, what must not leave in the answer, and what gets written down.
The industry puts that in a separate process: a gateway in front of many MCP
servers. A gateway pays off at a dozen servers; at three, each one an ordinary
Go service, importing a package is cheaper than running another process with
its own Redis and Postgres.

Four things here that we did not find elsewhere:

- **A work budget, not a request count.** `ratelimit.Charge` limits by time
  spent. Where one call can cost thirty seconds of ClickHouse, requests per
  minute measure nothing.
- **Log-injection defence.** `audit.SanitizeText` escapes ANSI and newlines: a
  model-authored string lands in your log.
- **Visibility is the tool's own answer,** recomputed on every `tools/list` —
  not a filter applied to a list cached per session, which can hand one caller
  the tools of another.
- **Errors as documentation.** A refusal carries a hint listing what *is*
  available, because the reader is a model that will retry.

## Packages

| Package | What it does |
|---|---|
| `mcpkit` | The server: MCP Streamable HTTP on `zenrpc.Server` — `tools/list` → `tools.list`, one request per POST, both protocol eras on one endpoint — and the ready-made services `initialize`/`ping`, `server/discover`, `resources.*`, `prompts.*` |
| `mcp` | The wire format: `Tool`, `ContentBlock`, `Capabilities`, `ResourceEntry`, … plus the revisions and `NegotiateVersion`, the modern era's headers and `_meta` keys, `Paginate`, `DecodeArgs`, `SchemaFor`, `Truncate`, `CutRunes` |
| `doc` | A tree of markdown with YAML frontmatter, served as resources and prompts |
| `mcptool` | The tool dispatcher: registry, answer envelope, error with a hint, the call metric |
| `auth` | Who is asking: api-key store, OIDC verifier, `Principal` in the context, RFC 9728 metadata |
| `auth/authtest` | A fake IdP that signs tokens, for the tests of a service that uses `auth` |
| `mcptest` | A client for your tests: starts your handler and sends correct requests of either era |
| `ratelimit` | Requests per minute, concurrency and an hourly work budget, per caller |
| `redact` | Masking personal data on the way out: seven rules, three modes |
| `audit` | One record per call — who asked, what was decided, what came out |

Dependencies run strictly downward: `mcpkit` → `mcp`; `doc` → `mcp`; `mcptool` →
`mcp`; `mcptest` → `mcp`; `ratelimit` → `auth`; `audit` → `redact`. Nothing points back up, `mcp`
depends on nothing, and `auth` is imported by exactly one package — `ratelimit`,
which keys its buckets on the principal. The server, the dispatcher and the
catalogues never learn who is asking.

The transport and the handshake are one package because neither stands up
alone: a server that answers `POST` but has no `initialize` is not an MCP
server, and the services that answer `initialize` have nothing to be served
over. The line between them ran along a technology — HTTP on one side, JSON-RPC
on the other — and not along a question you answer for yourself.

## The recipe

```go
docs, _ := doc.Load(docFS, "md", doc.Options{URIScheme: "docs://"})
tools := mcptool.NewRegistry(helloTool{}, queryTool{}) // yours

deps := mcpkit.InitDeps{
    Info: mcp.ServerInfo{Name: "mysrv", Version: version},
    // Declare exactly what you register: a capability is a promise to answer.
    Capabilities: mcp.Capabilities{
        Tools:     &mcp.ToolsCapability{},
        Resources: &mcp.ResourcesCapability{},
        Prompts:   &mcp.PromptsCapability{},
    },
    Instructions: instructions, // the voice of your service
}

zsrv := zenrpc.NewServer(zenrpc.Options{})
zsrv.RegisterAll(map[string]zenrpc.Invoker{
    // Both eras: initialize for the clients that still open with a handshake,
    // server/discover for the ones that no longer do.
    "":                        mcpkit.NewInitService(deps),
    mcpkit.NamespaceServer:    mcpkit.NewDiscoverService(deps),
    mcpkit.NamespaceResources: mcpkit.NewResourcesService(docs),
    mcpkit.NamespacePrompts:   mcpkit.NewPromptsService(docs),
    mcpkit.NamespaceTools:     ToolsService{registry: tools}, // six lines, yours
})

keys := auth.NewStore(cfg.APIKeys)
limiter := ratelimit.New(ratelimit.Config{PerUserRPM: 60, PerUserConcurrent: 4})
defer limiter.Stop()

var h http.Handler = mcpkit.NewServer(zsrv, logger)
h = limiter.Middleware(h, logger) // inside: the limit is per Principal.UserID
h = keys.Middleware(h, logger)    // outside: who is asking

mux.Handle("/mcp", h)
mux.Handle("/.well-known/oauth-protected-resource", auth.ProtectedResource{
    Resource: cfg.BaseURL + "/mcp",
    Issuer:   cfg.OIDC.Issuer,
}.Handler())
```

**The order of the wrappers is the mistake to avoid.** Authentication goes
outside, the limiter inside. A limiter that runs first sees no principal, buckets
every caller as `anonymous`, and the per-user limit silently means nothing.

The consequence of that order: a request that fails authentication never reaches
the limiter. Nothing here caps the rate of 401s, and each one writes a log line.
A key is 32 bytes and will not be guessed, but the flood is free — if the
endpoint faces the internet, put a per-IP limit in front of the whole thing.

A running version of all of the above is in [example/main.go](example/main.go):

```
make run
curl -s localhost:8075/mcp -H 'Authorization: Bearer demo-token' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}'
```

## mcpkit

One endpoint. `POST` is a JSON-RPC 2.0 request and always gets a synchronous
JSON response; a notification — no `id`, or a null one — is dispatched and
answered with `202` and an empty body. `GET` and `DELETE` are `405` with
`Allow: POST`: the server pushes nothing and holds no session, and saying so is
better than opening a stream that dies. A JSON array in the body — a JSON-RPC
batch — is `400`, and a body over 4 MiB is `413`.

MCP method names carry a slash, zenrpc dispatches on `namespace.method`, so the
transport rewrites `tools/list` into `tools.list` before dispatching. A third
segment is folded into the method name — `resources/templates/list` becomes
`resources.templatesList` — because zenrpc splits on the *first* dot and
`resources.templates.list` is not a name any Go method can have. Your services
are plain zenrpc services registered under the `tools`, `resources`, `prompts`,
`server` and `notifications` namespaces.

### Both eras on one endpoint

Revision 2026-07-28 removed the `initialize` handshake: the protocol version,
the client's identity and its capabilities travel in the `_meta` of every
request, and the `Mcp-Protocol-Version`, `Mcp-Method` and `Mcp-Name` headers
mirror them so a proxy can route without parsing the body. Everything up to
2025-11-25 works the old way.

This server answers both, which the spec allows — and the era is a property of
the request, not of the connection, so it costs no state either way:

| The request carries | Treated as | What it gets |
|---|---|---|
| `Mcp-Protocol-Version: 2026-07-28` or `_meta` | modern | `_meta` and the headers are checked; `-32601` is a `404`, a header that disagrees with the body is `-32020` and a `400` |
| an older version header, or nothing | legacy | dispatched as before; every JSON-RPC error stays inside a `200` |

The check runs body-first: the body is the truth and the header is its mirror,
because trusting the header instead is the hole those headers exist to close —
a gateway routing on one value while the server executes another.

`mcpkit.NewDiscoverService(deps)` under `mcpkit.NamespaceServer` answers
`server/discover`, which replaced the handshake and which a modern server *MUST*
implement. It negotiates nothing: it reports the revisions, the capabilities and
the identity, and a request naming a revision we do not speak is refused with
`-32022` rather than quietly served under another one.

Every result carries `resultType: "complete"`, in both eras. It is written by the
encoder rather than by each service, so a service that builds an `mcp.ToolList`
by hand still answers correctly, and a client of an older revision ignores the
key — which its own revision requires it to do.

For the older era, revisions are still negotiated down, never up:

```go
mcp.NegotiateVersion("2025-08-01") // "2025-06-18"
```

A client that asks for a revision we do not speak gets the newest one below it.
Answering with our newest is what the spec allows and what makes a strict client
disconnect with "Server's protocol version is not supported" — a revision older
than the client's is one it is required to understand.

`NewServerWithOptions` raises the body limit, switches on one log line per
`initialize` — which is how you find out what a client actually speaks — and
takes the origins a browser may call from.

**`Origin` is refused by default.** The spec is blunt about it — servers *MUST*
validate the header to stop a page in somebody's browser from reaching a server
on their own machine — so a request carrying any `Origin` gets a 403 until
`AllowedOrigins` says otherwise. A caller outside a browser sends no `Origin` and
never meets the check: `mcpurl`, Claude Code and curl are unaffected. A service
with a web client lists its origins; `"*"` switches the check off.

**`AllowedHosts` closes what `Origin` cannot.** In a DNS rebinding attack the
page at `http://evil.com` reaches `http://evil.com:8075`, whose name has just
been re-resolved to `127.0.0.1`. To the browser that is the *same* origin, so no
`Origin` header is sent at all and the check above has nothing to refuse. Only
the `Host` says what the client thought it was talking to.

The default is off: in production the proxy in front already answers this — an
nginx `server_name` is exactly this check — and a strict default would refuse
every deployment that had not listed its own name. A server bound to a
developer's loopback has no such proxy, which is why `example/main.go` fills the
list in from its own `-addr`.

There is no CORS here, and `zenrpc.Options{AllowCORS: true}` does not add any:
zenrpc reads that option inside its own `ServeHTTP`, and this transport calls
`zsrv.Do()` directly. A browser client needs the origins listed above *and* CORS
headers from whatever mounts the handler.

Declare only the capabilities you register. `Capabilities` holds three pointers,
so saying nothing about prompts is expressible — and it has to be, because a
server that declares them promises to answer `prompts/list`, and one that
declared all three by default sent the client into two namespaces that answer
`-32601`.

Paging is off by default, and that is a decision rather than a stub: a page is a
round trip the model waits through before it can use any of the list, and a
catalogue of a few dozen entries is cheaper sent whole. Turn it on where you know
better:

```go
mcpkit.NewResourcesService(docs, mcpkit.WithResourcePageSize(50))
mcpkit.NewPromptsService(docs, mcpkit.WithPromptPageSize(50))
mcptool.NewRegistry(tools...).With(mcptool.WithPageSize(50))
```

The client then walks `nextCursor` until it is absent. The cursor is opaque by
the protocol's rule; ours names the last entry of the page, so a cursor whose
entry is gone is refused with `-32602` rather than silently resolved to a
neighbouring position. Your `ToolsService.List` passes the cursor through and
wraps the error — `mcpkit.RPCError` is what makes it a `-32602` instead of the
`-32603` zenrpc gives any plain error:

```go
func (s ToolsService) List(ctx context.Context, cursor string) (mcp.ToolList, error) {
    list, err := s.registry.List(ctx, cursor)
    return list, mcpkit.RPCError("tools.list", err)
}
```

Every cacheable result carries `ttlMs` and `cacheScope` — the revision requires
the pair on `server/discover` and on the four list operations — and the default
is `{0, private}`: keep it no time at all, and never share it. That is the only
answer a library can give for a catalogue whose rate of change it does not know.
The default is filled in by the encoder, on the way out, so a result you build
by hand names a scope whether or not you set one. Say better where you know your
own:

```go
hint := mcp.CacheHint{TTLMs: 300_000, CacheScope: mcp.CacheScopePublic}

deps.CacheHint = hint                                        // server/discover
mcpkit.NewResourcesService(docs, mcpkit.WithResourceCache(hint))
mcpkit.NewPromptsService(docs, mcpkit.WithPromptCache(hint))
mcptool.NewRegistry(tools...).With(mcptool.WithCache(hint))
```

**`public` on a list that depends on who asked is a leak**, and that is why the
default is not it. The spec lets a client share such a response between callers
— "responses with a `public` `cacheScope` may be shared between callers even if
the Result is coming from an authenticated endpoint" — so a `tools/list` filtered
through `Describe(ctx)` would hand one user the tools of another, through a cache
this server never sees. `public` is a promise about your catalogue, made by
whoever knows it.

Metrics: `app_mcp_transport_rejected_total{reason}` — `batch`, `parse`,
`too_large`, `read_body`, `dispatch`, `method_not_allowed`, `origin`, `host`,
plus the modern-era refusals `header_mismatch`, `bad_version`, `missing_meta`; and
`app_mcp_requests_total{era}`, which is how you find out whether
anything still speaks the old one. A request refused here reaches no handler and
appears in no other series, so without these counters a client that speaks the
wrong dialect is invisible.

## auth

Two backends, one `Principal` in the request context:

```go
p, ok := auth.PrincipalFromContext(ctx) // UserID, Email, Roles, Groups
```

**Api keys.** The config holds sha256 hashes, never plaintext; both `sha256:…`
and bare hex are accepted, comparison is constant-time. An empty store is a
no-op middleware — that is the dev mode, and whether production may run in it is
your call. `Store.Keys()` is there so a service can refuse to start with a key
that carries no groups: such a key authenticates and then fails every call with
403, which reads as a broken server rather than a misconfigured key.

**OIDC.** Discovery plus JWKS at startup, nothing per request. With `Audience`
set (RFC 8707) the token must carry it in `aud` and `azp` is not consulted at
all, so a token minted for the same client and another resource does not open
this one. Without it the check falls back to `ClientID` in `aud` or `azp`, which
is what keeps a stand working before the IdP maps audiences. `RequiredRoles` is
matched against roles ∪ groups, because access is modelled one way in one
service and the other way in the next.

Pass an `HTTPClient` in production: discovery and the JWKS refreshes are the one
request that decides whether anyone can log in, and it should land in your client
metrics. Without one the verifier uses a client with `DefaultDiscoveryTimeout`
rather than `http.DefaultClient`, which has no timeout and would let an IdP that
accepts the connection and then says nothing hold the boot open.

A failed verification answers with the outcome and nothing else — `invalid
token`, `token expired`, `insufficient permissions`. The roles the token carried
and the audience this server expects go to the log, where the operator is; the
caller gets neither.

**RFC 9728.** `ProtectedResource{}.Handler()` is what a client fetches after a
401 to find the authorization server. Without an `Issuer` it answers 404 rather
than a document with an empty list: the document says "this resource is
protected", and a client that believes it starts OAuth against a server that
wants none.

Metrics: `app_mcp_oidc_verify_total{result}` — `ok`, `missing`, `invalid`,
`expired`, `forbidden` — registered in the default registry on first use, with
every series starting at zero.

## ratelimit

```go
limiter := ratelimit.New(ratelimit.Config{
    PerUserRPM:        60,
    PerUserConcurrent: 4,
    GlobalConcurrent:  32,
    CostBudgetPerHour: 30 * time.Minute,
})
defer limiter.Stop()
```

Each limit is switched off by a value ≤ 0; with all four off `Middleware`
returns your handler unwrapped. Only `POST` is counted — the listening `GET`
would hold a concurrency slot for the lifetime of a bridge and drain the bucket
by reconnecting. A denial is `429` with `Retry-After: 10`.

The bucket is keyed by `Principal.UserID`, so the limiter has to run inside the
authentication middleware. Everything is in memory and resets with the process:
this stops a client that lost its mind, it is not a billing quota. The hourly
budget is a fixed window, not a sliding one — a burst across the boundary passes
twice, which is fine for a limiter and would not be for a quota.

When one request can do several pieces of work, the wall clock stops being the
price: it reports the longest of them while the server did the sum. Whoever does
the work says so:

```go
start := time.Now()
// … one upstream call …
ratelimit.Charge(ctx, time.Since(start))
```

`Charge` is safe to call concurrently and does nothing when limits are off, so a
handler never has to ask whether they are. A request that charges nothing is
priced by its wall clock.

Metrics: `app_mcp_ratelimit_denied_total{reason}` — `rpm`, `user_concurrent`,
`global_concurrent`, `cost_budget` — and `app_mcp_ratelimit_inflight{scope}` with
`user` and `global`.

## mcp and doc

`mcp` is the wire format: no I/O, no state, no opinion about where a
`ResourceEntry` came from. Beside the types it carries the pure functions that
have nowhere better to live and that every other package would otherwise write
twice.

The revisions are among them — `ProtocolVersion`, `SupportedVersions` and
`NegotiateVersion` — because which revisions a server speaks is a fact about the
protocol and not about HTTP. `mcpkit` reads that rule twice, once to fill the
`Mcp-Protocol-Version` header and once to answer `initialize`, and owns it
neither time: a second transport would find the list where this one did, in the
package that describes the protocol.

So is the rest of the modern era's vocabulary: the header names, the reserved
`_meta` keys, the error codes `-32020`/`-32021`/`-32022`, `NamePathFor` (which
body field `Mcp-Name` mirrors for a given method) and the Base64 sentinel that
carries a value a header cannot hold. `mcptest` fills those in and `mcpkit`
checks them, and two lists of the same names would drift.

`Paginate` is there for the same reason — one cursor scheme for tools, resources
and prompts rather than three that disagree about what an invalid cursor is.

The rest are the helpers every dispatcher needs: `DecodeArgs` (the argument map
into your struct), `SchemaFor` (a JSON Schema reflected from that same struct,
once, at startup) and `Truncate` / `CutRunes` (a cut on a rune boundary, because
a byte slice of UTF-8 breaks the JSON that carries it — every cut in this
library goes through one of the two, since the one that did not was the one that
was wrong).

`mcpkit` has the three services nobody writes differently. `initialize` takes a
flat `protocolVersion` argument — MCP sends the handshake as a flat object, and
a struct argument makes zenrpc look for a nested `params` no client sends — and
negotiates the revision in the body. `resources.*` and `prompts.*` take
interfaces, so a service can keep its own catalogue:

```go
type ResourceSource interface {
    Resources() []mcp.ResourceEntry
    Read(uri string) (data []byte, mimeType string, err error)
}
```

`WithReadHook` is where a service audits catalogue reads without this package
learning what an audit is.

A resource is not necessarily text: bytes that are not valid UTF-8 — or whose
MIME type is not textual — travel base64-encoded in `blob` rather than in `text`,
because a PNG pushed through a JSON string comes back with `U+FFFD` in place of
every byte the encoder could not represent. A name the catalogue does not know
is `-32602`, not `-32603`: the caller can act on "no such resource" and cannot
act on "the server broke". Mark such a failure in your own source with
`mcp.ErrInvalidParams` and the services will answer with the right code.

`doc` is the default implementation of both: one `fs.FS`, markdown with YAML
frontmatter, everything outside the prompts subtree a resource and the prompts
subtree prompts. A `*doc.Library` is handed to the services as is. A file with no
`description:` gets the first prose paragraph of its body, because an entry
without a description costs the model a call to find out what it is. Two files
claiming one name fail the load rather than letting walk order decide.

`{{arg}}` placeholders are rewritten to `{{.arg}}` and rendered by
`text/template`: whoever writes the markdown is not required to know about Go
templates.

## mcptool

```go
type Tool interface {
    Name() string
    Describe(ctx context.Context) (mcp.Tool, bool)
    Call(ctx context.Context, args map[string]any) mcp.ToolCallResult
}
```

`Describe` is asked on every `tools/list`, because the answer depends on who is
asking, and it reports `false` when this caller may not see the tool at all —
that is how visibility stays the tool's business and the registry never learns
what a role is. A tool a caller cannot see is refused exactly like one that does
not exist.

The list is computed per request and keeps the order you built it in: the model
reads it top to bottom, and a cached list hands one user the tools of another.

An error is documentation, so it carries a hint:

```go
return mcptool.ErrorResult(mcptool.Error{
    Code:    "E_TARGET_UNKNOWN",
    Message: "no such target",
    Hint:    map[string]any{"targets": known}, // what to try instead
})
```

Codes are your vocabulary; the library owns only `E_UNKNOWN_TOOL` and
`E_ENCODE`. Batching, access rules and budgets stay in the service — they are
the same idea in three services and not the same code.

`E_UNKNOWN_TOOL` is the one code the library says on your behalf, and
`WithUnknownTool` takes it back. It answers both the name nothing is registered
under and the name whose `Describe` hid it — the default cannot tell them apart,
and a service that wants to say "no such tool" to one and "your role does not
grant it" to the other says so here:

```go
mcptool.NewRegistry(tools...).With(mcptool.WithUnknownTool(
    func(ctx context.Context, name string, visible []string) mcp.ToolCallResult {
        if slices.Contains(allTools, name) { // registered, but not for this caller
            return mcptool.ErrorResult(mcptool.Error{Code: "ForbiddenRole", Message: …})
        }
        return mcptool.ErrorResult(mcptool.Error{Code: "NoSuchTool", Hint: visible})
    }))
```

Hiding it is still the default, and for most servers the right one: telling a
caller which tools they are missing is an answer they were not meant to get.

`WithCallHook(before, after)` wraps every call: `before` may put a trace id or an
open audit record in the context, `after` sees the answer including refusals.
Metric: `app_mcp_tool_calls_total{tool,outcome}` with `ok` and `error`.

A tool can answer with more than text. `mcp.ImageBlock`, `mcp.AudioBlock`,
`mcp.ResourceLinkBlock` and `mcp.ResourceBlock` build the other four kinds; the
first two encode the bytes themselves, because binary data *MUST* be base64 and
raw bytes in a JSON string come out as U+FFFD:

```go
mcp.ToolCallResult{Content: []mcp.ContentBlock{
    mcp.ResourceLinkBlock(entry), // point at the catalogue, do not inline it
    mcp.ImageBlock(png, "image/png"),
}}
```

A link is what a search tool returns: the model reads the same description
`resources/list` gave it and decides whether the resource is worth a
`resources/read`.

`OKResult` fills both `structuredContent` and the text block with the same value.
That is deliberate: the field is what a client validates against your
`outputSchema` and hands to code, the text block is what an older client — and a
model reading the transcript — actually sees. Declare the schema from the same
struct the tool returns, and the answer cannot drift from what it promised:

```go
type helloResult struct {
    Greeting string `json:"greeting"`
}

var helloOutput = mcp.SchemaFor(helloResult{}) // once, at startup
```

## redact

```go
r, err := redact.New(redact.Options{Mode: redact.ModeOn}) // off, warn, mask
masked, res := r.Text(body)
```

Seven rules — `email`, `phone`, `card`, `token`, `jwt`, `pem`, `ip` — applied in
that order, because the specific pattern has to win: a JWT half-eaten by the
token rule is unreadable for a human and for a filter alike. `Options.Rules`
narrows the set for a source that would only get false positives.

Two rules keep the context and mask the secret. An address becomes
`s***@acme.com`: the domain says whose customer a row is about and hides nothing
the mask does not already hide (`MaskEmailDomain` takes it away). A token keeps
the name of its parameter — `?private_token=[masked:token]` still says which
parameter was refused.

`warn` counts without changing anything, which is how a rule set gets chosen on
data rather than in an argument. `Value` walks decoded JSON through a type
switch and anything else through reflection, so a `*string` from a nullable
column, a `[]string` from an array one and the exported fields of a struct a
driver hands back are masked too; numbers, map keys and unexported fields are
never touched.

An unexported field is not masked *and not counted*: `Result` names the rules
that actually fired, because an audit record claiming a mask that never happened
is worse than a missing one — it is the signal a leak would be caught by.
`Rows` does the same in place over a result set.

The marker is fixed — `Marker(rule)` gives `[masked:email]` — because the model
reads it and cheat sheets name it.

## audit

```go
w := audit.NewWriter(logger, audit.Options{Message: "mcp call"})
w.Write(ctx, audit.Record{
    Subject: p.UserID, Tool: name, Decision: audit.DecisionAllow,
    Query: sql, Rows: n, BytesOut: size, Duration: elapsed,
    Extra: []any{"target", target, "upstream_status", status},
})
```

One record per call, including the refused ones — a trail of successes answers
none of the questions a trail is kept for. Answers never go into it. Every
model-authored string is masked on the way in whatever the answer path does: a
deployment may show a user full values, but the log is read by everyone who can
read logs. Masking happens before the final cut, with slack, so the cut cannot
split a match and leave half an address in the log.

`SanitizeText` drops control characters and ANSI escapes and collapses line
breaks — without it a crafted `intent` forges log lines, and the injection gets
to write into the record that is supposed to describe it.

Core keys are fixed (`query`, `query_sha256`, `rows`, `rows_out`, …) so you can
write log queries against them and expect them to keep working; `Message` and
`Extra` are yours. Each key names its field — `query` and not `sql`, because the
text in it is an HTTP path as often as it is a statement, and a proxy would
otherwise log its URLs under a key that says SQL.

## Testing a service that uses this

`mcptest` drives the server you assembled — your namespaces, your
authentication, your limiter, your audit — the way a client would:

```go
h, stop := newMCP(log, docs, apiKey) // whatever your main builds
t.Cleanup(stop)

c := mcptest.New(t, h, mcptest.WithHeader("Authorization", "Bearer "+key))
tools := c.Tools(t)
res := c.CallTool(t, "hello", map[string]any{"who": "world"})
```

It exists for the modern era. A request of 2026-07-28 is correct only if
`params._meta` carries the protocol version and the client's capabilities and
the `Mcp-Protocol-Version`, `Mcp-Method` and `Mcp-Name` headers mirror the body
exactly — including the Base64 sentinel when a resource URI will not fit in a
header. Written out by hand in every test, that is how a suite ends up asserting
against requests no client would send.

`mcptest.WithEra(mcptest.Legacy)` sends what a client of 2025-11-25 sends, which
is how a dual-era server gets tested as one: run the table twice and both eras
have to answer the same catalogue. `WithProtocolVersion` and `WithHeader` are
there to break a request on purpose and see the `-32022` or `-32020` it earns —
`WithHeader` is applied after the protocol headers so it can overwrite one.

`auth/authtest` runs a fake issuer with a real discovery document and JWKS, so
the tests go through the real verifier rather than a mock of it:

```go
iss := authtest.NewIssuer(t, "my-client")
v, err := auth.NewVerifier(t.Context(), auth.OIDCConfig{Issuer: iss.URL, ClientID: "my-client"})
tok := iss.SignToken(t, map[string]any{"sub": "alice", "azp": "my-client", "exp": exp})
```

It is a separate package on purpose: `go-jose` stays out of the dependency graph
of your binary.

## License

MIT.
