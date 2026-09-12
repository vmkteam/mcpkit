// Command example is a whole MCP server on mcpkit: the Streamable HTTP
// transport, the handshake, a catalogue of markdown served as resources and
// prompts, one tool, api-key authentication, rate limiting, an audit record per
// call and the RFC 9728 metadata document — on net/http, with no config file
// and no web framework.
//
//	go run ./example -api-key demo-token
//	curl -s localhost:8075/mcp -H 'Authorization: Bearer demo-token' \
//	  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}'
package main

//go:generate go tool zenrpc

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"flag"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vmkteam/mcpkit"
	"github.com/vmkteam/mcpkit/audit"
	"github.com/vmkteam/mcpkit/auth"
	"github.com/vmkteam/mcpkit/doc"
	"github.com/vmkteam/mcpkit/mcp"
	"github.com/vmkteam/mcpkit/mcptool"
	"github.com/vmkteam/mcpkit/ratelimit"

	"github.com/vmkteam/embedlog"
	"github.com/vmkteam/zenrpc/v2"
)

// The documents this server serves. A real service ships its own tree; what it
// says is the service's business, which is why the library carries no texts of
// its own.
//
//go:embed md
var docFS embed.FS

const uriScheme = "docs://"

func main() {
	addr := flag.String("addr", ":8075", "listen address")
	apiKey := flag.String("api-key", "", "plaintext api key; empty means no authentication")
	issuer := flag.String("issuer", "", "OIDC issuer for the protected-resource document; empty means no document")
	baseURL := flag.String("base-url", "http://localhost:8075", "public base URL of this server")
	flag.Parse()

	log := embedlog.NewLogger(true, false)

	docs, err := doc.Load(docFS, "md", doc.Options{URIScheme: uriScheme})
	if err != nil {
		log.Errorf("load docs: %v", err)
		return
	}

	h, stop := newMCP(log, docs, *apiKey, localHosts(*addr))
	defer stop()

	mux := http.NewServeMux()
	mux.Handle("/mcp", h)
	mux.Handle("/.well-known/oauth-protected-resource", auth.ProtectedResource{
		Resource: *baseURL + "/mcp",
		Issuer:   *issuer,
	}.Handler())

	// This file gets copied into services, so the timeouts are here rather than
	// left to the zero value: without WriteTimeout and IdleTimeout a stuck
	// client holds a connection until the process dies.
	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	go func() {
		log.Print(ctx, "mcp server", "addr", *addr, "auth", *apiKey != "")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Errorf("listen: %v", err)
			stopSignals()
		}
	}()

	<-ctx.Done()
	// In-flight calls finish; a tool call cut in half writes an audit record
	// that says nothing about what happened to the work.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Errorf("shutdown: %v", err)
	}
}

// newMCP assembles the endpoint: the namespaces, authentication, the limiter
// and the audit, in the order they have to be in. The returned function stops
// the limiter's background work.
//
// It is separate from main so that a test can build exactly what production
// runs — see main_test.go. An example nobody can run against is an example
// nobody can check.
func newMCP(log embedlog.Logger, docs *doc.Library, apiKey string, hosts []string) (http.Handler, func()) {
	// One record per call, masked. The library does not know what this server is
	// about, so what goes beside the core fields is the service's to decide.
	auditor := audit.NewWriter(log, audit.Options{})
	tools := mcptool.NewRegistry(helloTool{}).With(mcptool.WithCallHook(nil,
		func(ctx context.Context, name string, res mcp.ToolCallResult, elapsed time.Duration) {
			decision := audit.DecisionAllow
			if res.IsError {
				decision = audit.DecisionDeny
			}
			subject := ""
			if p, ok := auth.PrincipalFromContext(ctx); ok {
				subject = p.UserID
			}
			auditor.Write(ctx, audit.Record{
				Subject: subject, Tool: name, Source: "example",
				Decision: decision, BytesOut: res.Size(), Duration: elapsed,
			})
		}))

	// No AllowCORS: zenrpc reads that option inside its own ServeHTTP, and the
	// transport calls zsrv.Do() directly — so the option would switch nothing on
	// while claiming a browser client works. This server has none; a browser
	// request is refused by the Origin check instead.
	zsrv := zenrpc.NewServer(zenrpc.Options{})
	deps := mcpkit.InitDeps{
		// Name and Version are the identity; the rest is what a client has to
		// show a human. All of it is self-reported — display and logging, never
		// a security decision.
		Info: mcp.ServerInfo{
			Name:        "mcpkit-example",
			Version:     "0.1.0",
			Title:       "mcpkit example",
			Description: "One tool, one document, one prompt — the shape of a service built on mcpkit.",
			WebsiteURL:  "https://github.com/vmkteam/mcpkit",
		},
		// Declare exactly the namespaces registered below. A capability the
		// server announces is one it promises to answer: declaring prompts
		// without registering them sends the client to a -32601.
		Capabilities: mcp.Capabilities{
			Tools:     &mcp.ToolsCapability{},
			Resources: &mcp.ResourcesCapability{},
			Prompts:   &mcp.PromptsCapability{},
		},
		Instructions: "An example server. It has one tool, it says hello, and it writes down that it did.",
	}

	zsrv.RegisterAll(map[string]zenrpc.Invoker{
		// Both eras on one endpoint: initialize for the clients that still open
		// with a handshake, server/discover for the ones that no longer do.
		"":                        mcpkit.NewInitService(deps),
		mcpkit.NamespaceServer:    mcpkit.NewDiscoverService(deps),
		mcpkit.NamespaceResources: mcpkit.NewResourcesService(docs),
		mcpkit.NamespacePrompts:   mcpkit.NewPromptsService(docs),
		mcpkit.NamespaceTools:     ToolsService{registry: tools},
	})

	keys := auth.NewStoreWithOptions(apiKeys(apiKey), auth.StoreOptions{Realm: "example-mcp"})
	limiter := ratelimit.New(ratelimit.Config{
		PerUserRPM:        60,
		PerUserConcurrent: 4,
		GlobalConcurrent:  16,
		CostBudgetPerHour: 10 * time.Minute,
	})

	// Authentication on the outside, so the limiter sees Principal.UserID; the
	// other order buckets every caller as anonymous.
	//
	// AllowedHosts is spelt out rather than left empty because this file gets
	// copied into services and this is the one server that runs with nothing in
	// front of it. On a developer's loopback there is no nginx to check the
	// Host, and a page at evil.com whose name has just been re-resolved to
	// 127.0.0.1 reaches this port as a same-origin request — carrying no Origin
	// at all, so the origin check above never sees it. A deployment behind a
	// proxy lists its own name here or leaves the list empty.
	var h http.Handler = mcpkit.NewServerWithOptions(zsrv, log, mcpkit.Options{
		AllowedHosts: hosts,
	})
	h = limiter.Middleware(h, log)
	h = keys.Middleware(h, log)
	return h, limiter.Stop
}

// localHosts is the set of Host values a browser can reach a loopback server
// under. It is derived from the listen address rather than hard-coded so that
// -addr and the check cannot disagree.
//
// A real deployment lists the name it is published under instead.
func localHosts(addr string) []string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return nil // an address we cannot read is not one to guess about
	}
	return []string{
		net.JoinHostPort("localhost", port),
		net.JoinHostPort("127.0.0.1", port),
		net.JoinHostPort("::1", port),
	}
}

func apiKeys(plaintext string) []auth.Key {
	if plaintext == "" {
		return nil // empty store — no authentication, which is a dev-only mode
	}
	sum := sha256.Sum256([]byte(plaintext))
	return []auth.Key{{
		UserID:  "demo",
		KeyHash: hex.EncodeToString(sum[:]),
		Groups:  []string{"demo-users"},
	}}
}

// ToolsService is what stays in a service once the registry is the library's:
// the zenrpc namespace, and nothing else.
type ToolsService struct {
	zenrpc.Service
	registry *mcptool.Registry
}

// List answers tools/list with the tools this caller may see.
//
// RPCError is what makes an invalid cursor a -32602 rather than the -32603
// zenrpc gives any plain error: the registry does not know what zenrpc is, so
// the translation happens here, where the namespace does.
//
//zenrpc:cursor nextCursor from the previous page; empty for the first
func (s ToolsService) List(ctx context.Context, cursor string) (mcp.ToolList, error) {
	list, err := s.registry.List(ctx, cursor)
	return list, mcpkit.RPCError("tools.list", err)
}

// Call dispatches tools/call to the named tool.
//
//zenrpc:name name of the tool to invoke
//zenrpc:arguments tool-specific arguments
func (s ToolsService) Call(ctx context.Context, name string, arguments map[string]any) (mcp.ToolCallResult, error) {
	return s.registry.Call(ctx, name, arguments)
}

// helloArgs is what the hello tool takes. The json tags are the whole
// description of it: the schema is reflected from this struct.
type helloArgs struct {
	Who string `json:"who,omitempty" jsonschema_description:"Who to greet; defaults to the caller."`
}

// helloResult is what the tool answers with. Declaring the shape is what lets a
// client validate the answer instead of parsing a string and hoping.
type helloResult struct {
	Greeting string `json:"greeting" jsonschema_description:"The greeting, addressed to whoever asked."`
}

// Both schemas are reflected once, at startup — tools/list is on the request
// path, and reflection there would be paid for on every call.
var (
	helloSchema = mcp.SchemaFor(helloArgs{})
	helloOutput = mcp.SchemaFor(helloResult{})
)

// helloTool is the domain of this server, such as it is.
type helloTool struct{}

// Name is the identity of the tool and never changes.
func (helloTool) Name() string { return "hello" }

// Describe is asked on every tools/list. This one is visible to everybody; a
// real tool answers false for a caller whose role does not include it.
func (helloTool) Describe(context.Context) (mcp.Tool, bool) {
	return mcp.Tool{
		Name:         "hello",
		Title:        "Say hello",
		Description:  "Greets whoever is asking. Read " + uriScheme + "hello.md for what this server is.",
		InputSchema:  helloSchema,
		OutputSchema: helloOutput,
		Annotations: &mcp.ToolAnnotations{
			Title:        "Say hello",
			ReadOnlyHint: new(true),
			// Spelt out rather than left unset: the spec default for these two is
			// true, and a read-only tool that says nothing is treated as a tool
			// that may destroy something and reach the open world.
			DestructiveHint: new(false),
			OpenWorldHint:   new(false),
		},
	}, true
}

// Call does the work. A refusal carries the schema as its hint: an error is the
// documentation a caller reads at the moment they need it.
func (helloTool) Call(ctx context.Context, args map[string]any) mcp.ToolCallResult {
	var a helloArgs
	if err := mcp.DecodeArgs(args, &a); err != nil {
		return mcptool.ErrorResult(mcptool.Error{
			Code:    "E_BAD_ARGS",
			Message: err.Error(),
			Hint:    helloSchema, // the schema is already json.RawMessage
		})
	}
	if a.Who == "" {
		if p, ok := auth.PrincipalFromContext(ctx); ok {
			a.Who = p.UserID
		}
	}
	if a.Who == "" {
		a.Who = "stranger"
	}
	// A struct rather than a map: the same type the output schema was reflected
	// from, so the answer cannot drift from what the tool promised.
	return mcptool.OKResult(helloResult{Greeting: "hello, " + a.Who})
}
