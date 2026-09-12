// Package mcptool is the tool dispatcher: the part of tools/list and
// tools/call that is the same whatever the tools do.
//
// What a tool does stays in the service — the tools are the reason a service
// exists. What lives here is the switch that finds one by name, the envelope
// its answer travels in, the metric, and the place to hang an audit.
//
// Visibility is the tool's own answer, not the registry's: Describe reports
// whether this caller may see it at all, so the registry never learns what a
// role is.
package mcptool

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/vmkteam/mcpkit/mcp"
)

// Tool is one tool of a service.
//
// Name is the identity and is fixed. Describe is asked on every tools/list,
// because the answer depends on who is asking — a caller sees the tools their
// role allows, described in the terms their role can use — and reports false
// when this caller may not see it at all.
type Tool interface {
	Name() string
	Describe(ctx context.Context) (mcp.Tool, bool)
	Call(ctx context.Context, args map[string]any) mcp.ToolCallResult
}

// BeforeHook runs before a tool is called and may return a context carrying
// whatever the service wants the call to have — a trace id, an open audit
// record. Returning the context it was given is the no-op.
type BeforeHook func(ctx context.Context, name string, args map[string]any) context.Context

// AfterHook runs after a tool answered, including when it refused. It is where
// a service writes its audit record: the registry does not know what an audit
// is, and the record needs fields only the service can fill.
type AfterHook func(ctx context.Context, name string, res mcp.ToolCallResult, elapsed time.Duration)

// Option tunes a Registry.
type Option func(*Registry)

// Registry dispatches tools/list and tools/call over a fixed set of tools.
type Registry struct {
	tools    []Tool
	byName   map[string]Tool
	before   BeforeHook
	after    AfterHook
	hint     mcp.CacheHint
	pageSize int
}

// NewRegistry indexes the tools by name.
//
// The order of the arguments is the order of tools/list, and it is kept: the
// model reads that list top to bottom, so sorting it "for tidiness" changes
// behaviour. A duplicate name panics — it is a wiring mistake, visible at
// startup, and the alternative is one of two tools silently disappearing.
func NewRegistry(tools ...Tool) *Registry {
	r := &Registry{tools: tools, byName: make(map[string]Tool, len(tools))}
	for _, t := range tools {
		if _, dup := r.byName[t.Name()]; dup {
			panic("mcptool: duplicate tool name " + t.Name())
		}
		r.byName[t.Name()] = t
	}
	registerMetrics()
	return r
}

// WithCache sets the caching hints of tools/list.
//
// The default — no freshness, private — is the only honest one for this list:
// it is computed per caller, and "public" would let a cache between us and the
// client serve one user the tools of another. A service whose tools are the
// same for everyone can say so and buy back the round trips.
func WithCache(h mcp.CacheHint) Option {
	return func(r *Registry) { r.hint = h }
}

// WithPageSize caps how many tools one tools/list answers with. The default,
// zero, is all of them in one answer.
//
// A tool catalogue is read once and used for the rest of the conversation, so
// paging it is rarely the right trade: the model cannot pick a tool it has not
// been shown, and each page is a round trip before it can start. It is here for
// the catalogue that has grown past what a context window should hold at once.
func WithPageSize(n int) Option {
	return func(r *Registry) { r.pageSize = n }
}

// WithCallHook installs the hooks around Call. Either may be nil.
func WithCallHook(before BeforeHook, after AfterHook) Option {
	return func(r *Registry) {
		r.before, r.after = before, after
	}
}

// With applies options to an existing registry. It exists so that a service can
// build the registry and wire the hooks in two steps, which is what happens when
// the audit needs the registry itself.
func (r *Registry) With(opts ...Option) *Registry {
	for _, o := range opts {
		o(r)
	}
	return r
}

// List answers tools/list with the tools this caller may see.
//
// It is computed per request rather than cached: the answer depends on the
// caller, and a cached list hands one user the tools of another.
//
// Paging happens after the visibility filter, over what this caller may see, so
// a tool hidden from them never occupies a slot on their page — and the cursor
// is scoped to them for the same reason. An invalid cursor comes back marked
// mcp.ErrInvalidParams; mcpkit.RPCError is what turns it into -32602.
func (r *Registry) List(ctx context.Context, cursor string) (mcp.ToolList, error) {
	// An empty list marshals as [] and not null: clients with strict schemas
	// reject null where an array was promised.
	out := make([]mcp.Tool, 0, len(r.tools))
	for _, t := range r.tools {
		if described, ok := t.Describe(ctx); ok {
			out = append(out, described)
		}
	}
	page, next, err := mcp.Paginate(out, cursor, r.pageSize, func(t mcp.Tool) string { return t.Name })
	if err != nil {
		return mcp.ToolList{}, err
	}
	return mcp.ToolList{Tools: page, NextCursor: next, CacheHint: r.hint.Normalized()}, nil
}

// Call dispatches tools/call by name.
//
// A tool this caller cannot see is refused exactly like one that does not
// exist: the alternative tells a caller which tools they are missing.
//
// The error of an unknown tool travels in the envelope, not as a JSON-RPC
// error — the model is meant to read it and pick another tool, which a
// transport error does not let it do.
func (r *Registry) Call(ctx context.Context, name string, args map[string]any) (mcp.ToolCallResult, error) {
	t, ok := r.byName[name]
	if ok {
		_, visible := t.Describe(ctx)
		ok = visible
	}

	// The hooks wrap the refusal too. AfterHook says it runs "including when it
	// refused", and the audit built on it exists for exactly these calls: a
	// caller probing for tools their role hides is the thing a trail is kept
	// for, and it used to leave none.
	if r.before != nil {
		ctx = r.before(ctx, name, args)
	}
	start := time.Now()

	var res mcp.ToolCallResult
	if ok {
		res = t.Call(ctx, args)
	} else {
		// The hint is built by asking every other tool whether this caller may
		// see it. The one just asked is skipped: Describe depends on who is
		// calling and may be doing real work, and the answer for this name is
		// already known to be no.
		res = ErrorResult(Error{
			Code:    CodeUnknownTool,
			Message: fmt.Sprintf("unknown tool %q", name),
			Hint:    r.visibleNames(ctx, name),
		})
	}
	elapsed := time.Since(start)

	// The metric label is metricName(name), not name: on the refusal path the
	// name is whatever the caller typed, and a counter labelled with client
	// input has no bound on its cardinality.
	observe(metricName(r, name), outcome(res))
	if r.after != nil {
		r.after(ctx, name, res, elapsed)
	}
	return res, nil
}

// metricName keeps the tool label inside the set of names this service
// registered. Anything else is counted as one series: a caller looping
// tools/call over random names would otherwise mint a series per name, and a
// CounterVec never evicts — the process grows, the scrape grows, and the TSDB
// keeps them forever.
//
// The refused call is not lost with it: the audit hook above records the name
// the caller actually used, which is where that question belongs.
func metricName(r *Registry, name string) string {
	if _, known := r.byName[name]; known {
		return name
	}
	return metricNameUnknown
}

// metricNameUnknown is the label every unregistered name is counted under.
const metricNameUnknown = "unknown"

// visibleNames is what a refusal offers instead: the names this caller does
// have. An error is the documentation a caller reads at the moment they need it.
//
// except names a tool whose visibility the caller has just established, so it
// is not asked twice.
func (r *Registry) visibleNames(ctx context.Context, except string) []string {
	out := make([]string, 0, len(r.tools))
	for _, t := range r.tools {
		if t.Name() == except {
			continue
		}
		if _, ok := t.Describe(ctx); ok {
			out = append(out, t.Name())
		}
	}
	return out
}

// The two error codes this package owns. Every other code is a word in the
// service's own vocabulary and stays there.
const (
	CodeUnknownTool = "E_UNKNOWN_TOOL"
	CodeEncode      = "E_ENCODE"
)

// Error is the refusal envelope. With few tools the error is the documentation:
// each code carries what the caller needs to fix the call on the next try.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	// Hint is what turns a refusal into documentation: the list of known
	// targets, the patterns that were allowed, the keys the answer actually had.
	Hint any `json:"hint,omitempty"`
}

// Error implements the error interface, so a decided refusal can travel back
// through a plain error return alongside failures from an upstream.
func (e Error) Error() string { return e.Code + ": " + e.Message }

// ErrorResult wraps a refusal as a tool answer. A tool failure travels inside a
// successful JSON-RPC response, marked isError.
func ErrorResult(e Error) mcp.ToolCallResult {
	body, err := json.Marshal(e)
	if err != nil {
		return mcp.ErrorResult(e.Message)
	}
	return mcp.ErrorResult(string(body))
}

// OKResult wraps a value as a successful tool answer.
func OKResult(v any) mcp.ToolCallResult {
	res, err := mcp.JSONResult(v)
	if err != nil {
		return ErrorResult(Error{Code: CodeEncode, Message: "encode result: " + err.Error()})
	}
	// The same answer twice, on purpose. structuredContent is what a client
	// validates against the tool's outputSchema and hands to code; the text
	// block is what a client of an older revision — and a model reading the
	// transcript — actually sees. The spec asks for both, and the encoding is
	// already paid for by JSONResult.
	res.StructuredContent = v
	return res
}
