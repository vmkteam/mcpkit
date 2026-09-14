package mcptool

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/vmkteam/mcpkit/mcp"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeTool is a tool of a service: a fixed name, a description that depends on
// who asks, and a body that does the work.
type fakeTool struct {
	name    string
	hidden  bool
	answer  mcp.ToolCallResult
	gotArgs map[string]any
	gotCtx  context.Context
}

func (f *fakeTool) Name() string { return f.name }

func (f *fakeTool) Describe(ctx context.Context) (mcp.Tool, bool) {
	if f.hidden || hiddenFor(ctx, f.name) {
		return mcp.Tool{}, false
	}
	return mcp.Tool{
		Name:        f.name,
		Description: "does " + f.name,
		InputSchema: json.RawMessage(`{"type":"object"}`),
	}, true
}

func (f *fakeTool) Call(ctx context.Context, args map[string]any) mcp.ToolCallResult {
	f.gotArgs, f.gotCtx = args, ctx
	return f.answer
}

// hiddenKey carries the names a caller may not see, which is how a service's
// access rules reach Describe without the registry knowing they exist.
type hiddenKey struct{}

func withHidden(ctx context.Context, names ...string) context.Context {
	return context.WithValue(ctx, hiddenKey{}, names)
}

func hiddenFor(ctx context.Context, name string) bool {
	names, _ := ctx.Value(hiddenKey{}).([]string)
	return slices.Contains(names, name)
}

func okTool(name string) *fakeTool {
	return &fakeTool{name: name, answer: OKResult(map[string]string{"tool": name})}
}

// visibleTool answers the cheap question cheaply and counts the times it was
// made to answer the expensive one instead. A real tool pays a template render
// or a reflected schema for a Describe it only wanted the bool of.
type visibleTool struct {
	fakeTool
	describes int
}

func (v *visibleTool) Describe(ctx context.Context) (mcp.Tool, bool) {
	v.describes++
	return v.fakeTool.Describe(ctx)
}

func (v *visibleTool) Visible(context.Context) bool { return !v.hidden }

func TestVisibility(t *testing.T) {
	t.Parallel()

	t.Run("dispatch asks Visible and builds no description", func(t *testing.T) {
		t.Parallel()
		v := &visibleTool{fakeTool: fakeTool{name: "cheap", answer: OKResult("done")}}
		r := NewRegistry(v)

		res, err := r.Call(t.Context(), "cheap", nil)
		require.NoError(t, err)
		require.False(t, res.IsError)
		assert.Zero(t, v.describes, "a description was built to answer a yes or no")

		// tools/list is the one place the description is the answer.
		_, err = r.List(t.Context(), "")
		require.NoError(t, err)
		assert.Equal(t, 1, v.describes)
	})

	// The refusal path is the one that asks about every tool, and it is the path
	// a caller probing for what their role hides takes over and over.
	t.Run("the hint asks Visible of the others", func(t *testing.T) {
		t.Parallel()
		hidden := &visibleTool{fakeTool: fakeTool{name: "secret", hidden: true}}
		shown := &visibleTool{fakeTool: fakeTool{name: "shown", answer: OKResult("done")}}
		r := NewRegistry(hidden, shown)

		res, err := r.Call(t.Context(), "secret", nil)
		require.NoError(t, err)
		require.True(t, res.IsError)
		assert.Nil(t, hidden.gotArgs, "an invisible tool must not run")
		assert.Zero(t, hidden.describes)
		assert.Zero(t, shown.describes)

		var e Error
		require.NoError(t, json.Unmarshal([]byte(res.Content[0].Text), &e))
		assert.Equal(t, CodeUnknownTool, e.Code)
		assert.Equal(t, []any{"shown"}, e.Hint)
	})

	// The interface is optional, and the registry this library shipped with has
	// only Tool in it.
	t.Run("a tool without it is asked Describe", func(t *testing.T) {
		t.Parallel()
		secret := okTool("secret")
		r := NewRegistry(okTool("a"), secret)

		res, err := r.Call(withHidden(t.Context(), "secret"), "secret", nil)
		require.NoError(t, err)
		require.True(t, res.IsError)
		assert.Nil(t, secret.gotArgs)
	})
}

func TestList(t *testing.T) {
	t.Parallel()

	// The model reads the list top to bottom, so sorting it would change
	// behaviour.
	t.Run("keeps the order it was built in", func(t *testing.T) {
		t.Parallel()
		r := NewRegistry(okTool("zulu"), okTool("alpha"), okTool("mike"))
		got, err := r.List(t.Context(), "")
		require.NoError(t, err)
		assert.Equal(t, []string{"zulu", "alpha", "mike"},
			mcp.Map(got.Tools, func(x mcp.Tool) string { return x.Name }))
	})

	// Visibility is the tool's own answer; the registry never learns what a role
	// is.
	t.Run("a tool invisible to this caller is absent", func(t *testing.T) {
		t.Parallel()
		r := NewRegistry(okTool("a"), okTool("b"))
		got, err := r.List(withHidden(t.Context(), "b"), "")
		require.NoError(t, err)
		assert.Equal(t, []string{"a"}, mcp.Map(got.Tools, func(x mcp.Tool) string { return x.Name }))
	})

	// Clients with strict schemas reject null where an array was promised.
	t.Run("an empty list is an array", func(t *testing.T) {
		t.Parallel()
		got, err := NewRegistry().List(t.Context(), "")
		require.NoError(t, err)
		b, err := json.Marshal(got)
		require.NoError(t, err)
		assert.JSONEq(t, `{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}`, string(b))
	})

	// The answer depends on the caller, so it cannot be computed once.
	t.Run("computed per call", func(t *testing.T) {
		t.Parallel()
		tool := okTool("a")
		r := NewRegistry(tool)

		first, err := r.List(t.Context(), "")
		require.NoError(t, err)
		require.Len(t, first.Tools, 1)

		tool.hidden = true
		second, err := r.List(t.Context(), "")
		require.NoError(t, err)
		assert.Empty(t, second.Tools, "a cached list hands one user the tools of another")
	})
}

// A tool answer travels twice: as data a client validates against outputSchema
// and hands to code, and as the serialized text an older client — and the model
// reading the transcript — actually sees. The spec asks for both.
func TestOKResultCarriesStructuredAndText(t *testing.T) {
	t.Parallel()
	type row struct {
		Name string `json:"name"`
		N    int    `json:"n"`
	}
	v := row{Name: "a", N: 1}

	res := OKResult(v)
	require.False(t, res.IsError)
	assert.Equal(t, v, res.StructuredContent)
	require.Len(t, res.Content, 1)
	assert.JSONEq(t, `{"name":"a","n":1}`, res.Content[0].Text,
		"the text block is what a client of an older revision reads")

	b, err := json.Marshal(res)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"structuredContent"`)

	// A refusal carries no structured content: there is no result to validate.
	fail := ErrorResult(Error{Code: "E_X", Message: "no"})
	assert.Nil(t, fail.StructuredContent)
	b, err = json.Marshal(fail)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "structuredContent")
}

func TestCall(t *testing.T) {
	t.Parallel()

	t.Run("dispatches by name", func(t *testing.T) {
		t.Parallel()
		a, b := okTool("a"), okTool("b")
		res, err := NewRegistry(a, b).Call(t.Context(), "b", map[string]any{"n": 1})
		require.NoError(t, err)
		assert.False(t, res.IsError)
		assert.JSONEq(t, `{"tool":"b"}`, res.Content[0].Text)
		assert.Equal(t, map[string]any{"n": 1}, b.gotArgs)
		assert.Nil(t, a.gotArgs, "only the named tool runs")
	})

	// The model is meant to read the refusal and pick another tool, which a
	// transport error does not let it do.
	t.Run("an unknown tool is an envelope, not an rpc error", func(t *testing.T) {
		t.Parallel()
		res, err := NewRegistry(okTool("a")).Call(t.Context(), "nope", nil)
		require.NoError(t, err)
		require.True(t, res.IsError)

		var e Error
		require.NoError(t, json.Unmarshal([]byte(res.Content[0].Text), &e))
		assert.Equal(t, CodeUnknownTool, e.Code)
		assert.Contains(t, e.Message, `"nope"`)
		assert.Equal(t, []any{"a"}, e.Hint, "the refusal says what this caller does have")
	})

	// Telling a caller which tools they are missing is an answer they were not
	// meant to get.
	t.Run("a tool this caller cannot see is refused like one that does not exist", func(t *testing.T) {
		t.Parallel()
		secret := okTool("secret")
		r := NewRegistry(okTool("a"), secret)

		res, err := r.Call(withHidden(t.Context(), "secret"), "secret", nil)
		require.NoError(t, err)
		require.True(t, res.IsError)
		assert.Nil(t, secret.gotArgs, "an invisible tool must not run")

		var e Error
		require.NoError(t, json.Unmarshal([]byte(res.Content[0].Text), &e))
		assert.Equal(t, CodeUnknownTool, e.Code)
		assert.Equal(t, []any{"a"}, e.Hint, "the hint must not name it either")
	})

	// A service whose error codes are its own gets to answer in them. The two
	// cases it can tell apart and the default cannot: a name nothing answers to,
	// and a name this caller may not see.
	t.Run("WithUnknownTool replaces the refusal", func(t *testing.T) {
		t.Parallel()
		secret := okTool("secret")
		r := NewRegistry(okTool("a"), secret).With(WithUnknownTool(
			func(_ context.Context, name string, visible []string) mcp.ToolCallResult {
				code := "NoSuchTool"
				if slices.Contains([]string{"a", "secret"}, name) {
					code = "ForbiddenRole"
				}
				return ErrorResult(Error{Code: code, Message: name, Hint: visible})
			}))

		hidden, err := r.Call(withHidden(t.Context(), "secret"), "secret", nil)
		require.NoError(t, err)
		require.True(t, hidden.IsError)
		assert.Nil(t, secret.gotArgs, "an invisible tool must not run, hook or no hook")

		var e Error
		require.NoError(t, json.Unmarshal([]byte(hidden.Content[0].Text), &e))
		assert.Equal(t, "ForbiddenRole", e.Code)
		assert.Equal(t, []any{"a"}, e.Hint, "the visible names are handed over, and still exclude it")

		unknown, err := r.Call(t.Context(), "nope", nil)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal([]byte(unknown.Content[0].Text), &e))
		assert.Equal(t, "NoSuchTool", e.Code)
	})

	t.Run("a tool that refuses answers through the envelope", func(t *testing.T) {
		t.Parallel()
		failing := &fakeTool{name: "f", answer: ErrorResult(Error{Code: "E_DOMAIN", Message: "no"})}
		res, err := NewRegistry(failing).Call(t.Context(), "f", nil)
		require.NoError(t, err)
		assert.True(t, res.IsError)
		assert.Contains(t, res.Content[0].Text, "E_DOMAIN")
	})
}

// The hooks are where a service hangs its audit without the registry knowing
// what an audit is.
func TestCallHooks(t *testing.T) {
	t.Parallel()

	type ctxKey struct{}
	var (
		beforeName, afterName string
		beforeArgs            map[string]any
		afterRes              mcp.ToolCallResult
		afterElapsed          time.Duration
	)

	tool := okTool("a")
	r := NewRegistry(tool).With(WithCallHook(
		func(ctx context.Context, name string, args map[string]any) context.Context {
			beforeName, beforeArgs = name, args
			return context.WithValue(ctx, ctxKey{}, "trace-1")
		},
		func(_ context.Context, name string, res mcp.ToolCallResult, elapsed time.Duration) {
			afterName, afterRes, afterElapsed = name, res, elapsed
		},
	))

	_, err := r.Call(t.Context(), "a", map[string]any{"n": 1})
	require.NoError(t, err)

	assert.Equal(t, "a", beforeName)
	assert.Equal(t, map[string]any{"n": 1}, beforeArgs)
	assert.Equal(t, "a", afterName)
	assert.False(t, afterRes.IsError)
	assert.GreaterOrEqual(t, afterElapsed, time.Duration(0))
	assert.Equal(t, "trace-1", tool.gotCtx.Value(ctxKey{}),
		"what the before hook put in the context has to reach the tool")
}

// A refusal is the record that matters most, so the after hook has to see it.
func TestAfterHookSeesRefusals(t *testing.T) {
	t.Parallel()
	var seen []mcp.ToolCallResult
	failing := &fakeTool{name: "f", answer: ErrorResult(Error{Code: "E_DOMAIN", Message: "no"})}
	r := NewRegistry(failing).With(WithCallHook(nil,
		func(_ context.Context, _ string, res mcp.ToolCallResult, _ time.Duration) {
			seen = append(seen, res)
		}))

	_, err := r.Call(t.Context(), "f", nil)
	require.NoError(t, err)
	require.Len(t, seen, 1)
	assert.True(t, seen[0].IsError)
}

// One of two tools with the same name would silently disappear, and the wiring
// mistake would be found by the model.
func TestDuplicateNamePanics(t *testing.T) {
	t.Parallel()
	assert.PanicsWithValue(t, "mcptool: duplicate tool name a", func() {
		NewRegistry(okTool("a"), okTool("a"))
	})
}

func TestEnvelopes(t *testing.T) {
	t.Parallel()

	t.Run("OKResult", func(t *testing.T) {
		t.Parallel()
		res := OKResult(map[string]int{"n": 1})
		assert.False(t, res.IsError)
		assert.JSONEq(t, `{"n":1}`, res.Content[0].Text)
	})

	t.Run("OKResult on a value json cannot encode", func(t *testing.T) {
		t.Parallel()
		res := OKResult(make(chan int))
		require.True(t, res.IsError)
		assert.Contains(t, res.Content[0].Text, CodeEncode)
	})

	// An error is the documentation a caller reads at the moment they need it.
	t.Run("ErrorResult carries the hint", func(t *testing.T) {
		t.Parallel()
		res := ErrorResult(Error{
			Code: "E_TARGET_UNKNOWN", Message: "no such target",
			Hint: map[string]any{"targets": []string{"grafana", "sentry"}},
		})
		require.True(t, res.IsError)
		assert.Contains(t, res.Content[0].Text, "grafana")
	})

	t.Run("a hintless error omits the field", func(t *testing.T) {
		t.Parallel()
		res := ErrorResult(Error{Code: "E_X", Message: "m"})
		assert.NotContains(t, res.Content[0].Text, "hint")
	})

	t.Run("Error is an error", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "E_X: m", Error{Code: "E_X", Message: "m"}.Error())
	})
}

func TestMetric(t *testing.T) {
	before := testutil.ToFloat64(toolCalls.WithLabelValues("m", outcomeOK))
	r := NewRegistry(okTool("m"), &fakeTool{name: "bad", answer: ErrorResult(Error{Code: "E"})})

	_, err := r.Call(t.Context(), "m", nil)
	require.NoError(t, err)
	assert.InDelta(t, before+1, testutil.ToFloat64(toolCalls.WithLabelValues("m", outcomeOK)), 0)

	failuresBefore := testutil.ToFloat64(toolCalls.WithLabelValues("bad", outcomeError))
	_, err = r.Call(t.Context(), "bad", nil)
	require.NoError(t, err)
	assert.InDelta(t, failuresBefore+1, testutil.ToFloat64(toolCalls.WithLabelValues("bad", outcomeError)), 0)

	// An unknown name is counted under one fixed label, not under the name the
	// caller typed. The name is client input, a CounterVec never evicts, and a
	// caller looping tools/call over random strings would mint a series each —
	// growing the process, the scrape and the TSDB with no bound.
	//
	// The information is not lost, it moved: the call hook now runs for refusals
	// too and records the name the caller actually used. A log holds unbounded
	// strings; a metric label cannot.
	unknownBefore := testutil.ToFloat64(toolCalls.WithLabelValues(metricNameUnknown, outcomeError))
	for _, name := range []string{"ghost", "phantom", "ghost"} {
		_, err = r.Call(t.Context(), name, nil)
		require.NoError(t, err)
	}
	assert.InDelta(t, unknownBefore+3, testutil.ToFloat64(toolCalls.WithLabelValues(metricNameUnknown, outcomeError)), 0)
	assert.InDelta(t, 0, testutil.ToFloat64(toolCalls.WithLabelValues("ghost", outcomeError)), 0,
		"a name the caller invented must not become a series of its own")
}
