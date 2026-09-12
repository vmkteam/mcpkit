package mcptool

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/vmkteam/mcpkit/mcp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type roleKey struct{}

// roleTool is visible only to the role it belongs to: two callers asking at the
// same time must get two different lists, which is the claim "computed per
// request, never cached" actually makes.
type roleTool struct {
	name string
	role string
}

func (t roleTool) Name() string { return t.name }

func (t roleTool) Describe(ctx context.Context) (mcp.Tool, bool) {
	if role, _ := ctx.Value(roleKey{}).(string); role != t.role {
		return mcp.Tool{}, false
	}
	return mcp.Tool{Name: t.name, Description: "for " + t.role}, true
}

func (t roleTool) Call(ctx context.Context, _ map[string]any) mcp.ToolCallResult {
	role, _ := ctx.Value(roleKey{}).(string)
	return mcp.TextResult(t.name + ":" + role)
}

// A cached list hands one user the tools of another, and the only way that bug
// shows up is with both users asking at once.
func TestListIsPerCallerUnderConcurrency(t *testing.T) {
	t.Parallel()
	r := NewRegistry(
		roleTool{name: "analyst-tool", role: "analyst"},
		roleTool{name: "admin-tool", role: "admin"},
	)

	var wg sync.WaitGroup
	for range 64 {
		for _, role := range []string{"analyst", "admin"} {
			wg.Go(func() {
				ctx := context.WithValue(t.Context(), roleKey{}, role)
				list, err := r.List(ctx, "")
				require.NoError(t, err)
				require.Len(t, list.Tools, 1, "a caller sees exactly the tools of their role")
				assert.Equal(t, role+"-tool", list.Tools[0].Name)
			})
		}
	}
	wg.Wait()
}

// Dispatch, the metric and both hooks run from many goroutines at once in any
// real server; the registry itself holds the shared state.
func TestCallIsSafeUnderConcurrency(t *testing.T) {
	t.Parallel()

	var (
		mu     sync.Mutex
		before int
		after  int
	)
	r := NewRegistry(
		roleTool{name: "analyst-tool", role: "analyst"},
		roleTool{name: "admin-tool", role: "admin"},
	).With(WithCallHook(
		func(ctx context.Context, _ string, _ map[string]any) context.Context {
			mu.Lock()
			before++
			mu.Unlock()
			return ctx
		},
		func(_ context.Context, _ string, _ mcp.ToolCallResult, _ time.Duration) {
			mu.Lock()
			after++
			mu.Unlock()
		},
	))

	const rounds = 64
	var wg sync.WaitGroup
	for range rounds {
		wg.Go(func() {
			ctx := context.WithValue(t.Context(), roleKey{}, "analyst")
			res, err := r.Call(ctx, "analyst-tool", nil)
			require.NoError(t, err)
			assert.False(t, res.IsError)
			assert.Equal(t, "analyst-tool:analyst", res.Content[0].Text)
		})
		wg.Go(func() {
			// The admin tool is invisible to an analyst and is refused exactly
			// like one that does not exist — including while others dispatch.
			ctx := context.WithValue(t.Context(), roleKey{}, "analyst")
			res, err := r.Call(ctx, "admin-tool", nil)
			require.NoError(t, err)
			assert.True(t, res.IsError)
			assert.Contains(t, res.Content[0].Text, CodeUnknownTool)
			assert.NotContains(t, res.Content[0].Text, "admin-tool\"]",
				"the hint must not name a tool this caller cannot see")
		})
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	// Twice the rounds: the hooks wrap the refusals too. A caller probing for
	// tools their role hides is precisely what an audit is kept for, and it used
	// to leave no record at all — the refusal returned before the hooks ran.
	assert.Equal(t, 2*rounds, before, "the before hook runs once per call, refused or not")
	assert.Equal(t, 2*rounds, after, "the after hook runs once per call, refused or not")
}
