package mcpkit

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fastjson"
)

func methodOf(t *testing.T, body []byte) string {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(body, &m))
	s, _ := m["method"].(string)
	return s
}

func TestRewriteMethodSlash_Single(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"tools/list", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, "tools.list"},
		{"tools/call", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"x"}}`, "tools.call"},
		{"initialize (unchanged)", `{"jsonrpc":"2.0","id":3,"method":"initialize"}`, "initialize"},
		{"notifications/initialized", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, "notifications.initialized"},
		{"resources/read", `{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"docs://index"}}`, "resources.read"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := RewriteMethodSlash([]byte(tc.in))
			require.NoError(t, err)
			assert.Equal(t, tc.want, methodOf(t, got))
		})
	}
}

// zenrpc splits a method on the *first* dot, so a three-segment name cannot be
// rewritten slash-for-dot: `resources.templates.list` arrives as namespace
// `resources` and method `templates.list`, which no Go method can be. The later
// segments are folded into the method name instead.
func TestRewriteMethodSlash_MultipleSegments(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"tools/list":                      "tools.list",
		"resources/templates/list":        "resources.templatesList",
		"notifications/resources/updated": "notifications.resourcesUpdated",
		"a/b/c/d":                         "a.bCD",
		"tools/":                          "tools.", // trailing slash: malformed stays malformed
		"tools//list":                     "tools.List",
		"/list":                           ".list", // no namespace at all
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			t.Parallel()
			got, err := RewriteMethodSlash([]byte(`{"jsonrpc":"2.0","id":1,"method":"` + in + `"}`))
			require.NoError(t, err)
			assert.Equal(t, want, methodOf(t, got))
		})
	}
}

// The transport refuses arrays before it gets here, but the function is
// exported and has to be right about them on its own.
func TestRewriteMethodSlash_Array(t *testing.T) {
	t.Parallel()
	in := `[
        {"jsonrpc":"2.0","id":1,"method":"tools/list"},
        {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"x"}},
        {"jsonrpc":"2.0","method":"notifications/initialized"}
    ]`
	got, err := RewriteMethodSlash([]byte(in))
	require.NoError(t, err)
	var arr []map[string]any
	require.NoError(t, json.Unmarshal(got, &arr))
	want := []string{"tools.list", "tools.call", "notifications.initialized"}
	for i, w := range want {
		assert.Equal(t, w, arr[i]["method"], "array[%d]", i)
	}
}

func TestRewriteMethodSlash_NoAlloc_WhenNoSlash(t *testing.T) {
	t.Parallel()
	// Verify returned slice is the SAME underlying slice if no rewrite happened.
	in := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	got, err := RewriteMethodSlash(in)
	require.NoError(t, err)
	require.Same(t, &in[0], &got[0], "expected zero-copy: input slice should be returned when no `/` in method")
}

// Method names in MCP are ASCII identifiers, but a quote or a backslash in one
// would otherwise end the string literal being built and corrupt the document.
func TestRewriteMethodSlash_Escaping(t *testing.T) {
	t.Parallel()
	in, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": `to"ols/li\st`})
	require.NoError(t, err)

	got, err := RewriteMethodSlash(in)
	require.NoError(t, err)
	assert.Equal(t, `to"ols.li\st`, methodOf(t, got))
}

// A method is client input, and a control character in one used to be written
// into the rewritten body raw: the result was not JSON, and the client got a
// parse error on a request it had sent correctly encoded.
func TestRewriteMethodSlash_ControlCharactersStayValidJSON(t *testing.T) {
	t.Parallel()
	for name, method := range map[string]string{
		"newline":   "tools/li\nst",
		"tab":       "tools/li\tst",
		"nul":       "tools/li\x00st",
		"escape":    "tools/li\x1bst",
		"non-ascii": "инструменты/список",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			in, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method})
			require.NoError(t, err)

			got, err := RewriteMethodSlash(in)
			require.NoError(t, err)

			// The point of the test: whatever the method was, what comes back
			// still parses, and the slash is gone.
			var m map[string]any
			require.NoError(t, json.Unmarshal(got, &m), "rewritten body must stay valid JSON: %q", got)
			assert.Equal(t, strings.ReplaceAll(method, "/", "."), m["method"])
		})
	}
}

func TestRewriteMethodSlash_BrokenJSON(t *testing.T) {
	t.Parallel()
	_, err := RewriteMethodSlash([]byte(`{"jsonrpc":"2.0","method":`))
	assert.Error(t, err)
}

func TestIsNotification(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"with id", `{"jsonrpc":"2.0","id":1,"method":"ping"}`, false},
		{"no id", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, true},
		// Arrays are refused before this question is asked (transport.go), so
		// an array is never a notification here.
		{"array of notifications", `[{"jsonrpc":"2.0","method":"a"},{"jsonrpc":"2.0","method":"b"}]`, false},
		{"mixed array", `[{"jsonrpc":"2.0","id":1,"method":"a"},{"jsonrpc":"2.0","method":"b"}]`, false},
		{"broken json", `{`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var p fastjson.Parser
			v, err := p.Parse(tc.body)
			if err != nil {
				assert.False(t, tc.want, "a body that does not parse is never a notification")
				return
			}
			assert.Equal(t, tc.want, isNotification(v))
		})
	}
}

func TestIsBatch(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		`[{"jsonrpc":"2.0"}]`:      true,
		"  \n\t[{}]":               true, // leading whitespace is not the answer
		`{"jsonrpc":"2.0"}`:        false,
		"":                         false,
		` {"method":"tools/list"}`: false,
	}
	for body, want := range cases {
		t.Run(body, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, want, isBatch([]byte(body)))
		})
	}
}
