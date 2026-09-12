package mcp

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeArgs(t *testing.T) {
	t.Parallel()
	type args struct {
		Name  string   `json:"name"`
		Limit int      `json:"limit"`
		Tags  []string `json:"tags"`
	}

	t.Run("the json tags are the description of what a tool takes", func(t *testing.T) {
		t.Parallel()
		var got args
		require.NoError(t, DecodeArgs(map[string]any{
			"name": "x", "limit": float64(5), "tags": []any{"a", "b"},
		}, &got))
		assert.Equal(t, args{Name: "x", Limit: 5, Tags: []string{"a", "b"}}, got)
	})

	t.Run("an absent key leaves the zero value", func(t *testing.T) {
		t.Parallel()
		var got args
		require.NoError(t, DecodeArgs(map[string]any{"name": "x"}, &got))
		assert.Equal(t, args{Name: "x"}, got)
	})

	t.Run("a wrong type is an error the tool can report", func(t *testing.T) {
		t.Parallel()
		var got args
		assert.Error(t, DecodeArgs(map[string]any{"limit": "not a number"}, &got))
	})

	t.Run("nil map decodes to nothing", func(t *testing.T) {
		t.Parallel()
		var got args
		require.NoError(t, DecodeArgs(nil, &got))
		assert.Equal(t, args{}, got)
	})
}

func TestSchemaFor(t *testing.T) {
	t.Parallel()
	type call struct {
		Target string `json:"target" jsonschema:"required" jsonschema_description:"Name from the catalogue."`
		JQ     string `json:"jq,omitempty"`
	}

	raw := SchemaFor(call{})
	var schema map[string]any
	require.NoError(t, json.Unmarshal(raw, &schema))

	assert.Equal(t, "object", schema["type"])
	assert.NotContains(t, schema, "$schema", "MCP has no use for it")
	assert.NotContains(t, schema, "$id")
	assert.NotContains(t, schema, "$defs", "refs are inlined for tools/list")
	assert.Equal(t, []any{"target"}, schema["required"])
	assert.Equal(t, false, schema["additionalProperties"])

	props, ok := schema["properties"].(map[string]any)
	require.True(t, ok)
	assert.Contains(t, props, "target")
	assert.Contains(t, props, "jq")
	target, ok := props["target"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "Name from the catalogue.", target["description"])
}

func TestTruncate(t *testing.T) {
	t.Parallel()

	t.Run("under the limit is untouched", func(t *testing.T) {
		t.Parallel()
		out, cut, total := Truncate("hello", 10)
		assert.Equal(t, "hello", out)
		assert.False(t, cut)
		assert.Equal(t, 5, total)
	})

	t.Run("a limit of zero is no limit", func(t *testing.T) {
		t.Parallel()
		out, cut, _ := Truncate("hello", 0)
		assert.Equal(t, "hello", out)
		assert.False(t, cut)
	})

	t.Run("over the limit is cut and marked", func(t *testing.T) {
		t.Parallel()
		out, cut, total := Truncate("0123456789", 4)
		assert.Equal(t, "0123"+TruncateMarker, out)
		assert.True(t, cut)
		assert.Equal(t, 10, total, "total is the original length, not the cut one")
	})

	// A byte slice of UTF-8 breaks the character it lands in, and with it the
	// JSON document carrying the character.
	t.Run("cuts on a rune boundary", func(t *testing.T) {
		t.Parallel()
		s := strings.Repeat("ы", 10) // two bytes per rune
		out, cut, _ := Truncate(s, 5)
		require.True(t, cut)
		body := strings.TrimSuffix(out, TruncateMarker)
		assert.True(t, utf8.ValidString(body), "cut mid-rune: %q", body)
		assert.Len(t, body, 4, "the cut moved back to the boundary")
	})

	t.Run("the marker tells the model the answer is partial", func(t *testing.T) {
		t.Parallel()
		out, _, _ := Truncate("0123456789", 4)
		assert.Contains(t, out, "truncated")
	})
}
