package mcp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every DTO has to survive the wire: a field that marshals one way and
// unmarshals another is a protocol bug that only shows up in a client.
func TestRoundTrip(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		v    any
	}{
		{"InitializeResult", &InitializeResult{
			ProtocolVersion: "2026-07-28",
			Capabilities: Capabilities{
				Tools:     &ToolsCapability{ListChanged: true},
				Resources: &ResourcesCapability{Subscribe: true, ListChanged: true},
				Prompts:   &PromptsCapability{ListChanged: true},
			},
			ServerInfo:   ServerInfo{Name: "srv", Version: "1.2.3"},
			Instructions: "read this first",
		}},
		{"PingResult", &PingResult{}},
		{"Tool", &Tool{
			Name:        "hello",
			Description: "Says hello.",
			InputSchema: json.RawMessage(`{"type":"object"}`),
			Annotations: &ToolAnnotations{Title: "Hello", ReadOnlyHint: new(true), DestructiveHint: new(false)},
		}},
		{"ToolList", &ToolList{Tools: []Tool{{Name: "a", InputSchema: json.RawMessage(`{}`)}}}},
		{"ToolCallResult", &ToolCallResult{Content: []ContentBlock{{Type: ContentTypeText, Text: "x"}}, IsError: true}},
		{"ResourceList", &ResourceList{Resources: []ResourceEntry{{URI: "d://a", Name: "a", Description: "d", MimeType: "text/markdown"}}}},
		{"ResourceData", &ResourceData{Contents: []ResourceContent{{URI: "d://a", MimeType: "text/markdown", Text: "body"}}}},
		{"PromptList", &PromptList{Prompts: []PromptEntry{{Name: "p", Description: "d", Arguments: []Argument{{Name: "a", Required: true}}}}}},
		{"RenderedPrompt", &RenderedPrompt{Description: "d", Messages: []PromptMessage{{Role: RoleUser, Content: PromptMessageContent{Type: ContentTypeText, Text: "t"}}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b, err := json.Marshal(tc.v)
			require.NoError(t, err)

			// Same concrete type, zeroed, to unmarshal back into.
			back := newLike(tc.v)
			require.NoError(t, json.Unmarshal(b, back))
			assert.Equal(t, tc.v, back)
		})
	}
}

// newLike returns a fresh zero value of the same pointer type as v.
func newLike(v any) any {
	switch v.(type) {
	case *InitializeResult:
		return &InitializeResult{}
	case *PingResult:
		return &PingResult{}
	case *Tool:
		return &Tool{}
	case *ToolList:
		return &ToolList{}
	case *ToolCallResult:
		return &ToolCallResult{}
	case *ResourceList:
		return &ResourceList{}
	case *ResourceData:
		return &ResourceData{}
	case *PromptList:
		return &PromptList{}
	case *RenderedPrompt:
		return &RenderedPrompt{}
	}
	panic("newLike: unhandled type")
}

// Clients with strict schemas reject null where an array was promised, so a
// list built from an empty slice has to stay a list.
func TestEmptyListsMarshalAsArrays(t *testing.T) {
	t.Parallel()
	cases := map[string]any{
		`{"resultType":"complete","resources":[],"ttlMs":0,"cacheScope":"private"}`: ResourceList{
			Resources: []ResourceEntry{}, CacheHint: CacheHint{}.Normalized()},
		`{"resultType":"complete","prompts":[],"ttlMs":0,"cacheScope":"private"}`: PromptList{
			Prompts: []PromptEntry{}, CacheHint: CacheHint{}.Normalized()},
		`{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}`: ToolList{
			Tools: []Tool{}, CacheHint: CacheHint{}.Normalized()},
	}
	for want, v := range cases {
		t.Run(want, func(t *testing.T) {
			t.Parallel()
			b, err := json.Marshal(v)
			require.NoError(t, err)
			assert.JSONEq(t, want, string(b))
			assert.NotContains(t, string(b), "null")
		})
	}
}

// Optional fields must not appear when empty: an annotation block of all-false
// hints is not the same as no hints, and the difference reaches the client.
func TestOmitEmpty(t *testing.T) {
	t.Parallel()
	b, err := json.Marshal(Tool{Name: "t", InputSchema: json.RawMessage(`{}`)})
	require.NoError(t, err)
	assert.NotContains(t, string(b), "annotations")

	b, err = json.Marshal(ToolCallResult{Content: []ContentBlock{{Type: ContentTypeText, Text: "x"}}})
	require.NoError(t, err)
	assert.NotContains(t, string(b), "isError", "a successful call says nothing about errors")
}

// A capability a server declares is one it promises to answer: "Servers that
// declare the prompts capability MUST respond to prompts/list requests". So not
// declaring one has to be expressible — with value fields it was not, and a
// server with only tools invited the client into two namespaces that answer
// -32601.
func TestCapabilitiesDeclareOnlyWhatWasSet(t *testing.T) {
	t.Parallel()

	b, err := json.Marshal(Capabilities{Tools: &ToolsCapability{ListChanged: true}})
	require.NoError(t, err)
	assert.JSONEq(t, `{"tools":{"listChanged":true}}`, string(b))
	assert.NotContains(t, string(b), "prompts")
	assert.NotContains(t, string(b), "resources")

	b, err = json.Marshal(Capabilities{})
	require.NoError(t, err)
	assert.JSONEq(t, `{}`, string(b), "a server that declares nothing says nothing")
}

// The hints are pointers because their defaults are not all false: the spec
// says destructiveHint and openWorldHint default to true. A plain bool left
// unset used to marshal as false and tell the client the opposite of the
// default — that an unannotated tool is safe to auto-approve.
func TestToolAnnotationHintsOmitWhenUnset(t *testing.T) {
	t.Parallel()

	b, err := json.Marshal(ToolAnnotations{Title: "Say hello"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"title":"Say hello"}`, string(b))

	b, err = json.Marshal(ToolAnnotations{ReadOnlyHint: new(true), DestructiveHint: new(false)})
	require.NoError(t, err)
	assert.JSONEq(t, `{"readOnlyHint":true,"destructiveHint":false}`, string(b),
		"an explicit false is not the same as saying nothing, and both have to survive the wire")
	assert.NotContains(t, string(b), "idempotentHint")
}

// Exactly one of text and blob is set. Binary data "MUST be properly encoded",
// and a byte slice that is not valid UTF-8 pushed through text comes back out
// of the encoder as U+FFFD — a document that parses and is wrong.
func TestResourceContentCarriesTextOrBlob(t *testing.T) {
	t.Parallel()

	b, err := json.Marshal(ResourceContent{URI: "d://a", MimeType: "text/markdown", Text: "body"})
	require.NoError(t, err)
	assert.NotContains(t, string(b), "blob")

	b, err = json.Marshal(ResourceContent{URI: "d://a", MimeType: "image/png", Blob: "iVBORw0K"})
	require.NoError(t, err)
	assert.NotContains(t, string(b), `"text"`)
}

// "The result MUST include a resultType field to indicate the type of the
// result." One pass over every result this library produces, because the whole
// point of doing it at the encoder is that no one has to remember it — and a
// type added later without the method is exactly what this test is for.
func TestEveryResultCarriesResultType(t *testing.T) {
	t.Parallel()
	results := []any{
		InitializeResult{},
		PingResult{},
		ToolList{Tools: []Tool{}},
		ToolCallResult{Content: []ContentBlock{{Type: ContentTypeText, Text: "x"}}},
		ResourceList{Resources: []ResourceEntry{}},
		ResourceData{Contents: []ResourceContent{{URI: "d://a"}}},
		PromptList{Prompts: []PromptEntry{}},
		RenderedPrompt{Messages: []PromptMessage{}},
	}
	for _, r := range results {
		t.Run(fmt.Sprintf("%T", r), func(t *testing.T) {
			t.Parallel()
			b, err := json.Marshal(r)
			require.NoError(t, err)

			var back map[string]any
			require.NoError(t, json.Unmarshal(b, &back), "still has to be valid JSON: %s", b)
			assert.Equal(t, ResultTypeComplete, back["resultType"])
		})
	}

	// A nested value is not a result and must not claim to be one.
	for _, v := range []any{Tool{Name: "t"}, ResourceEntry{URI: "u"}, ContentBlock{Type: ContentTypeText}} {
		b, err := json.Marshal(v)
		require.NoError(t, err)
		assert.NotContains(t, string(b), "resultType", "%T is part of an answer, not an answer", v)
	}
}

func TestEnvelopes(t *testing.T) {
	t.Parallel()

	t.Run("TextResult", func(t *testing.T) {
		t.Parallel()
		r := TextResult("hello")
		assert.False(t, r.IsError)
		require.Len(t, r.Content, 1)
		assert.Equal(t, ContentBlock{Type: ContentTypeText, Text: "hello"}, r.Content[0])
	})

	// A tool failure travels inside a successful JSON-RPC response: the model is
	// meant to read it and try again, which a transport error does not let it do.
	t.Run("ErrorResult", func(t *testing.T) {
		t.Parallel()
		r := ErrorResult("nope")
		assert.True(t, r.IsError)
		assert.Equal(t, "nope", r.Content[0].Text)
	})

	t.Run("JSONResult", func(t *testing.T) {
		t.Parallel()
		r, err := JSONResult(map[string]int{"n": 1})
		require.NoError(t, err)
		assert.JSONEq(t, `{"n":1}`, r.Content[0].Text)
		assert.False(t, r.IsError)

		_, err = JSONResult(make(chan int))
		assert.Error(t, err, "a value json cannot marshal is the caller's bug, not an answer")
	})

	t.Run("Size counts what the model receives", func(t *testing.T) {
		t.Parallel()
		r := ToolCallResult{Content: []ContentBlock{{Text: "abc"}, {Text: "de"}}}
		assert.Equal(t, 5, r.Size())
	})

	// An image is the largest thing a tool can return. Leaving base64 out of the
	// figure would make the one answer worth watching the one reported as zero.
	t.Run("Size counts base64 too", func(t *testing.T) {
		t.Parallel()
		r := ToolCallResult{Content: []ContentBlock{ImageBlock([]byte("0123456789"), "image/png")}}
		assert.Equal(t, len(base64.StdEncoding.EncodeToString([]byte("0123456789"))), r.Size())
	})
}

// A tool can answer with more than text, and each kind carries its own fields.
// The union is one struct, so the test that matters is that each constructor
// fills its own and leaves the others out of the document.
func TestContentBlocks(t *testing.T) {
	t.Parallel()

	t.Run("image and audio carry base64 and a type", func(t *testing.T) {
		t.Parallel()
		raw := []byte{0x89, 'P', 'N', 'G', 0x00, 0xff}
		for _, tc := range []struct {
			block ContentBlock
			want  string
		}{
			{ImageBlock(raw, "image/png"), ContentTypeImage},
			{AudioBlock(raw, "audio/wav"), ContentTypeAudio},
		} {
			assert.Equal(t, tc.want, tc.block.Type)
			decoded, err := base64.StdEncoding.DecodeString(tc.block.Data)
			require.NoError(t, err)
			assert.Equal(t, raw, decoded, "the bytes come back exactly as they went in")
			assert.Empty(t, tc.block.Text, "a binary block carries no text")

			b, err := json.Marshal(tc.block)
			require.NoError(t, err)
			assert.NotContains(t, string(b), `"text"`)
			assert.NotContains(t, string(b), `"uri"`)
		}
	})

	// A link is how a tool points at the catalogue instead of inlining it, so
	// what it carries has to be what resources/list carried — the model decides
	// from the same description.
	t.Run("a resource link is the catalogue entry", func(t *testing.T) {
		t.Parallel()
		e := ResourceEntry{
			URI: "docs://a.md", Name: "a", Title: "A", Description: "about a",
			MimeType: "text/markdown", Size: 42,
			Icons: []Icon{{Src: "https://example.com/i.png"}},
		}
		got := ResourceLinkBlock(e)
		assert.Equal(t, ContentTypeResourceLink, got.Type)
		assert.Equal(t, e.URI, got.URI)
		assert.Equal(t, e.Name, got.Name)
		assert.Equal(t, e.Title, got.Title)
		assert.Equal(t, e.Description, got.Description)
		assert.Equal(t, e.MimeType, got.MimeType)
		assert.Equal(t, e.Size, got.Size)
		assert.Equal(t, e.Icons, got.Icons)
	})

	t.Run("an embedded resource carries the contents", func(t *testing.T) {
		t.Parallel()
		got := ResourceBlock(ResourceContent{URI: "docs://a.md", MimeType: "text/markdown", Text: "body"})
		assert.Equal(t, ContentTypeResource, got.Type)
		require.NotNil(t, got.Resource)
		assert.Equal(t, "body", got.Resource.Text)
	})

	// Every kind has to survive the wire; a field that marshals one way and
	// unmarshals another is a protocol bug that only shows up in a client.
	t.Run("round trip", func(t *testing.T) {
		t.Parallel()
		for _, in := range []ContentBlock{
			{Type: ContentTypeText, Text: "hello"},
			ImageBlock([]byte("bytes"), "image/png"),
			AudioBlock([]byte("bytes"), "audio/wav"),
			ResourceLinkBlock(ResourceEntry{URI: "docs://a.md", Name: "a", Size: 7}),
			ResourceBlock(ResourceContent{URI: "docs://a.md", Blob: "AAEC"}),
		} {
			b, err := json.Marshal(in)
			require.NoError(t, err)
			var back ContentBlock
			require.NoError(t, json.Unmarshal(b, &back))
			assert.Equal(t, in, back)
		}
	})
}

// The sentinel is a header value, which is to say it is whatever the client
// sent. "=?base64?=" satisfied both the prefix and the suffix check on the same
// two characters, and the slice that followed read s[9:8] — one header away
// from taking the connection down.
func TestDecodeHeaderValueSurvivesHostileInput(t *testing.T) {
	t.Parallel()
	for _, s := range []string{
		"=?base64?=",      // prefix and suffix overlap
		"=?base64?",       // prefix only
		"?=",              // suffix only
		"=?base64??=",     // empty payload
		"=?base64?a?=",    // payload that is not base64
		"=?base64?" + "=", // the same overlap spelt differently
		"",
		"=",
		"=?",
	} {
		t.Run(s, func(t *testing.T) {
			t.Parallel()
			assert.NotPanics(t, func() { _, _ = DecodeHeaderValue(s) })
		})
	}

	// The round trip still works, which is what the sentinel is for.
	got, err := DecodeHeaderValue(EncodeHeaderValue("docs://привет.md"))
	require.NoError(t, err)
	assert.Equal(t, "docs://привет.md", got)
}

// SEP-973 gave the server somewhere to say who it is in human terms. The fields
// are optional, so the test that earns its place is that they stay absent when
// unset — a serverInfo full of empty strings is worse than a short one.
func TestServerInfoMetadata(t *testing.T) {
	t.Parallel()

	bare, err := json.Marshal(ServerInfo{Name: "srv", Version: "1.0.0"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"name":"srv","version":"1.0.0"}`, string(bare))

	full := ServerInfo{
		Name: "srv", Version: "1.0.0",
		Title: "The Service", Description: "What it does.",
		WebsiteURL: "https://example.com/docs",
		Icons:      []Icon{{Src: "https://example.com/i.png", MimeType: "image/png"}},
	}
	b, err := json.Marshal(full)
	require.NoError(t, err)
	var back ServerInfo
	require.NoError(t, json.Unmarshal(b, &back))
	assert.Equal(t, full, back)
}

func TestMap(t *testing.T) {
	t.Parallel()
	got := Map([]int{1, 2, 3}, func(i int) string { return strings.Repeat("x", i) })
	assert.Equal(t, []string{"x", "xx", "xxx"}, got)
	assert.Empty(t, Map(nil, func(i int) int { return i }))
}
