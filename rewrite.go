package mcpkit

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/valyala/fastjson"
)

// RewriteMethodSlash turns an MCP method name into the `namespace.method` form
// zenrpc dispatches on. Handles single requests and batch arrays.
//
// Why: MCP uses method names like `tools/list`, `resources/read`,
// `notifications/initialized`. zenrpc dispatches on `namespace.method` and
// cannot route `/`. Rewriting the method at the transport boundary lets a
// service register plain zenrpc services under the `tools`, `resources`,
// `prompts`, `notifications` namespaces.
//
// The first slash becomes the dot; the rest are folded away in camelCase —
// `resources/templates/list` becomes `resources.templatesList`. Replacing every
// slash with a dot looked right and was not: zenrpc splits on the *first* dot,
// so a three-segment name arrived as namespace `resources` and method
// `templates.list`, which no Go method can be called. Folding keeps one rule for
// names of any length, so the next three-segment method the spec adds needs no
// table and no second thought.
//
// Arrays are walked even though the transport refuses batches earlier: the
// function is exported and has to be correct on its own.
//
// Allocates only when a rewrite happens — pure zero-copy when method has no `/`.
func RewriteMethodSlash(body []byte) ([]byte, error) {
	var p fastjson.Parser
	v, err := p.ParseBytes(body)
	if err != nil {
		return nil, fmt.Errorf("fastjson: %w", err)
	}

	changed := rewriteValue(v)
	if !changed {
		return body, nil
	}
	return v.MarshalTo(nil), nil
}

func rewriteValue(v *fastjson.Value) bool {
	changed := false
	switch v.Type() {
	case fastjson.TypeArray:
		for _, item := range v.GetArray() {
			if rewriteValue(item) {
				changed = true
			}
		}
	case fastjson.TypeObject:
		m := v.GetStringBytes("method")
		if len(m) > 0 && bytes.ContainsRune(m, '/') {
			fixed := foldMethod(m)
			// The method arrives from an untrusted client, so the JSON string
			// literal is built by the encoder rather than by hand: a control
			// character hand-escaping missed used to be written into the body
			// raw, and the document this function returned was no longer JSON.
			//
			// Neither Marshal on a string nor the parse that follows can fail;
			// the error paths are guarded rather than asserted, because a panic
			// here would be reachable from the wire.
			quoted, err := json.Marshal(string(fixed))
			if err != nil {
				return changed
			}
			nv, err := fastjson.ParseBytes(quoted)
			if err != nil {
				return changed
			}
			v.Set("method", nv)
			changed = true
		}
	case fastjson.TypeNull, fastjson.TypeString, fastjson.TypeNumber, fastjson.TypeTrue, fastjson.TypeFalse:
		// scalar — nothing to rewrite
	}
	return changed
}

// foldMethod maps an MCP method name onto a zenrpc one: the first slash becomes
// the dot that separates namespace from method, and every later segment is
// appended with its first letter upper-cased.
//
//	tools/list                    → tools.list
//	resources/templates/list      → resources.templatesList
//	notifications/resources/updated → notifications.resourcesUpdated
//
// Case costs nothing here: zenrpc lower-cases the method before looking it up,
// so `templatesList` finds the Go method TemplatesList. An empty segment is
// folded as it stands — a malformed name stays malformed and gets the ordinary
// "method not found" rather than a special error nobody asked for.
func foldMethod(m []byte) []byte {
	head, tail, found := bytes.Cut(m, []byte("/"))
	if !found {
		return m
	}
	out := make([]byte, 0, len(m))
	out = append(out, head...)
	out = append(out, '.')

	upperNext := false
	for _, c := range tail {
		switch {
		case c == '/':
			upperNext = true // the segment boundary disappears into the case
		case upperNext:
			// ASCII only, deliberately: the method name arrives from the wire,
			// and upper-casing an arbitrary byte through unicode would widen it
			// past a byte. Method names the spec defines are ASCII, and one that
			// is not stays as it came and gets an ordinary "method not found".
			if c >= 'a' && c <= 'z' {
				c -= 'a' - 'A'
			}
			out = append(out, c)
			upperNext = false
		default:
			out = append(out, c)
		}
	}
	return out
}
