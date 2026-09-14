package mcp

// Helpers every tool dispatcher needs and every service wrote for itself:
// decoding the argument map, reflecting a schema out of the struct it decodes
// into, and cutting an answer to a budget.

import (
	"encoding/json"
	"unicode/utf8"

	"github.com/invopop/jsonschema"
)

// TruncateMarker tells the model the answer is incomplete. Without it a cut
// answer reads as the whole answer, and the model draws conclusions from the
// part it got.
const TruncateMarker = "…[truncated]"

// DecodeArgs converts the loosely typed argument map of tools/call into a
// struct, through JSON, so that the json tags of that struct are the single
// description of what the tool accepts.
func DecodeArgs(in map[string]any, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// SchemaFor reflects a Go struct into a JSON Schema (Draft 2020-12) shaped for
// the inputSchema of tools/list: refs inlined, no $defs, no additional
// properties. Call it once at startup — it is reflection, and tools/list is on
// the request path.
//
// It panics on a struct it cannot marshal, because that is a programming error
// discovered at startup and not a condition a server can run with.
func SchemaFor(v any) json.RawMessage {
	r := &jsonschema.Reflector{
		ExpandedStruct:             true,
		DoNotReference:             true,
		RequiredFromJSONSchemaTags: true,
		AllowAdditionalProperties:  false,
	}
	s := r.Reflect(v)
	// Strip the keys MCP has no use for.
	s.Version = ""
	s.ID = ""
	out, err := json.Marshal(s)
	if err != nil {
		panic("mcp: marshal jsonschema: " + err.Error())
	}
	return out
}

// CutBytes cuts s to at most limit bytes without splitting a rune, reporting
// whether it cut anything. It appends nothing: what marks the cut — a marker
// the model reads, an ellipsis a human reads — belongs to whoever is doing the
// cutting.
//
// The boundary matters: a byte-slice of UTF-8 breaks the character it lands in
// and, with it, the JSON document carrying the character. Every cut in this
// library goes through here, because the one that did not was the one that was
// wrong.
//
// The limit is a byte budget, and the name says so. It used to say runes, and
// the caller that read it that way — the audit, capping a query at so many
// characters — spent a rune budget in bytes and cut a Cyrillic query at half of
// it.
func CutBytes(s string, limit int) (string, bool) {
	if limit <= 0 || len(s) <= limit {
		return s, false
	}
	at := limit
	for at > 0 && !utf8.RuneStart(s[at]) {
		at--
	}
	return s[:at], true
}

// Truncate cuts s to limit bytes on a rune boundary and appends TruncateMarker,
// reporting whether it cut and how long the original was.
func Truncate(s string, limit int) (out string, cut bool, total int) {
	total = len(s)
	out, cut = CutBytes(s, limit)
	if cut {
		out += TruncateMarker
	}
	return out, cut, total
}
