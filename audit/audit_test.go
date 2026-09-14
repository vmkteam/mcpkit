package audit

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vmkteam/mcpkit/redact"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

// A lone ESC is not an ANSI sequence, and treating it as one let a single byte
// swallow everything after it: the crafted string then deleted the part of the
// record that was supposed to describe it.
func TestSanitizeTextBoundsTheEscapeWindow(t *testing.T) {
	t.Parallel()

	t.Run("a real sequence is dropped whole", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "red text", SanitizeText("\x1b[31mred text\x1b[0m", 100))
	})

	t.Run("a lone escape does not eat the rest of the line", func(t *testing.T) {
		t.Parallel()
		got := SanitizeText("\x1b"+strings.Repeat("1", 64)+" tail", 200)
		assert.Contains(t, got, "tail", "the record must survive a stray ESC")
		assert.Greater(t, len(got), 40, "at most MaxEscapeLen characters may be dropped")
	})
}

// capture runs fn with a logger writing to a pipe and returns the records it
// produced. embedlog binds its writer at construction, so the only way to read
// what it prints is to hand it a pipe as stdout for that instant.
func capture(t *testing.T, opts Options, fn func(w Writer)) []map[string]any {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)

	orig := os.Stdout
	os.Stdout = w
	logger := embedlog.NewLogger(true, true)
	os.Stdout = orig

	fn(NewWriter(logger, opts))
	require.NoError(t, w.Close())

	raw, err := io.ReadAll(r)
	require.NoError(t, err)

	var out []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) == nil && rec[EventKey] == EventValue {
			out = append(out, rec)
		}
	}
	return out
}

func TestWrite_CoreKeys(t *testing.T) {
	recs := capture(t, Options{}, func(w Writer) {
		w.Write(t.Context(), Record{
			TraceID:    "trace-1",
			Subject:    "alice-uuid",
			Email:      "alice@example.com",
			Groups:     []string{"mcp-users", "analysts"},
			Roles:      []string{"analyst"},
			Tool:       "db_query",
			Source:     "warehouse",
			Env:        "prod",
			Intent:     "count signups",
			Query:      "SELECT count() FROM users",
			Decision:   DecisionAllow,
			Rows:       100,
			RowsOut:    50,
			BytesOut:   4096,
			Truncated:  true,
			Masked:     []string{redact.RuleEmail},
			BatchSize:  3,
			BatchIndex: 1,
			Duration:   1500 * time.Millisecond,
		})
	})
	require.Len(t, recs, 1)
	r := recs[0]

	assert.Equal(t, DefaultMessage, r["msg"])
	assert.Equal(t, "trace-1", r["trace_id"])
	assert.Equal(t, "alice-uuid", r["sub"])
	assert.Equal(t, "alice@example.com", r["email"])
	assert.Equal(t, "mcp-users,analysts", r["groups"])
	assert.Equal(t, "analyst", r["roles"])
	assert.Equal(t, "db_query", r["tool"])
	assert.Equal(t, "warehouse", r["source"])
	assert.Equal(t, "prod", r["env"])
	assert.Equal(t, "count signups", r["intent"])
	assert.Equal(t, DecisionAllow, r["decision"])
	assert.InDelta(t, float64(100), r["rows"], 0)
	assert.InDelta(t, float64(50), r["rows_out"], 0)
	assert.InDelta(t, float64(4096), r["bytes_out"], 0)
	assert.Equal(t, true, r["truncated"])
	assert.Equal(t, redact.RuleEmail, r["masked"])
	assert.InDelta(t, float64(3), r["batch_size"], 0)
	assert.InDelta(t, float64(1), r["batch_index"], 0)
	assert.InDelta(t, float64(1500), r["duration_ms"], 0)

	// Key and field agree: `query`, not `sql` — the text is a path as often as
	// it is a statement.
	assert.Equal(t, "SELECT count() FROM users", r["query"])
	assert.Equal(t, Hash("SELECT count() FROM users"), r["query_sha256"])
}

// A field a call did not have stays empty rather than being omitted, so a query
// never has to guess whether the field is missing or the call never had it.
func TestWrite_EmptyFieldsArePresent(t *testing.T) {
	recs := capture(t, Options{}, func(w Writer) {
		w.Write(t.Context(), Record{Tool: "ping"})
	})
	require.Len(t, recs, 1)

	for _, key := range []string{
		"trace_id", "sub", "email", "groups", "roles", "tool", "source", "env",
		"intent", "query", "query_sha256", "uri", "decision", "deny_reason",
		"rows", "rows_out", "bytes_out", "truncated", "masked",
		"batch_size", "batch_index", "duration_ms",
	} {
		assert.Containsf(t, recs[0], key, "core key %q must always be written", key)
	}
}

// A refusal is the record that matters most, and it names its caller the way an
// answered call does.
func TestWrite_Denial(t *testing.T) {
	recs := capture(t, Options{}, func(w Writer) {
		w.Write(t.Context(), Record{
			Subject: "bob", Tool: "db_query",
			Decision: DecisionDeny, DenyReason: "table not allowed",
		})
	})
	require.Len(t, recs, 1)
	assert.Equal(t, DecisionDeny, recs[0]["decision"])
	assert.Equal(t, "table not allowed", recs[0]["deny_reason"])
	assert.Equal(t, "bob", recs[0]["sub"])
}

// The message is what a log query matches on before it parses a field, so each
// service keeps its own.
func TestWrite_MessageIsAParameter(t *testing.T) {
	recs := capture(t, Options{Message: "api call"}, func(w Writer) {
		w.Write(t.Context(), Record{Tool: "x"})
	})
	require.Len(t, recs, 1)
	assert.Equal(t, "api call", recs[0]["msg"])
}

// Extra is written after the core keys, so a service's own field cannot
// displace one of them.
func TestWrite_Extra(t *testing.T) {
	recs := capture(t, Options{}, func(w Writer) {
		w.Write(t.Context(), Record{
			Tool:  "api_call",
			Extra: []any{"target", "grafana", "method", "GET", "upstream_status", 200},
		})
	})
	require.Len(t, recs, 1)
	assert.Equal(t, "grafana", recs[0]["target"])
	assert.Equal(t, "GET", recs[0]["method"])
	assert.InDelta(t, float64(200), recs[0]["upstream_status"], 0)
	assert.Equal(t, "api_call", recs[0]["tool"], "a core key is still the core key")
}

// A deployment may choose to show a user full values; the log is read by
// everyone who can read logs.
func TestWrite_MasksAlways(t *testing.T) {
	recs := capture(t, Options{}, func(w Writer) {
		w.Write(t.Context(), Record{
			Query: "SELECT * FROM users WHERE email = 'alice@acme.com'",
			URI:   "docs://users/alice@acme.com.md",
		})
	})
	require.Len(t, recs, 1)
	assert.Equal(t, "SELECT * FROM users WHERE email = 'a***@acme.com'", recs[0]["query"])
	assert.Equal(t, "docs://users/a***@acme.com.md", recs[0]["uri"])
}

// "Model-authored strings are masked on the way in, always" is the rule at the
// top of this package, and intent is the field whose own doc calls it
// model-authored. It used to be sanitised only — control characters escaped,
// the card number written through verbatim into the log that exists so nobody
// has to hold one.
func TestWrite_MasksIntentToo(t *testing.T) {
	recs := capture(t, Options{}, func(w Writer) {
		w.Write(t.Context(), Record{
			Intent: "look up card 4111 1111 1111 1111 for sergey@acme.com",
		})
	})
	require.Len(t, recs, 1)
	intent, _ := recs[0]["intent"].(string)
	assert.NotContains(t, intent, "4111 1111 1111 1111", "a card number must not reach the log")
	assert.NotContains(t, intent, "sergey@acme.com")
	assert.Contains(t, intent, "look up card", "the sentence around it still has to be readable")
}

func TestWriterText(t *testing.T) {
	t.Parallel()
	w := NewWriter(embedlog.Logger{}, Options{})

	t.Run("empty stays empty", func(t *testing.T) {
		t.Parallel()
		assert.Empty(t, w.Text(""))
	})

	t.Run("masked and flattened", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "SELECT 1 WHERE email = 's***@acme.com'",
			w.Text("SELECT 1\n  WHERE email = 'sergey@acme.com'"))
	})

	// Masking before the cut, with slack, is what keeps the cut from splitting a
	// match and leaving half of an address in the log.
	t.Run("a match on the cap boundary is masked whole", func(t *testing.T) {
		t.Parallel()
		// The address starts before the cap and ends after it. Without the slack
		// the pre-mask cut would split it and leave "sergey@acm" in the log;
		// with it the whole address is inside the window, gets masked, and only
		// the marker is shortened by the final cut.
		pad := strings.Repeat("x", MaxTextLen-10)
		out := w.Text(pad + " sergey@acme.com tail")
		assert.NotContains(t, out, "sergey@", "half an address is still an address")
		assert.Contains(t, out, "s***@", "what survives the cut is the marker, not the value")

		// Well inside the cap, the whole marker survives.
		short := w.Text(strings.Repeat("x", 100) + " sergey@acme.com")
		assert.Contains(t, short, "s***@acme.com")
	})

	t.Run("capped at MaxTextLen", func(t *testing.T) {
		t.Parallel()
		out := w.Text(strings.Repeat("a", MaxTextLen*2))
		assert.LessOrEqual(t, len([]rune(out)), MaxTextLen)
	})
}

// An unknown rule name must not switch masking off: a masker that masks too
// much is a readable log, one that masks nothing is a leak.
func TestWriterFailsClosed(t *testing.T) {
	t.Parallel()
	w := NewWriter(embedlog.Logger{}, Options{Redact: redact.Options{Rules: []string{"nonsense"}}})
	assert.Equal(t, "s***@acme.com", w.Text("sergey@acme.com"))
}

func TestWriterRedactOptions(t *testing.T) {
	t.Parallel()
	w := NewWriter(embedlog.Logger{}, Options{Redact: redact.Options{MaskEmailDomain: true}})
	assert.Equal(t, redact.Marker(redact.RuleEmail), w.Text("sergey@acme.com"))

	limited := NewWriter(embedlog.Logger{}, Options{Redact: redact.Options{Rules: []string{redact.RuleIP}}})
	assert.Equal(t, "sergey@acme.com", limited.Text("sergey@acme.com"),
		"a service that named its rules gets those rules")
}

// Without this a crafted intent forges log lines: the injection gets to write
// into the record that is supposed to describe it.
func TestSanitizeText(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		in   string
		max  int
		want string
	}{
		"newlines become spaces": {"a\nb\r\nc", 100, "a b c"},
		"tabs become spaces":     {"a\tb", 100, "a b"},
		"ansi escapes are gone":  {"\x1b[31mred\x1b[0m", 100, "red"},
		"control chars are gone": {"a\x00\x07b", 100, "ab"},
		"runs of space collapse": {"a     b", 100, "a b"},
		"empty stays empty":      {"", 100, ""},
		"capped by runes":        {"ыыыыы", 3, "ыыы"},
		"a forged line is inert": {"ok\nevent=audit decision=allow", 100, "ok event=audit decision=allow"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, SanitizeText(tc.in, tc.max))
		})
	}
}

func TestSanitizeTextCapsRunesNotBytes(t *testing.T) {
	t.Parallel()
	out := SanitizeText(strings.Repeat("ы", 10), 4)
	assert.Equal(t, "ыыыы", out)
	assert.Len(t, []rune(out), 4)
}

// The cap is a number of characters, and so is the slack that feeds it. Spent
// in bytes, it cut a Russian query at half its budget: the pre-cut kept
// MaxTextLen+CapSlack bytes of a string two bytes per character, and the cap it
// was meant to hand a whole query to never got to be the thing that cut.
func TestWrite_CapsAQueryInRunesNotBytes(t *testing.T) {
	long := strings.Repeat("ы", MaxTextLen*2)
	recs := capture(t, Options{}, func(w Writer) {
		w.Write(t.Context(), Record{Query: long})
	})
	require.Len(t, recs, 1)

	query, _ := recs[0]["query"].(string)
	assert.Len(t, []rune(query), MaxTextLen, "a Cyrillic query gets the whole character budget")
}

func TestHash(t *testing.T) {
	t.Parallel()
	assert.Empty(t, Hash(""))

	h := Hash("SELECT 1")
	assert.Len(t, h, HashLen)
	assert.Equal(t, h, Hash("SELECT 1"), "the same text hashes the same")
	assert.NotEqual(t, h, Hash("SELECT 2"))
}

// The hash is taken from the full text, so a capped query still matches its
// repeat.
func TestWrite_HashIsOfTheFullText(t *testing.T) {
	long := "SELECT " + strings.Repeat("a", MaxTextLen*2)
	recs := capture(t, Options{}, func(w Writer) {
		w.Write(t.Context(), Record{Query: long})
	})
	require.Len(t, recs, 1)

	query, _ := recs[0]["query"].(string)
	assert.LessOrEqual(t, len([]rune(query)), MaxTextLen, "the text is capped")
	assert.Equal(t, Hash(long), recs[0]["query_sha256"], "the hash is not")
}

// A service that computed the hash itself — over a query it never put in the
// record — keeps its value.
func TestWrite_HashCanBeSuppliedByTheCaller(t *testing.T) {
	recs := capture(t, Options{}, func(w Writer) {
		w.Write(t.Context(), Record{Query: "SELECT 1", QueryHash: "deadbeef1234"})
	})
	require.Len(t, recs, 1)
	assert.Equal(t, "deadbeef1234", recs[0]["query_sha256"])
}

// The dispatcher hands the hook whatever name the caller typed when the tool
// was not found — that is the point of recording refusals — so this field
// carries client input. Unescaped, a newline in it writes a second log line of
// the caller's choosing, under keys the caller chose.
func TestWrite_ToolNameIsSanitised(t *testing.T) {
	recs := capture(t, Options{}, func(w Writer) {
		w.Write(t.Context(), Record{
			Tool:       "hello\nevent=audit sub=root decision=allow",
			DenyReason: "nope\nevent=audit",
		})
	})
	require.Len(t, recs, 1, "one call writes one record, whatever the caller typed")
	tool, _ := recs[0]["tool"].(string)
	assert.NotContains(t, tool, "\n", "a newline in a tool name must not break the line")
	assert.Contains(t, tool, "hello")
	reason, _ := recs[0]["deny_reason"].(string)
	assert.NotContains(t, reason, "\n")
}

// Extra is where a service puts its own fields, and the doc names headers and
// upstream URLs among them — values derived from what the model asked for. An
// escape hatch that skipped the masking rule would be the one place the rule
// does not hold, and the place the field list grows.
func TestWrite_ExtraIsMaskedToo(t *testing.T) {
	recs := capture(t, Options{}, func(w Writer) {
		w.Write(t.Context(), Record{
			Extra: []any{
				"upstream", "https://api.example.com/users/sergey@acme.com",
				"headers", map[string]any{"x-user": "sergey@acme.com"},
				"status", 200,
			},
		})
	})
	require.Len(t, recs, 1)

	upstream, _ := recs[0]["upstream"].(string)
	assert.NotContains(t, upstream, "sergey@acme.com", "a string in Extra takes the same path as query")
	assert.Contains(t, upstream, "api.example.com", "the rest of the value still has to be readable")

	headers, ok := recs[0]["headers"].(map[string]any)
	require.True(t, ok, "a map keeps its shape: %#v", recs[0]["headers"])
	assert.NotContains(t, headers["x-user"], "sergey@acme.com", "the walk reaches strings inside a map")

	assert.InDelta(t, 200, recs[0]["status"], 0, "a number is not personal data and must survive intact")
}
