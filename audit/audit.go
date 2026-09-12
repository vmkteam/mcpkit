// Package audit writes one record per MCP call: who asked, what they asked
// for, what was decided and what came out.
//
// Two rules shape everything here. A record is written for every call including
// the refused ones — a trail of successes answers none of the questions a trail
// is kept for. And answers never go into it: a log carrying bodies is an
// unmanaged second copy of the data that passed through it.
//
// Model-authored strings are masked on the way in, always, whatever the answer
// path is configured to do: a deployment may choose to show a user full values,
// but the log is read by everyone who can read logs.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/vmkteam/mcpkit/mcp"
	"github.com/vmkteam/mcpkit/redact"

	"github.com/vmkteam/embedlog"
)

// The record is marked so it can be selected with one query and kept apart from
// ordinary request logging.
const (
	EventKey   = "event"
	EventValue = "audit"
)

// What the server did with the call.
const (
	DecisionAllow = "allow"
	DecisionDeny  = "deny"
)

const (
	// MaxIntentLen caps the model-authored comment. A sentence fits; a log line
	// stays readable.
	MaxIntentLen = 120
	// MaxTextLen caps the longer model-authored strings — a query, a path. Two
	// kilobytes keep a whole query in one record and keep a record from becoming
	// the query.
	MaxTextLen = 2048
	// CapSlack is how much past the cap Text keeps before masking, so that a
	// match sitting on the boundary is matched whole instead of being cut in two
	// with half of it left in the log.
	CapSlack = 256
	// MaxNameLen caps the short identifiers a caller can influence — the tool
	// name, the deny reason. They are names, not prose: anything longer is
	// either a mistake or an attempt to fill the log with one record.
	MaxNameLen = 128
	// HashLen is how much of the SHA-256 of a query goes into the record: twelve
	// hex digits tie a capped query to its repeat without pretending to be a
	// fingerprint anyone verifies.
	HashLen = 12
	// MaxEscapeLen bounds how far SanitizeText will drop characters looking for
	// the end of an ANSI sequence. A real one is a handful of bytes; past that
	// the ESC was not opening a sequence at all, and continuing to drop would
	// let one byte erase the rest of the record.
	MaxEscapeLen = 16
)

// DefaultMessage is the log message when Options names none.
const DefaultMessage = "mcp call"

// Record is what any MCP server has to say about a call, whatever it serves.
// The fields are the union of what two services write, minus what is specific
// to one kind of upstream: an HTTP method or a table name goes into Extra.
//
// A field a call did not have stays empty rather than being omitted, so a log
// query never has to guess whether the field is missing or the call never had
// it.
type Record struct {
	// Who asked. Written before anything is decided, so a refused call names its
	// caller the way an answered one does.
	TraceID string
	Subject string
	Email   string
	Groups  []string
	Roles   []string

	// What was asked. Source is where the answer came from — a catalogue, a
	// database, an upstream; Env is the contour, and it comes from the config
	// and never from an argument.
	Tool   string
	Source string
	Env    string
	Intent string

	// Query is the model-authored text of the request: the SQL of a query tool,
	// the path of an HTTP one. Written masked and capped; QueryHash is taken
	// from the full text, so a capped query still matches its repeat.
	Query     string
	QueryHash string
	URI       string

	// What was decided.
	Decision   string
	DenyReason string

	// Rows is what the source returned, RowsOut what the client received: the
	// byte budget cuts between the two, and a record with only one of them
	// cannot say whether a masked value reached anyone.
	Rows      int
	RowsOut   int
	BytesOut  int
	Truncated bool
	// Masked names the rules that fired on the answer — which rule, not what it
	// fired on. An empty list where personal data lives is worth a look.
	Masked []string

	// Where in a batch. A batched call writes one record per item plus one for
	// the call itself with BatchIndex = -1; a tool that takes no list leaves
	// both at zero, so BatchSize tells the three kinds of record apart.
	BatchSize  int
	BatchIndex int

	Duration time.Duration

	// Extra are the service's own fields, written after the core ones:
	// target, method, headers and upstream status for an HTTP proxy, a table for
	// a database tool. Key-value pairs, as the logger takes them.
	Extra []any
}

// Options configures a Writer.
type Options struct {
	// Message is the log message, and it is what a log query matches on before
	// it parses any field. Each service keeps its own — changing it means
	// touching somebody's saved queries for a string that decides nothing.
	// Empty takes DefaultMessage.
	Message string
	// Redact chooses the rules applied to every model-authored string on its way
	// into the record. The mode is not taken from here: the writer always masks.
	Redact redact.Options
}

// Writer writes records to a logger.
type Writer struct {
	log      embedlog.Logger
	message  string
	redactor *redact.Redactor
}

// NewWriter builds a writer. The rule set comes from the options; the mode does
// not, because a record is masked whatever the answer path does.
//
// Options that do not compile — an unknown rule name — fall back to the full
// rule set rather than to no masking. A misconfigured masker that masks too
// much is a readable log; one that masks nothing is a leak.
func NewWriter(l embedlog.Logger, opts Options) Writer {
	if opts.Message == "" {
		opts.Message = DefaultMessage
	}
	ro := opts.Redact
	ro.Mode = redact.ModeOn
	r, err := redact.New(ro)
	if err != nil {
		// Only the input that failed is rolled back — the rule names — rather
		// than the whole Options rebuilt field by field. Listing the fields to
		// keep meant the next one added to redact.Options would be dropped here
		// silently, on the path taken precisely when something is already wrong.
		ro.Rules = nil
		r, _ = redact.New(ro)
	}
	return Writer{log: l, message: opts.Message, redactor: r}
}

// Write emits one record.
//
// The core keys are fixed and each one names its field: `query` for Query, not
// `sql`, because the text in it is a path as often as it is a statement, and a
// server that proxies HTTP would be logging its URLs under a key that says SQL.
// Fixed means callers may write log queries against them and expect them to
// keep working; it does not mean they were inherited.
//
// Extra follows the core keys, so a service's own fields cannot displace one.
func (w Writer) Write(ctx context.Context, r Record) {
	hash := r.QueryHash
	if hash == "" {
		hash = Hash(r.Query)
	}
	// A literal, not a make with a capacity: the capacity was a hand-counted 46
	// that had to be kept in step with the pairs below, and it would have drifted
	// the first time somebody added a key. One slice growth when Extra is
	// non-empty is a cheaper thing to pay than a number nobody can verify.
	args := []any{ //nolint:prealloc // the literal sizes itself; see above
		EventKey, EventValue,
		"trace_id", r.TraceID,
		"sub", r.Subject,
		"email", r.Email,
		"groups", strings.Join(r.Groups, ","),
		"roles", strings.Join(r.Roles, ","),
		// Sanitised, not trusted. The dispatcher hands the hook whatever name
		// the caller typed when the tool was not found — that is the point of
		// recording refusals — so this field carries client input, and an
		// unescaped newline in it writes a second log line of the caller's
		// choosing.
		"tool", SanitizeText(r.Tool, MaxNameLen),
		"source", r.Source,
		"env", r.Env,
		// Masked, not merely sanitised. Intent is model-authored, and the rule at
		// the top of this file has no exceptions: a deployment may show a user
		// full values, but the log is read by everyone who can read logs.
		// Sanitising alone escaped the control characters and wrote the card
		// number through.
		"intent", w.text(r.Intent, MaxIntentLen),
		"query", w.Text(r.Query),
		"query_sha256", hash,
		"uri", w.Text(r.URI),
		"decision", r.Decision,
		"deny_reason", SanitizeText(r.DenyReason, MaxNameLen),
		"rows", r.Rows,
		"rows_out", r.RowsOut,
		"bytes_out", r.BytesOut,
		"truncated", r.Truncated,
		"masked", strings.Join(r.Masked, ","),
		"batch_size", r.BatchSize,
		"batch_index", r.BatchIndex,
		"duration_ms", r.Duration.Milliseconds(),
	}
	// Extra is where a service puts its own fields, and the doc above names
	// headers and upstream URLs among them — values derived from what the model
	// asked for. The rule at the top of this file says model-authored strings
	// are masked always; an escape hatch that skipped it would be the one place
	// the rule does not hold, and the place the field list grows.
	args = append(args, w.extra(r.Extra)...)
	w.log.Print(ctx, w.message, args...)
}

// extra puts the service's own fields through the same rule as the core ones.
//
// Keys are left alone — a service writes those itself and they are not derived
// from a request. Values are not: the doc on Record.Extra names headers and
// upstream URLs, which are exactly the strings the rule at the top of this file
// is about. A string value is masked and flattened; anything else goes through
// the redactor's value walk, which reaches the strings inside a map or a struct
// and leaves numbers alone.
func (w Writer) extra(kv []any) []any {
	if len(kv) == 0 {
		return nil
	}
	out := make([]any, len(kv))
	for i, v := range kv {
		switch {
		case i%2 == 0: // a key
			out[i] = v
		case v == nil:
			out[i] = v
		default:
			out[i] = w.value(v)
		}
	}
	return out
}

// value masks one Extra value. Strings take the same path as Query and URI;
// everything else is walked, so a map of headers is masked inside rather than
// logged whole.
func (w Writer) value(v any) any {
	if s, ok := v.(string); ok {
		return w.Text(s)
	}
	masked, _ := w.redactor.Value(v)
	return masked
}

// Text is the one rule for a model-authored string on its way into a log:
// masked, flattened to one line, capped at MaxTextLen. Exported for the error
// lines a tool writes beside its record, which quote the same strings.
func (w Writer) Text(s string) string { return w.text(s, MaxTextLen) }

// text is Text with the cap spelt out, because intent is capped shorter than a
// query and still has to be masked the same way.
func (w Writer) text(s string, maxRunes int) string {
	if s == "" {
		return ""
	}
	// Cap first, with slack, then mask: the string may be megabytes, and running
	// every pattern over all of it to keep two kilobytes is pure waste. The
	// slack is what keeps masking-before-the-final-cut meaningful — a match
	// straddling the cap is still whole inside the slack, so the cut cannot
	// split one and leak half.
	if cut, ok := mcp.CutRunes(s, maxRunes+CapSlack); ok {
		s = cut + "…"
	}
	masked, _ := w.redactor.Text(s)
	return SanitizeText(masked, maxRunes)
}

// SanitizeText makes a model-authored string safe to put in a log humans read.
// Control characters and ANSI escapes are dropped, line breaks and tabs become
// spaces, and the length is capped at maxRunes.
//
// Without it a crafted intent forges log lines: the injection gets to write into
// the record that is supposed to describe it.
func SanitizeText(s string, maxRunes int) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	skipEscape, escaped := false, 0
	for _, r := range s {
		switch {
		case skipEscape:
			// An ANSI sequence ends at a letter; everything up to it goes. The
			// window is bounded because a lone ESC is not a sequence: without
			// the bound, one stray byte swallowed the rest of the record, and
			// the crafted string got to delete the line describing it.
			escaped++
			if unicode.IsLetter(r) || escaped >= MaxEscapeLen {
				skipEscape = false
			}
		case r == 0x1b:
			skipEscape, escaped = true, 0
		case r == '\n', r == '\r', r == '\t':
			b.WriteRune(' ')
		case unicode.IsControl(r):
			// dropped
		default:
			b.WriteRune(r)
		}
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	// Counted, not converted. []rune(out) allocated four bytes per character —
	// nine kilobytes for a two-kilobyte query — for the sole purpose of learning
	// how many characters there were, and this runs three times per record.
	// Walking to the cap costs one slice of the string we already have.
	if utf8.RuneCountInString(out) > maxRunes {
		cut, n := len(out), 0
		for i := range out { // ranging a string yields byte offsets of runes
			if n == maxRunes {
				cut = i
				break
			}
			n++
		}
		out = out[:cut]
	}
	return out
}

// Hash is the first HashLen hex digits of the SHA-256 of the full text, empty
// for an empty one. It is computed over what the model sent, not over the
// masked or capped record, so two records of the same query agree even when
// neither holds all of it.
func Hash(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:HashLen]
}
