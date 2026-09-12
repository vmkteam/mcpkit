// Package redact masks personal data on its way out of an MCP server — into
// the answer the model reads and into the audit log.
//
// The rules were tuned against real payloads in two services and are the union
// of what both arrived at. What a rule finds is replaced by a marker naming the
// rule, so a reader of the answer can tell a masked value from a missing one.
//
// Three modes. Off leaves everything alone, which is the right default for a
// source that returns metrics and configuration, where a mask only produces
// false positives. Warn counts what would be masked without touching anything,
// which is how a rule set gets chosen — on data, not in an argument. Mask
// replaces.
package redact

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Modes a deployment can run in.
const (
	ModeOff  = "off"
	ModeWarn = "warn"
	ModeOn   = "mask"
)

// Rule names. Exported so a config, a dashboard and a cheat sheet all spell
// them the same way.
const (
	RuleEmail = "email"
	RulePhone = "phone"
	RuleCard  = "card"
	RuleToken = "token"
	RuleJWT   = "jwt"
	RulePEM   = "pem"
	RuleIP    = "ip"
)

// Marker is what replaces a match. The model reads it and cheat sheets name it,
// so it is fixed rather than configured: two servers must not say the same
// thing in different words.
func Marker(rule string) string { return "[masked:" + rule + "]" }

// ParseMode normalises a config value, reporting whether it is one this package
// understands.
//
// It accepts "redact" as a synonym of ModeOn: that is what some catalogues say
// today, and they live outside the repository — a config that quietly stops
// meaning what it meant is a worse outcome than a second spelling. Anything
// else is rejected, so a typo fails validation instead of silently switching
// the mask off.
func ParseMode(s string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", ModeOff:
		return ModeOff, true
	case ModeWarn:
		return ModeWarn, true
	case ModeOn, "redact":
		return ModeOn, true
	}
	return "", false
}

// Options configures a Redactor.
type Options struct {
	Mode string
	// Rules limits the active set by name; empty means every rule. A source
	// that returns metrics or configuration gets false positives from rules it
	// has no data for.
	Rules []string
	// MaskEmailDomain replaces the whole address instead of keeping the domain.
	// The default — the zero value — masks the local part only ("s***@acme.com"):
	// the domain says whose customer a row is about and groups rows by employer,
	// and hiding it protects nothing the mask does not already protect.
	MaskEmailDomain bool
}

// Result reports what matched, per rule, so a log line can say which rule fired
// without carrying what it fired on.
type Result struct {
	Hits map[string]int
}

// Total is the number of matches across all rules.
func (r Result) Total() int {
	n := 0
	for _, v := range r.Hits {
		n += v
	}
	return n
}

// Names lists the rules that matched, in rule order.
func (r Result) Names() []string {
	out := make([]string, 0, len(r.Hits))
	for _, rl := range rules {
		if r.Hits[rl.name] > 0 {
			out = append(out, rl.name)
		}
	}
	return out
}

// RuleNames lists every rule this package knows, for config validation and for
// documentation.
func RuleNames() []string {
	out := make([]string, 0, len(rules))
	for _, rl := range rules {
		out = append(out, rl.name)
	}
	return out
}

// Redactor holds a compiled rule set. Build one per profile when a catalogue
// loads, or one per instance at boot: choosing the rules is the same work on
// every call, and every call is on a hot path.
type Redactor struct {
	mode   string
	active []rule
	opts   Options
}

// New validates the options and compiles the rule set. An unknown mode or an
// unknown rule name is an error here rather than a mask that silently does
// nothing.
func New(opts Options) (*Redactor, error) {
	mode, ok := ParseMode(opts.Mode)
	if !ok {
		return nil, fmt.Errorf("redact: unknown mode %q, want one of off, warn, mask", opts.Mode)
	}
	active, err := selectRules(opts.Rules)
	if err != nil {
		return nil, err
	}
	return &Redactor{mode: mode, active: active, opts: opts}, nil
}

// Mode is the normalised mode this redactor runs in.
func (r *Redactor) Mode() string { return r.mode }

// Text masks one string. It is what a body that is not JSON — an HTML error
// page, plain text — and an upstream's error message go through: they reach the
// model just as a document does, and personal data in them is no less personal
// for the missing braces.
func (r *Redactor) Text(s string) (string, Result) {
	var res Result
	if r.off() || s == "" {
		return s, res
	}
	return r.maskString(s, &res), res
}

// Value returns v with every string reachable inside it masked.
//
// Numbers and map keys are left alone: personal data does not hide in a number,
// and rewriting numbers breaks the arithmetic the answer was asked for.
func (r *Redactor) Value(v any) (any, Result) {
	var res Result
	if r.off() {
		return v, res
	}
	return r.maskAny(v, &res, 0), res
}

// Rows masks the string values of a query result in place and returns only the
// count: this runs over thousands of cells, where a copy costs more than the
// convenience is worth.
func (r *Redactor) Rows(rows [][]any) Result {
	var res Result
	if r.off() {
		return res
	}
	for _, row := range rows {
		for i, v := range row {
			row[i] = r.maskAny(v, &res, 0)
		}
	}
	return res
}

func (r *Redactor) off() bool { return r == nil || r.mode == ModeOff || len(r.active) == 0 }

// Text masks one string with one-off options. It builds a Redactor per call —
// for a startup check or a test, not for a hot path.
func Text(s string, opts Options) (string, Result) {
	r, err := New(opts)
	if err != nil {
		return s, Result{Hits: map[string]int{}}
	}
	return r.Text(s)
}

// Value masks one value with one-off options, with the same caveat as Text.
func Value(v any, opts Options) (any, Result) {
	r, err := New(opts)
	if err != nil {
		return v, Result{Hits: map[string]int{}}
	}
	return r.Value(v)
}

func selectRules(names []string) ([]rule, error) {
	if len(names) == 0 {
		return rules, nil
	}
	known := map[string]bool{}
	for _, rl := range rules {
		known[rl.name] = true
	}
	want := map[string]bool{}
	for _, n := range names {
		name := strings.ToLower(strings.TrimSpace(n))
		if !known[name] {
			return nil, fmt.Errorf("redact: unknown rule %q, want one of %s", n, strings.Join(RuleNames(), ", "))
		}
		want[name] = true
	}
	out := make([]rule, 0, len(rules))
	for _, rl := range rules {
		if want[rl.name] {
			out = append(out, rl)
		}
	}
	return out, nil
}

// maskString applies every active rule to s, in rule order.
func (r *Redactor) maskString(s string, res *Result) string {
	// Counted once for the whole string rather than scanned once per numeric
	// rule: three rules asked "is there a digit" and got three identical passes
	// over the same bytes.
	digits := countDigits(s)
	for _, rl := range r.active {
		if !rl.mayMatch(s, digits) {
			continue
		}
		var b strings.Builder
		last, hits := 0, 0
		for _, loc := range rl.re.FindAllStringSubmatchIndex(s, -1) {
			// A rule may mask part of its match: the token rule keeps the name
			// of the parameter and replaces only the value, the same thought as
			// keeping the domain of an address — the context stays, the secret
			// goes.
			start, end := loc[0], loc[1]
			if rl.group > 0 {
				start, end = loc[2*rl.group], loc[2*rl.group+1]
				if start < 0 {
					continue
				}
			}
			if rl.accept != nil && !rl.accept(s, loc[0], loc[1]) {
				continue
			}
			hits++
			if r.mode != ModeOn {
				continue
			}
			b.WriteString(s[last:start])
			if rl.mask != nil {
				b.WriteString(rl.mask(s[start:end], r.opts))
			} else {
				b.WriteString(rl.marker)
			}
			last = end
		}
		if hits == 0 {
			continue
		}
		if res.Hits == nil {
			// Built on the first hit, not on every call. Total and Names read a
			// nil map safely, and the overwhelming majority of cells never
			// match anything.
			res.Hits = map[string]int{}
		}
		res.Hits[rl.name] += hits
		if r.mode == ModeOn {
			b.WriteString(s[last:])
			s = b.String()
		}
	}
	return s
}

// maskEmail keeps the first character and, unless the options say otherwise,
// the whole domain: "s***@acme.com". Enough to tell two rows apart at a glance
// and to group by employer, not enough to write to anyone.
func maskEmail(match string, opts Options) string {
	if opts.MaskEmailDomain {
		return Marker(RuleEmail)
	}
	local, domain, ok := strings.Cut(match, "@")
	if !ok || local == "" {
		return Marker(RuleEmail)
	}
	first, _ := utf8.DecodeRuneInString(local)
	return string(first) + "***@" + domain
}

// mustCompile is regexp.MustCompile under another name, so that the rule table
// below reads as a table.
func mustCompile(expr string) *regexp.Regexp { return regexp.MustCompile(expr) }
