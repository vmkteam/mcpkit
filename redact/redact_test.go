package redact

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newRedactor(t *testing.T, opts Options) *Redactor {
	t.Helper()
	if opts.Mode == "" {
		opts.Mode = ModeOn
	}
	r, err := New(opts)
	require.NoError(t, err)
	return r
}

func TestParseMode(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		want string
		ok   bool
	}{
		"mask":   {ModeOn, true},
		"redact": {ModeOn, true}, // the second spelling some catalogues still use
		"MASK":   {ModeOn, true},
		"warn":   {ModeWarn, true},
		"off":    {ModeOff, true},
		"":       {ModeOff, true},
		"masc":   {"", false}, // a typo must fail validation, not disable the mask
		"on":     {"", false},
	}
	for in, want := range cases {
		t.Run("in="+in, func(t *testing.T) {
			t.Parallel()
			got, ok := ParseMode(in)
			assert.Equal(t, want.ok, ok)
			assert.Equal(t, want.want, got)
		})
	}

	// A config value arrives with whatever surrounds it in the file.
	t.Run("surrounding whitespace", func(t *testing.T) {
		t.Parallel()
		got, ok := ParseMode("  warn\t")
		assert.True(t, ok)
		assert.Equal(t, ModeWarn, got)
	})
}

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("an unknown rule is an error, not a silent no-op", func(t *testing.T) {
		t.Parallel()
		_, err := New(Options{Mode: ModeOn, Rules: []string{"email", "e-mail"}})
		require.ErrorContains(t, err, `unknown rule "e-mail"`)
		assert.ErrorContains(t, err, "email", "the message lists what is allowed")
	})

	t.Run("an unknown mode is an error", func(t *testing.T) {
		t.Parallel()
		_, err := New(Options{Mode: "masc"})
		require.ErrorContains(t, err, "unknown mode")
	})

	t.Run("no rules named means every rule", func(t *testing.T) {
		t.Parallel()
		r := newRedactor(t, Options{})
		assert.Len(t, r.active, len(RuleNames()))
	})
}

func TestMarkerIsFixed(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "[masked:email]", Marker(RuleEmail))
	assert.Equal(t, "[masked:jwt]", Marker(RuleJWT))
}

func TestRuleNames(t *testing.T) {
	t.Parallel()
	assert.Equal(t,
		[]string{RuleJWT, RulePEM, RuleEmail, RuleToken, RuleCard, RulePhone, RuleIP},
		RuleNames(), "order is the order rules are applied, and it is load-bearing")
}

func TestEmail(t *testing.T) {
	t.Parallel()

	// The domain says whose customer a row is about and groups rows by employer;
	// hiding it protects nothing the mask does not already protect.
	t.Run("the domain survives by default", func(t *testing.T) {
		t.Parallel()
		got, res := newRedactor(t, Options{}).Text("write to sergey@acme.com now")
		assert.Equal(t, "write to s***@acme.com now", got)
		assert.Equal(t, 1, res.Hits[RuleEmail])
	})

	t.Run("MaskEmailDomain hides it", func(t *testing.T) {
		t.Parallel()
		got, _ := newRedactor(t, Options{MaskEmailDomain: true}).Text("write to sergey@acme.com now")
		assert.Equal(t, "write to "+Marker(RuleEmail)+" now", got)
	})

	t.Run("several addresses in one string", func(t *testing.T) {
		t.Parallel()
		got, res := newRedactor(t, Options{}).Text("a@x.com, b@y.org")
		assert.Equal(t, "a***@x.com, b***@y.org", got)
		assert.Equal(t, 2, res.Hits[RuleEmail])
	})
}

// The name of the parameter is context, not a secret: a refusal has to say
// which parameter was rejected, and a JSON-shaped body has to stay parseable.
func TestToken(t *testing.T) {
	t.Parallel()
	r := newRedactor(t, Options{})
	cases := map[string]string{
		"?private_token=glpat-abcdefghijkl":   "?private_token=" + Marker(RuleToken),
		"Authorization: Bearer abcdefghijklm": "Authorization: Bearer " + Marker(RuleToken),
		`{"apiKey":"abcdefghijklmn"}`:         `{"apiKey":"` + Marker(RuleToken) + `"}`,
		"password: abcdefghijklmn":            "password: " + Marker(RuleToken),
		"api_key=abcdefghijklmn":              "api_key=" + Marker(RuleToken),
		"secret = abcdefghijklmn":             "secret = " + Marker(RuleToken),
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			t.Parallel()
			got, res := r.Text(in)
			assert.Equal(t, want, got)
			assert.Equal(t, 1, res.Hits[RuleToken])
		})
	}

	t.Run("a short value is not a token", func(t *testing.T) {
		t.Parallel()
		got, res := r.Text("token=short")
		assert.Equal(t, "token=short", got)
		assert.Zero(t, res.Total())
	})
}

// The JWT rule runs before the token rule, so it takes the match whole; the
// result must not be matched again by the token rule.
func TestJWTWinsOverToken(t *testing.T) {
	t.Parallel()
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	got, res := newRedactor(t, Options{}).Text("Bearer " + jwt)

	assert.Equal(t, "Bearer "+Marker(RuleJWT), got)
	assert.Equal(t, 1, res.Hits[RuleJWT])
	assert.Zero(t, res.Hits[RuleToken], "the marker must not match the token rule a second time")
}

func TestPEM(t *testing.T) {
	t.Parallel()
	in := "before\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\nafter"
	got, res := newRedactor(t, Options{}).Text(in)
	assert.Equal(t, "before\n"+Marker(RulePEM)+"\nafter", got)
	assert.Equal(t, 1, res.Hits[RulePEM])
}

func TestCard(t *testing.T) {
	t.Parallel()
	r := newRedactor(t, Options{})

	t.Run("a real PAN is masked", func(t *testing.T) {
		t.Parallel()
		got, res := r.Text("pay with 4242 4242 4242 4242 today")
		// The pattern allows a separator after each digit, so the match takes
		// the trailing space with it. Both donors behave this way, and the
		// alternative — a card number split by a narrower pattern — is worse.
		assert.Equal(t, "pay with "+Marker(RuleCard)+"today", got)
		assert.Equal(t, 1, res.Hits[RuleCard])
	})

	// Real data is full of both, and a rule that ate them made answers
	// unreadable for exactly the questions that asked for them.
	t.Run("a millisecond timestamp is not a card", func(t *testing.T) {
		t.Parallel()
		got, res := r.Text("created_at 1757635200000")
		assert.Equal(t, "created_at 1757635200000", got)
		assert.Zero(t, res.Hits[RuleCard])
	})

	t.Run("a number that fails Luhn is not a card", func(t *testing.T) {
		t.Parallel()
		got, res := r.Text("order 4242424242424241")
		assert.Equal(t, "order 4242424242424241", got)
		assert.Zero(t, res.Hits[RuleCard])
	})
}

func TestPhone(t *testing.T) {
	t.Parallel()
	r := newRedactor(t, Options{})

	// An RU-only rule masks nothing for a customer in the US or the UAE.
	t.Run("international", func(t *testing.T) {
		t.Parallel()
		for _, in := range []string{"+1 (415) 555-0132", "+971 50 123 4567", "+7 916 123-45-67"} {
			got, res := r.Text("call " + in)
			assert.Equalf(t, "call "+Marker(RulePhone), got, "input %q", in)
			assert.Equal(t, 1, res.Hits[RulePhone])
		}
	})

	t.Run("the russian 8-prefixed form", func(t *testing.T) {
		t.Parallel()
		got, res := r.Text("call 8 916 123-45-67 now")
		assert.Equal(t, "call "+Marker(RulePhone)+" now", got)
		assert.Equal(t, 1, res.Hits[RulePhone])
	})

	t.Run("too few digits is not a number", func(t *testing.T) {
		t.Parallel()
		got, res := r.Text("version +1 234.56")
		assert.Equal(t, "version +1 234.56", got)
		assert.Zero(t, res.Hits[RulePhone])
	})
}

func TestIP(t *testing.T) {
	t.Parallel()
	r := newRedactor(t, Options{})

	t.Run("an address is masked", func(t *testing.T) {
		t.Parallel()
		got, res := r.Text("from 192.168.1.10 at")
		assert.Equal(t, "from "+Marker(RuleIP)+" at", got)
		assert.Equal(t, 1, res.Hits[RuleIP])
	})

	t.Run("a version glued to a letter is a release, not a host", func(t *testing.T) {
		t.Parallel()
		got, res := r.Text("v10.0.0.1 shipped")
		assert.Equal(t, "v10.0.0.1 shipped", got)
		assert.Zero(t, res.Hits[RuleIP])
	})

	t.Run("an OID is not an address", func(t *testing.T) {
		t.Parallel()
		got, res := r.Text("oid 1.3.6.1.4.1")
		assert.Equal(t, "oid 1.3.6.1.4.1", got)
		assert.Zero(t, res.Hits[RuleIP])
	})

	t.Run("an octet over 255 is not an address", func(t *testing.T) {
		t.Parallel()
		got, res := r.Text("999.1.1.1")
		assert.Equal(t, "999.1.1.1", got)
		assert.Zero(t, res.Hits[RuleIP])
	})
}

// Warn is how a rule set gets chosen — on data, not in an argument.
func TestWarnCountsAndChangesNothing(t *testing.T) {
	t.Parallel()
	in := "sergey@acme.com from 192.168.1.10"
	got, res := newRedactor(t, Options{Mode: ModeWarn}).Text(in)

	assert.Equal(t, in, got, "warn must not touch the body")
	assert.Equal(t, 1, res.Hits[RuleEmail])
	assert.Equal(t, 1, res.Hits[RuleIP])
	assert.Equal(t, 2, res.Total())
	assert.Equal(t, []string{RuleEmail, RuleIP}, res.Names(), "names come back in rule order")
}

func TestOffDoesNothing(t *testing.T) {
	t.Parallel()
	in := "sergey@acme.com"
	got, res := newRedactor(t, Options{Mode: ModeOff}).Text(in)
	assert.Equal(t, in, got)
	assert.Zero(t, res.Total())
	assert.Empty(t, res.Names())
}

// A source that returns metrics or configuration gets false positives from
// rules it has no data for.
func TestRulesLimitTheActiveSet(t *testing.T) {
	t.Parallel()
	r := newRedactor(t, Options{Rules: []string{RuleEmail}})
	got, res := r.Text("sergey@acme.com from 192.168.1.10")

	assert.Equal(t, "s***@acme.com from 192.168.1.10", got)
	assert.Equal(t, []string{RuleEmail}, res.Names())
}

func TestPackageLevelWrappers(t *testing.T) {
	t.Parallel()

	got, res := Text("sergey@acme.com", Options{Mode: ModeOn})
	assert.Equal(t, "s***@acme.com", got)
	assert.Equal(t, 1, res.Total())

	v, res := Value(map[string]any{"email": "sergey@acme.com"}, Options{Mode: ModeOn})
	assert.Equal(t, map[string]any{"email": "s***@acme.com"}, v)
	assert.Equal(t, 1, res.Total())

	t.Run("bad options mask nothing rather than panic", func(t *testing.T) {
		t.Parallel()
		got, res := Text("sergey@acme.com", Options{Mode: "masc"})
		assert.Equal(t, "sergey@acme.com", got)
		assert.Zero(t, res.Total())
	})
}

func TestNilRedactorIsOff(t *testing.T) {
	t.Parallel()
	var r *Redactor
	got, res := r.Text("sergey@acme.com")
	assert.Equal(t, "sergey@acme.com", got)
	assert.Zero(t, res.Total())
}

func TestEmptyStringIsUntouched(t *testing.T) {
	t.Parallel()
	got, res := newRedactor(t, Options{}).Text("")
	assert.Empty(t, got)
	assert.Zero(t, res.Total())
}

func TestModeIsNormalised(t *testing.T) {
	t.Parallel()
	synonym, err := New(Options{Mode: "redact"})
	require.NoError(t, err)
	assert.Equal(t, ModeOn, synonym.Mode())

	unset, err := New(Options{})
	require.NoError(t, err)
	assert.Equal(t, ModeOff, unset.Mode(), "an unset mode is off, not on")
}

// Seven rules over a big answer is the cost this prefilter exists to avoid; a
// prefilter that rejected something the pattern would have found would be a
// silent leak.
func FuzzPrefilterFindsWhatTheRegexpFinds(f *testing.F) {
	seeds := []string{
		"", "plain text", "sergey@acme.com", "Bearer abcdefghijklm",
		"4242 4242 4242 4242", "+1 (415) 555-0132", "192.168.1.10",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc",
		"-----BEGIN KEY-----x-----END KEY-----",
		"TOKEN=ABCDEFGHIJKLM", "8 916 123-45-67", "1757635200000",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		digits := countDigits(s)
		for _, rl := range rules {
			if rl.mayMatch(s, digits) {
				continue
			}
			// The invariant is about what the rule would have *masked*, not
			// about what its pattern would have touched. A rule only replaces a
			// match its accept function keeps, so a gate that skips a match
			// accept would have thrown away leaks nothing — and the numeric
			// gates do exactly that: the phone pattern matches "+1       2",
			// which acceptPhone rejects for having two digits.
			for _, loc := range rl.re.FindAllStringIndex(s, -1) {
				if rl.accept == nil || rl.accept(s, loc[0], loc[1]) {
					t.Errorf("rule %q was skipped but would have masked %q in %q",
						rl.name, s[loc[0]:loc[1]], s)
				}
			}
		}
	})
}

// The prefilter has to fold without allocating, and the fold has to be exact.
// strings.ToLower returns its argument untouched only for pure ASCII, so one
// capital Cyrillic letter used to copy the whole cell — on a table of Russian
// text, on every cell, to then reject every cell.
func FuzzContainsAnyFoldMatchesStringsToLower(f *testing.F) {
	for _, s := range []string{
		"", "token", "TOKEN", "ToKeN", "Bearer x", "СЕКРЕТ", "пароль",
		"Ключ", "api_key", "no match here", "\x00\xff", "kEy",
	} {
		f.Add(s)
	}
	needles := []string{"bearer", "token", "key", "secret", "password"}
	f.Fuzz(func(t *testing.T, s string) {
		want := false
		lower := strings.ToLower(s)
		for _, n := range needles {
			if strings.Contains(lower, n) {
				want = true
				break
			}
		}
		assert.Equalf(t, want, containsAnyFold(s, needles...),
			"the in-place fold must agree with strings.ToLower on %q", s)
	})
}

func BenchmarkTextTypicalCell(b *testing.B) {
	r, err := New(Options{Mode: ModeOn})
	require.NoError(b, err)
	for b.Loop() {
		_, _ = r.Text("completed")
	}
}

func BenchmarkTextWithMatches(b *testing.B) {
	r, err := New(Options{Mode: ModeOn})
	require.NoError(b, err)
	s := strings.Repeat("contact sergey@acme.com from 192.168.1.10; ", 8)
	for b.Loop() {
		_, _ = r.Text(s)
	}
}

// BenchmarkTextTypicalCell uses "completed" — pure lower-case ASCII, which is
// the one input shape where strings.ToLower returns without copying. That is
// why it never saw the token prefilter allocate a copy of every cell of a
// Russian table: the benchmark that existed could not.
//
// ReportAllocs is the point of this one. The number to watch is zero.
func BenchmarkTextCyrillicCell(b *testing.B) {
	r, err := New(Options{Mode: ModeOn})
	require.NoError(b, err)
	b.ReportAllocs()
	for b.Loop() {
		_, _ = r.Text("Заказ Выполнен")
	}
}

// A cell holding an order number: three numeric rules used to scan it for a
// digit apiece and then run their patterns, where a digit count now rejects all
// three at once.
func BenchmarkTextNumericCell(b *testing.B) {
	r, err := New(Options{Mode: ModeOn})
	require.NoError(b, err)
	b.ReportAllocs()
	for b.Loop() {
		_, _ = r.Text("order 84213")
	}
}
