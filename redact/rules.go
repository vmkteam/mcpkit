package redact

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// rule is one named pattern plus the three hooks that make it usable on real
// data: accept vets a match against its surroundings (a timestamp is not a card
// number, a version is not an address), group narrows the replacement to a
// submatch, mask decides what replaces it.
type rule struct {
	name   string
	re     *regexp.Regexp
	accept func(s string, start, end int) bool
	// group is the submatch to replace; 0 replaces the whole match.
	group int
	// mask builds the replacement; nil means Marker(name).
	mask func(match string, opts Options) string
	// prefilter is a cheap substring test: when it fails, the pattern cannot
	// match and is not run. See mayMatch.
	prefilter func(s string) bool
	// minDigits is the same idea for the numeric rules, which have no character
	// they can be scanned for. A match cannot hold more digits than the string
	// it came from, so a string with fewer than this many cannot contain one.
	minDigits int
	// marker is the replacement, built once at init rather than concatenated
	// per match.
	marker string
}

// mayMatch reports whether the pattern could match at all. Seven rules over
// every cell of a thousand-row answer is half a million regexp runs on the path
// that holds a database connection open; a byte scan for the one character a
// rule cannot match without is several times cheaper, and for a typical cell
// ("completed", a date, a city name) no rule gets past this line.
//
// A prefilter that rejected something the pattern would have found would be a
// silent leak, which is why FuzzPrefilterFindsWhatTheRegexpFinds exists.
func (r rule) mayMatch(s string, digits int) bool {
	if r.minDigits > 0 && digits < r.minDigits {
		return false
	}
	return r.prefilter == nil || r.prefilter(s)
}

// containsAnyFold reports whether s contains any of subs, case-insensitively.
// Every sub must be lower-case ASCII — they are the literal words of the token
// rule, and nothing else is passed here.
//
// It folds in place rather than through strings.ToLower, which returns its
// argument untouched only for pure ASCII: one capital Cyrillic letter sends it
// down strings.Map and allocates a copy of the whole cell. On a table of
// Russian text that fired on every cell — the prefilter allocated on all ten
// thousand of them and then rejected all ten thousand, which is the opposite of
// what a prefilter is for.
//
// The fold is exact for this input. Only 'A'-'Z' and 'a'-'z' map into 'a'-'z'
// under |0x20; a byte of 0x80 or above stays above it, so no part of a UTF-8
// sequence can be mistaken for a letter.
func containsAnyFold(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) == 0 || len(s) < len(sub) {
			continue
		}
		for i := 0; i+len(sub) <= len(s); i++ {
			j := 0
			for ; j < len(sub); j++ {
				if s[i+j]|0x20 != sub[j] {
					break
				}
			}
			if j == len(sub) {
				return true
			}
		}
	}
	return false
}

// countDigits is how the numeric rules are gated. It replaces three separate
// "is there a digit anywhere" scans — one per rule — with one count, and the
// count gates far harder than the boolean did: a card needs thirteen digits and
// a phone nine, so a cell holding one order number never reaches either regexp.
//
// It is sound to gate on the whole string: a match is a substring, and a
// substring cannot hold more digits than the string it came from. The floors
// here are the ones acceptCard and acceptPhone already enforce after the fact.
func countDigits(s string) int {
	n := 0
	for i := range len(s) {
		if s[i] >= '0' && s[i] <= '9' {
			n++
		}
	}
	return n
}

// Rules are applied in order, and the more specific pattern has to win: a JWT
// half-eaten by the token rule is unreadable for both a human and a filter.
//
// Each marker is built here rather than per masked match: Marker concatenates,
// and there are seven fixed names.
var rules = []rule{
	{
		name:      RuleJWT,
		marker:    Marker(RuleJWT),
		re:        mustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]+`),
		prefilter: func(s string) bool { return strings.Contains(s, "eyJ") },
	},
	{
		name:      RulePEM,
		marker:    Marker(RulePEM),
		re:        mustCompile(`(?s)-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----`),
		prefilter: func(s string) bool { return strings.Contains(s, "-----BEGIN ") },
	},
	{
		name:      RuleEmail,
		marker:    Marker(RuleEmail),
		re:        mustCompile(`\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b`),
		mask:      maskEmail,
		prefilter: func(s string) bool { return strings.Contains(s, "@") },
	},
	// Bearer and api keys as they appear in headers, query strings and stack
	// frames — not bare hex: a bare 32-hex string is as likely to be a commit or
	// a request id. The key may carry a prefix (private_token, access_token),
	// and \b alone never sees it because _ is a word character.
	//
	// Group 1 is the name of the parameter and survives; group 2 is the value
	// and is replaced. A refusal then still says which parameter was rejected,
	// and a JSON-shaped body stays parseable instead of losing its key.
	{
		name:      RuleToken,
		marker:    Marker(RuleToken),
		re:        mustCompile(`(?i)\b((?:bearer|(?:[a-z]+[_-])?token|api[_-]?key|secret|password)["'\s:=]+)([A-Za-z0-9._\-]{12,})`),
		group:     2,
		prefilter: func(s string) bool { return containsAnyFold(s, "bearer", "token", "key", "secret", "password") },
	},
	{
		name:      RuleCard,
		marker:    Marker(RuleCard),
		re:        mustCompile(`\b(?:\d[ -]?){13,19}\b`),
		accept:    acceptCard,
		minDigits: 13, // acceptCard rejects anything shorter
	},
	// Two shapes: an international number in any punctuation, and the Russian
	// 8-prefixed form that carries no plus. An RU-only rule masks nothing for a
	// customer in the US or the UAE while the documentation promises otherwise.
	{
		name:      RulePhone,
		marker:    Marker(RulePhone),
		re:        mustCompile(`\+\d[\d\s().\-]{7,17}\d|\b8[\s\-(]?\d{3}[\s\-)]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}\b`),
		accept:    acceptPhone,
		minDigits: 9, // acceptPhone rejects anything shorter
	},
	{
		name:      RuleIP,
		marker:    Marker(RuleIP),
		re:        mustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
		accept:    acceptIP,
		minDigits: 4, // four octets, one digit each at least
	},
}

// acceptCard keeps a digit run only when it is plausibly a card number: it
// passes the Luhn check every issuer applies and it is not the shape of a unix
// timestamp. Real data is full of both — milliseconds since the epoch, order
// ids — and a rule that ate them made answers unreadable for exactly the
// questions that asked for them.
func acceptCard(s string, start, end int) bool {
	match := s[start:end]
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, match)
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	if len(digits) == len(match) && looksLikeEpoch(digits) {
		return false
	}
	return luhn(digits)
}

// looksLikeEpoch recognises a bare number in the range unix time occupies this
// century: seconds, milliseconds, microseconds and nanoseconds since 1970 all
// start with a 1 at their respective lengths.
func looksLikeEpoch(digits string) bool {
	switch len(digits) {
	case 10, 13, 16, 19:
		return digits[0] == '1'
	default:
		return false
	}
}

// luhn is the checksum a card number satisfies. One run in ten passes it by
// chance, which cuts false positives tenfold rather than to zero — the epoch
// check above handles the class that matters most.
func luhn(digits string) bool {
	sum, double := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// acceptPhone keeps a run only when it has as many digits as a real number:
// E.164 allows fifteen at most, and no country plan is shorter than eight.
// Without the count, "+1 234.56" and a padded id would both read as numbers.
func acceptPhone(s string, start, end int) bool {
	digits := 0
	for _, r := range s[start:end] {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	return digits >= 9 && digits <= 15
}

// acceptIP keeps four dotted numbers only when they are an address: each octet
// at most 255, not part of a longer dotted run such as a version or an OID, and
// not glued to a letter — "v10.0.0.1" is a release, not a host.
func acceptIP(s string, start, end int) bool {
	for oct := range strings.SplitSeq(s[start:end], ".") {
		if n, err := strconv.Atoi(oct); err != nil || n > 255 {
			return false
		}
	}
	if start > 0 {
		prev, _ := utf8.DecodeLastRuneInString(s[:start])
		if prev == '.' || unicode.IsLetter(prev) {
			return false
		}
	}
	if end+1 < len(s) && s[end] == '.' && s[end+1] >= '0' && s[end+1] <= '9' {
		return false
	}
	return true
}
