package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Answering with our newest revision is allowed by the spec and gets the
// connection dropped in practice: "Server's protocol version is not supported".
// The revision below the client's is the one it must understand, so negotiation
// only ever goes down.
func TestNegotiateVersion(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		ProtocolVersion: ProtocolVersion,
		Version20251125: Version20251125,
		Version20250618: Version20250618,
		"2026-01-01":    Version20251125, // a revision between two of ours
		"2025-08-01":    Version20250618,
		"2030-01-01":    ProtocolVersion, // a future client gets our newest
		"2024-01-01":    Version20250618, // older than anything we speak
		"":              Version20250618, // asked for nothing at all
	}
	for asked, want := range cases {
		t.Run("asked/"+asked, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, want, NegotiateVersion(asked))
		})
	}
}

// The list is read on every handshake and on every response header, so a
// service that sorted it "for tidiness" would change what every client is told.
func TestSupportedVersionsAreNewestFirst(t *testing.T) {
	t.Parallel()
	for i := 1; i < len(SupportedVersions); i++ {
		assert.Greater(t, SupportedVersions[i-1], SupportedVersions[i],
			"SupportedVersions must be newest-first: NegotiateVersion walks it in order")
	}
	assert.Equal(t, ProtocolVersion, SupportedVersions[0])
}

// What the client sent is a string, not a revision. Digits sort below letters,
// so "draft", "latest", "v2" and "9" all compare above every date — and a plain
// ordering answered each of them with our newest, which is the one outcome this
// function's own doc comment exists to prevent.
//
// The tell was already in the table: an empty string went to the oldest
// revision while garbage went to the newest. Same category of input, opposite
// answers.
func TestNegotiateVersionRejectsWhatIsNotARevision(t *testing.T) {
	t.Parallel()
	oldest := SupportedVersions[len(SupportedVersions)-1]

	for _, s := range []string{"draft", "latest", "v2", "9", "zzz", "2026-07", "20260728", "2026-07-2a"} {
		assert.Equalf(t, oldest, NegotiateVersion(s),
			"%q is not a revision and must go where the empty string goes", s)
	}

	// The control: real revisions still negotiate as they did, including a date
	// newer than anything we speak — that client is told our newest on purpose.
	assert.Equal(t, oldest, NegotiateVersion(""))
	assert.Equal(t, ProtocolVersion, NegotiateVersion("2030-01-01"))
	assert.Equal(t, ProtocolVersion, NegotiateVersion(ProtocolVersion))
	assert.Equal(t, Version20251125, NegotiateVersion(Version20251125))
	assert.Equal(t, Version20250618, NegotiateVersion("2025-08-01"))
}

func TestIsRevision(t *testing.T) {
	t.Parallel()
	for _, s := range append([]string{"2026-07-28", "0000-00-00", "9999-99-99"}, SupportedVersions...) {
		assert.Truef(t, IsRevision(s), "%q has the shape of a revision", s)
	}
	for _, s := range []string{"", "draft", "latest", "v2", "9", "2026-07-2", "2026-07-2a", "20260728", "2026/07/28", "2026-07-28 "} {
		assert.Falsef(t, IsRevision(s), "%q does not", s)
	}
}

// The point of computing it: a fixture that wrote down "the newest legacy
// revision" was right until a revision was added, and then silently was not.
func TestNewestRevision(t *testing.T) {
	t.Parallel()
	assert.Equal(t, ProtocolVersion, NewestRevision(EraModern))

	legacy := NewestRevision(EraLegacy)
	assert.Less(t, legacy, VersionMetaEra, "the newest legacy revision is below the boundary")
	assert.Contains(t, SupportedVersions, legacy)
	// Nothing between it and the boundary: it is the newest of its era, not
	// merely one of them.
	for _, v := range SupportedVersions {
		assert.Falsef(t, v > legacy && v < VersionMetaEra,
			"%q is a legacy revision newer than the one reported, %q", v, legacy)
	}
}

// The era boundary and the newest revision we speak are the same string today
// and mean different things. If a newer revision is ever added, this test is
// what says so out loud rather than letting 2026-07-28 quietly stop being
// modern.
func TestVersionMetaEraIsItsOwnFact(t *testing.T) {
	t.Parallel()
	assert.True(t, IsRevision(VersionMetaEra))
	assert.Contains(t, SupportedVersions, VersionMetaEra,
		"the era boundary has to be a revision this server actually answers on")
	assert.LessOrEqual(t, VersionMetaEra, ProtocolVersion,
		"the boundary cannot be newer than the newest revision we speak")
}
