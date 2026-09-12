package mcp

// The protocol revisions this library speaks, and the rule for picking one.
//
// They live here rather than with the server because which revisions a server
// speaks is a fact about the protocol and not about HTTP. mcpkit reads this
// list twice — to mirror the answer back in the Mcp-Protocol-Version header and
// to answer initialize — and owns it neither time. A second transport would
// find the list where this one did, in the package that describes the protocol,
// rather than importing the HTTP server to learn what it speaks.

// ProtocolVersion is the revision this server speaks by default.
const ProtocolVersion = "2026-07-28"

// VersionMetaEra is the revision that removed the initialize handshake and
// moved the protocol version, the client's identity and its capabilities into
// the _meta of every request. A request naming it or anything newer belongs to
// that era; anything older is served the old way.
//
// It is its own constant rather than an alias of ProtocolVersion, though today
// they hold the same string. One is a fact about the protocol and the other a
// fact about this build: adding a newer revision to SupportedVersions moves
// ProtocolVersion, and 2026-07-28 would quietly have stopped being modern —
// sending a client of the current era down the legacy path to be refused for
// metadata its own revision never defined.
const VersionMetaEra = "2026-07-28"

// Revisions older clients still ask for. All of them are served by the same
// stateless code path; the difference that mattered — sessions — is unused.
const (
	Version20251125 = "2025-11-25"
	Version20250618 = "2025-06-18"
)

// SupportedVersions are the revisions this server answers on, newest first.
// It is a process-wide list: a service must not mutate it.
//
// 2025-03-26 is not among them any more. A client of that revision may send a
// JSON-RPC batch — its transport page lists an array as one of the shapes the
// POST body may take — and this server refuses one. The refusal is deliberate
// and stays: zenrpc would run the members of a batch in parallel while a rate
// limiter in front counted a single POST, which is ten calls for the price of
// one on the limit that exists to stop exactly that. What changes here is only
// that we no longer invite a client whose requests we would turn away.
var SupportedVersions = []string{ProtocolVersion, Version20251125, Version20250618}

// Era names which side of the VersionMetaEra boundary a revision falls on: the
// per-request-metadata era, or the handshake one before it.
//
// It is here rather than with the client that picks one because the boundary is
// here. A caller that says "the older era" and then has to name the newest
// revision of it is keeping a second copy of this file's contents — and that
// copy is what goes stale when a revision is added.
type Era string

const (
	// EraModern is VersionMetaEra and later: no handshake, per-request _meta,
	// headers mirroring it.
	EraModern Era = "modern"
	// EraLegacy is everything before it: initialize, then plain requests.
	EraLegacy Era = "legacy"
)

// NewestRevision returns the newest revision this build speaks in era e.
//
// It is computed from SupportedVersions rather than written down, so that
// adding a revision moves it. Naming Version20251125 as "the newest legacy one"
// was true when it was written and stops being true the moment a revision is
// added between it and the boundary.
func NewestRevision(e Era) string {
	if e == EraModern {
		return ProtocolVersion
	}
	// Newest-first, so the first revision below the boundary is the newest of
	// the older era.
	for _, v := range SupportedVersions {
		if v < VersionMetaEra {
			return v
		}
	}
	return SupportedVersions[len(SupportedVersions)-1]
}

// IsRevision reports whether s has the shape of a protocol revision: an ISO
// date, YYYY-MM-DD. Only the shape — a client naming a revision from the future
// is naming one whether or not that date exists in a calendar.
//
// It lives here, beside the list and the ordering rule, because it answers the
// same question they do: what counts as a revision. Two callers ask — the
// transport deciding which era a request belongs to, and NegotiateVersion —
// and when only one of them knew the answer, the other one was wrong.
func IsRevision(s string) bool {
	const layout = "0000-00-00"
	if len(s) != len(layout) {
		return false
	}
	for i := range len(s) {
		if layout[i] == '-' {
			if s[i] != '-' {
				return false
			}
			continue
		}
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// NegotiateVersion echoes the client's revision when we speak it, and otherwise
// answers with the newest revision we speak that is not newer than the one
// asked for.
//
// Answering with our newest is what the spec allows and what breaks clients in
// practice: a client that asks for a revision between two of ours and gets one
// above it reports "Server's protocol version is not supported" and
// disconnects. A revision older than the client's is the one it is required to
// understand, so going down always works and going up is a coin toss.
//
// Revisions are ISO dates, so string order is chronological order — but only
// for a revision. Anything else the client may have sent is not ordered against
// them at all: "draft", "latest", "v2" and "9" all sort above every date, so a
// plain comparison answered each of them with our newest, which is precisely
// the outcome described above. They go where the empty string already went.
func NegotiateVersion(requested string) string {
	if IsRevision(requested) {
		// SupportedVersions is newest-first and revisions are ISO dates, so the
		// first one that is not newer than the request is the answer.
		for _, v := range SupportedVersions {
			if v <= requested {
				return v
			}
		}
	}
	// The client asked for something older than anything we speak, for nothing
	// at all, or for something that is not a revision: our oldest is the closest
	// we can offer, and the one it is likeliest to understand.
	return SupportedVersions[len(SupportedVersions)-1]
}
