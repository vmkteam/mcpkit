package mcpkit

// Which era a request belongs to, and what a modern one has to carry.
//
// Revision 2026-07-28 removed the initialize handshake: version, identity and
// capabilities travel in the _meta of every request, and the Streamable HTTP
// binding mirrors some of them into headers so that a proxy can route without
// parsing the body. Everything up to 2025-11-25 works the old way.
//
// This server answers both — a dual-era server, which the spec allows: "A
// dual-era server MAY serve both eras concurrently on the same endpoint or
// process." The era is a property of the request, not of the connection, which
// is what makes that cheap: there is no connection state to keep either way.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"slices"

	"github.com/vmkteam/mcpkit/mcp"

	"github.com/valyala/fastjson"
	"github.com/vmkteam/zenrpc/v2"
)

// fault is a refusal decided before dispatch: the JSON-RPC error to answer
// with, plus the label it is counted under. Every refusal here is a 400 —
// see writeFault — so there is no status to carry.
type fault struct {
	code    int
	message string
	data    any
	reason  string
}

// The three shapes a refusal takes, as constructors rather than as six
// five-line literals. The pairing of a code with the label it is counted under
// is the part worth writing once: nothing stopped the seventh case from
// pairing them differently.
func headerMismatch(message string) *fault {
	return &fault{code: mcp.CodeHeaderMismatch, message: message, reason: reasonHeaderMismatch}
}

func missingMeta(key string) *fault {
	return &fault{
		code:    zenrpc.InvalidParams,
		message: "params._meta." + key + " is required",
		reason:  reasonMissingMeta,
	}
}

func unsupportedVersion(requested string) *fault {
	return &fault{
		code:    mcp.CodeUnsupportedProtocolVersion,
		message: "unsupported protocol version",
		data:    map[string]any{"supported": mcp.SupportedVersions, "requested": requested},
		reason:  reasonBadVersion,
	}
}

// isModern reports whether the request speaks the per-request-metadata era.
//
// Either signal is enough. The header alone identifies a client whose body we
// have not read yet; the _meta alone covers a client that omits the header. A
// legacy client announces an older revision in the header, or nothing at all,
// and neither matches.
func isModern(r *http.Request, v *fastjson.Value) bool {
	return isModernRevision(r.Header.Get(mcp.HeaderProtocolVersion)) ||
		metaString(v, mcp.MetaProtocolVersion) != ""
}

// isModernRevision reports whether a revision string names this era.
//
// Revisions are ISO dates and string order is chronological order, so a plain
// >= would do — for a revision. This value is a header, which is to say it is
// whatever the client sent, and "draft", "latest", "v2" and "9" all sort above
// any date. Each of those used to put a legacy client on the modern path, where
// it was refused with -32602 for metadata its own revision never defined. So the
// shape is checked before the ordering is allowed to mean anything.
//
// The boundary is VersionMetaEra and not ProtocolVersion. They are the same
// string today and that is a coincidence: one is a fact about the protocol —
// the revision that introduced per-request metadata — and the other is a fact
// about this build. Adding a newer revision to SupportedVersions would move
// ProtocolVersion, and 2026-07-28 would have stopped being modern.
func isModernRevision(s string) bool {
	return mcp.IsRevision(s) && s >= mcp.VersionMetaEra
}

// validateModern checks what a modern request must carry, in the order that
// tells the caller the most useful thing first: what it asked with, then what
// it asked for.
//
// Notifications are exempt: this revision "defines no client-to-server
// notifications over Streamable HTTP", and the header rules for a notification
// POST are explicitly left undefined.
func validateModern(r *http.Request, v *fastjson.Value) *fault {
	if isNotification(v) {
		return nil
	}

	version := metaString(v, mcp.MetaProtocolVersion)
	if version == "" {
		return missingMeta(mcp.MetaProtocolVersion)
	}
	// The body is the source of truth and the header is its mirror, so the
	// comparison runs in that direction. Trusting the header instead is the
	// hole these headers exist to close: a gateway routes on one value while
	// the server executes another.
	if h := r.Header.Get(mcp.HeaderProtocolVersion); h != "" && h != version {
		return headerMismatch(mcp.HeaderProtocolVersion + " does not match params._meta." + mcp.MetaProtocolVersion)
	}
	if !slices.Contains(mcp.SupportedVersions, version) {
		return unsupportedVersion(version)
	}
	if !v.Exists("params", "_meta", mcp.MetaClientCapabilities) {
		return missingMeta(mcp.MetaClientCapabilities)
	}

	method := string(v.GetStringBytes("method"))
	if got := r.Header.Get(mcp.HeaderMethod); got != method {
		return headerMismatch(mcp.HeaderMethod + " does not match the method in the body")
	}
	return validateName(r, v, method)
}

// validateName checks Mcp-Name for the three methods that carry one.
func validateName(r *http.Request, v *fastjson.Value, method string) *fault {
	path := mcp.NamePathFor(method)
	if path == nil {
		return nil
	}
	// Required before compared. Equality alone would let a request with an empty
	// name through on an absent header — both sides read as "" and match — and
	// the header is required on these three methods whatever the body says.
	raw := r.Header.Get(mcp.HeaderName)
	if raw == "" {
		return headerMismatch(mcp.HeaderName + " is required for " + method)
	}
	// Decoded before comparing: "servers MUST decode an encoded Mcp-Name value
	// before comparing it to the corresponding request body value".
	got, err := mcp.DecodeHeaderValue(raw)
	if err != nil || got != string(v.GetStringBytes(path...)) {
		return headerMismatch(mcp.HeaderName + " does not match the name in the body")
	}
	return nil
}

// metaString reads one reserved _meta key of the request. A nil value, a body
// that is not an object, a missing key — fastjson answers all three with an
// empty result of its own accord, so there is nothing to guard here.
func metaString(v *fastjson.Value, key string) string {
	return string(v.GetStringBytes("params", "_meta", key))
}

// writeFault answers a refused modern request: the JSON-RPC error in the body,
// and always a 400 — every refusal decided before dispatch is one, which is why
// fault carries no status of its own.
//
// The envelope is zenrpc's, the one every dispatched error goes out in, so a
// refusal here cannot come out in a shape of its own. The id is echoed exactly
// as it arrived — "error responses MUST include the same ID as the request they
// correspond to" — and a request whose id could not be read gets null, which is
// what JSON-RPC asks for.
func writeFault(w http.ResponseWriter, id *fastjson.Value, f fault) {
	var raw *json.RawMessage
	if id != nil {
		b := json.RawMessage(id.MarshalTo(nil))
		raw = &b
	}
	b, err := json.Marshal(zenrpc.NewResponseError(raw, f.code, f.message, f.data))
	if err != nil { // a fixed shape plus data the caller supplied
		http.Error(w, f.message, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write(b)
}

// statusForResponse raises the HTTP status of a dispatched answer for the codes
// whose status this revision fixes, and leaves everything else at 200.
//
// Only two cases are lifted. An unknown method is 404 because a client uses
// that status to tell a modern server from a legacy one that does not host this
// endpoint at all; the header and version refusals are 400 because they are how
// a client learns to correct the request rather than fall back. Every other
// JSON-RPC error — an unknown resource, a tool that failed — stays inside a 200,
// which is where JSON-RPC puts errors and where a legacy client expects them.
func statusForResponse(body []byte) int {
	// Asked before the parse, and it is what keeps this cheap: a successful
	// answer omits the member entirely, so the common case never gets past this
	// line. Parsing every answer to read one int that is usually absent cost a
	// full copy of the body — on a megabyte of tool output, a megabyte of
	// garbage per request. A false positive from payload data merely falls
	// through to the parse below, which then finds no error object.
	if !bytes.Contains(body, []byte(`"error"`)) {
		return http.StatusOK
	}
	var p fastjson.Parser
	v, err := p.ParseBytes(body)
	if err != nil || v.Type() != fastjson.TypeObject {
		return http.StatusOK
	}
	e := v.Get("error")
	if e == nil {
		return http.StatusOK
	}
	switch e.GetInt("code") {
	case zenrpc.MethodNotFound:
		return http.StatusNotFound
	case mcp.CodeHeaderMismatch, mcp.CodeUnsupportedProtocolVersion:
		return http.StatusBadRequest
	}
	return http.StatusOK
}
