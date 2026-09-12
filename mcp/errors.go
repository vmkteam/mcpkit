package mcp

import "errors"

// ErrInvalidParams marks a failure caused by what the caller asked for — an
// unknown resource, an unknown prompt, a missing required argument — rather
// than by the server. A dispatcher wraps such an error as JSON-RPC -32602.
//
// The mark lives here because "the request named something that is not there"
// is a fact about the protocol, and because the two packages that need to agree
// on it — the catalogue that raises it and the service that answers with it —
// already depend on this one and must not depend on each other.
//
// Without it every plain error reaches the client as -32603: the server saying
// it broke, when what happened is that the caller asked for a name that does
// not exist. The spec is explicit that the resource case is -32602, and that
// -32002 from earlier revisions must no longer be emitted.
var ErrInvalidParams = errors.New("invalid params")
