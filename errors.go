package mcpkit

// How a failure from a catalogue becomes a JSON-RPC error.

import (
	"errors"
	"fmt"

	"github.com/vmkteam/mcpkit/mcp"

	"github.com/vmkteam/zenrpc/v2"
)

// RPCError turns a source failure into the error the caller should see.
//
// zenrpc wraps any plain error as -32603 — the server reporting that it broke.
// That is the wrong thing to say when the request named a resource or a prompt
// that does not exist: the spec asks for -32602 there, and a caller that reads
// "internal error" retries instead of correcting the name. An error marked
// mcp.ErrInvalidParams therefore travels as a *zenrpc.Error, which Response.Set
// passes through untouched; everything else keeps the old behaviour, because a
// failure to read a file really is this server's problem.
//
// The code -32002 that earlier revisions used for a missing resource is not
// emitted: implementations of 2026-07-28 "MUST NOT" send it.
//
// It is exported because the tools namespace stays in the service — mcptool
// does not know what zenrpc is, and its errors, an invalid cursor among them,
// would otherwise reach the client mislabelled. A nil error stays nil, so a
// service method is one line:
//
//	list, err := s.registry.List(ctx, cursor)
//	return list, mcpkit.RPCError("tools.list", err)
func RPCError(prefix string, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, mcp.ErrInvalidParams):
		return zenrpc.NewStringError(zenrpc.InvalidParams, prefix+": "+err.Error())
	default:
		return fmt.Errorf("%s: %w", prefix, err)
	}
}
