package mcp

// Pagination. The protocol's cursor is opaque: "Clients MUST treat cursors as
// opaque tokens" and must not parse, construct or guess one. What is inside is
// therefore entirely the server's choice, and what is inside here is the
// identity of the last entry of the page — its name, or its URI for a resource
// — base64url encoded.
//
// That choice has a consequence worth stating: resuming means finding that
// entry again, so a cursor outlives a change to the catalogue only if the entry
// it names is still there. When it is not, the cursor is refused rather than
// silently resolved to a nearby position — see Paginate.

import (
	"encoding/base64"
	"fmt"
)

// maxCursorLen caps what will even be decoded. A cursor is client input, and
// without a cap a caller can hand the decoder as many megabytes as the request
// body allows. No catalogue here has entry names anywhere near this long.
const maxCursorLen = 512

// EncodeCursor turns the identity of an entry into the token a client sends
// back to continue from it.
func EncodeCursor(key string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(key))
}

// DecodeCursor recovers the identity a cursor was made from.
//
// A cursor that does not decode is the caller's mistake, not the server's, so
// the error is marked ErrInvalidParams and reaches the client as -32602 — which
// is what the spec asks for: "If the cursor is invalid, servers SHOULD return
// an Invalid params error".
//
// The bad value is deliberately not echoed back: it is unvalidated input of
// arbitrary bytes, and a JSON-RPC message is not the place for it.
func DecodeCursor(cursor string) (string, error) {
	if len(cursor) > maxCursorLen {
		return "", fmt.Errorf("cursor is too long: %w", ErrInvalidParams)
	}
	b, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return "", fmt.Errorf("cursor is malformed: %w", ErrInvalidParams)
	}
	return string(b), nil
}

// Paginate cuts one page out of items, starting just after the entry the cursor
// names, and returns the cursor that continues it. key reports the identity of
// an entry: Name for a tool or a prompt, URI for a resource.
//
// size of zero or less means no paging at all — the whole list, and no
// nextCursor. That is the default, and for a catalogue of a few dozen entries
// it is also the right answer: a page is a round trip, and the model pays for
// it in latency before it can do anything with the list.
//
// An empty next is the end of the enumeration, and it is the only signal a
// client has: "the absence of a nextCursor indicates the end of the results".
// A short page is not one — the last full page returns no cursor precisely so
// that the client is not sent back for a page it would find empty.
//
// A cursor naming an entry that is no longer in the list is refused as invalid.
// It is well-formed, so the alternative was tempting: resume from wherever that
// name would have sorted. But this library does not know the list is sorted —
// tools come in registration order, resources in walk order — so "wherever"
// would mean starting over or skipping ahead, silently, in the middle of an
// enumeration the client believes is consistent. Refusing says what happened,
// and restarting the enumeration is the recovery the protocol already defines.
func Paginate[T any](items []T, cursor string, size int, key func(T) string) (page []T, next string, err error) {
	start := 0
	if cursor != "" {
		after, err := DecodeCursor(cursor)
		if err != nil {
			return nil, "", err
		}
		// The *last* match, not the first. A source is free to hand out two
		// entries with the same name — ResourceSource and PromptSource are the
		// extension point for a service with its own catalogue, and neither
		// interface promises uniqueness. Resuming at the first match then
		// returned the same page forever and the client never reached the end.
		// Taking the last one makes a duplicate skip a page rather than loop,
		// which is the failure a client can at least survive.
		idx := -1
		for i := range items {
			if key(items[i]) == after {
				idx = i
			}
		}
		if idx < 0 {
			return nil, "", fmt.Errorf("cursor points at an entry that is no longer listed: %w", ErrInvalidParams)
		}
		start = idx + 1
	}

	switch {
	// size >= len(items)-start rather than start+size >= len(items): the sum
	// overflows for an absurd page size, and a negative bound panics the slice.
	case size <= 0, size >= len(items)-start:
		page = items[start:]
	default:
		page = items[start : start+size]
		next = EncodeCursor(key(page[len(page)-1]))
	}
	// Never nil: every list result here marshals as [] when empty, because a
	// client with a strict schema rejects null where an array was promised.
	if page == nil {
		page = []T{}
	}
	return page, next, nil
}
