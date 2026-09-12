package mcp

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// same is the identity function these tests page by: the entries are their own
// names.
func same(s string) string { return s }

// Walking the whole list one page at a time has to visit every entry exactly
// once and stop by itself. This is the property that matters — a client loops
// until nextCursor is absent, and an off-by-one here either drops an entry or
// never terminates.
func TestPaginateWalksEveryEntryOnce(t *testing.T) {
	t.Parallel()
	items := []string{"a", "b", "c", "d", "e", "f", "g"}
	for _, size := range []int{1, 2, 3, 6, 7, 8, 100} {
		t.Run("size="+strconv.Itoa(size), func(t *testing.T) {
			t.Parallel()
			var got []string
			cursor := ""
			for i := 0; ; i++ {
				require.Less(t, i, len(items)+2, "enumeration did not terminate")
				page, next, err := Paginate(items, cursor, size, same)
				require.NoError(t, err)
				assert.LessOrEqual(t, len(page), size, "a page never exceeds the declared size")
				got = append(got, page...)
				if next == "" {
					break
				}
				cursor = next
			}
			assert.Equal(t, items, got)
		})
	}
}

func TestPaginate(t *testing.T) {
	t.Parallel()
	items := []string{"a", "b", "c", "d", "e"}

	t.Run("no page size is the whole list and no cursor", func(t *testing.T) {
		t.Parallel()
		page, next, err := Paginate(items, "", 0, same)
		require.NoError(t, err)
		assert.Equal(t, items, page)
		assert.Empty(t, next, "a server that does not page never issues a cursor")
	})

	t.Run("a cursor resumes after the entry it names", func(t *testing.T) {
		t.Parallel()
		page, next, err := Paginate(items, EncodeCursor("b"), 2, same)
		require.NoError(t, err)
		assert.Equal(t, []string{"c", "d"}, page)
		assert.Equal(t, EncodeCursor("d"), next)
	})

	// The end of the enumeration is the absence of a cursor and nothing else.
	// A last page that filled exactly must therefore still say it is the last,
	// or the client is sent back for a page it would find empty.
	t.Run("the last page carries no cursor", func(t *testing.T) {
		t.Parallel()
		page, next, err := Paginate(items, EncodeCursor("c"), 2, same)
		require.NoError(t, err)
		assert.Equal(t, []string{"d", "e"}, page)
		assert.Empty(t, next)
	})

	t.Run("a cursor on the final entry is an empty last page", func(t *testing.T) {
		t.Parallel()
		page, next, err := Paginate(items, EncodeCursor("e"), 2, same)
		require.NoError(t, err)
		assert.Empty(t, page)
		assert.Empty(t, next)
	})

	// An empty list marshals as [] and not null whatever the paging says:
	// clients with strict schemas reject null where an array was promised.
	t.Run("an empty list is [] and not null", func(t *testing.T) {
		t.Parallel()
		for _, in := range [][]string{nil, {}} {
			page, next, err := Paginate(in, "", 2, same)
			require.NoError(t, err)
			assert.Empty(t, next)
			b, err := json.Marshal(page)
			require.NoError(t, err)
			assert.JSONEq(t, `[]`, string(b))
		}
	})
}

// A cursor is client input. Every way of getting it wrong is the caller's
// mistake — -32602, not -32603 — which is what the ErrInvalidParams mark says.
func TestPaginateRejectsBadCursors(t *testing.T) {
	t.Parallel()
	items := []string{"a", "b", "c"}
	cases := map[string]string{
		"not base64":    "!!!!",
		"padded base64": base64.StdEncoding.EncodeToString([]byte("aaaa")), // RawURLEncoding takes no '='
		"too long":      base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", maxCursorLen))),
		"unknown entry": EncodeCursor("zzz"),
	}
	for name, cursor := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, _, err := Paginate(items, cursor, 2, same)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidParams, "a bad cursor must be -32602")
		})
	}
}

// The catalogue here is loaded at startup and does not change under a running
// enumeration, but a dev run on an os.DirFS reloads and a service with its own
// source may do anything.
//
// The two outcomes are both deliberate. While the entry a cursor names is still
// there, the enumeration continues from it and simply does not report what
// changed behind it — no cursor scheme can. Once that entry is gone, resuming
// would mean guessing a position: refusing says what happened instead, and
// restarting the enumeration is the recovery the protocol already defines.
func TestPaginateWhenTheListChangedUnderneath(t *testing.T) {
	t.Parallel()
	before := []string{"a", "b", "c", "d"}
	page, next, err := Paginate(before, "", 2, same)
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b"}, page)
	require.NotEmpty(t, next)

	t.Run("inserted ahead of the cursor: served", func(t *testing.T) {
		t.Parallel()
		got, _, err := Paginate([]string{"a", "b", "b2", "c", "d"}, next, 2, same)
		require.NoError(t, err)
		assert.Equal(t, []string{"b2", "c"}, got)
	})

	t.Run("inserted behind the cursor: never seen", func(t *testing.T) {
		t.Parallel()
		got, _, err := Paginate([]string{"a", "a2", "b", "c", "d"}, next, 2, same)
		require.NoError(t, err)
		assert.Equal(t, []string{"c", "d"}, got, "a2 is behind the cursor and this page cannot go back for it")
	})

	t.Run("the entry itself is gone: refused, not guessed", func(t *testing.T) {
		t.Parallel()
		_, _, err := Paginate([]string{"a", "c", "d"}, next, 2, same)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidParams)
	})
}

// ResourceSource and PromptSource are the extension point for a service with
// its own catalogue, and neither interface promises unique names. Resuming at
// the first match then returned the same page forever: the client looped and
// never reached the end of a list it was told it could enumerate.
func TestPaginateSurvivesDuplicateKeys(t *testing.T) {
	t.Parallel()
	items := []string{"a", "b", "c", "b", "d"}

	var got []string
	cursor := ""
	for i := 0; ; i++ {
		require.Less(t, i, 10, "enumeration did not terminate")
		page, next, err := Paginate(items, cursor, 2, same)
		require.NoError(t, err)
		got = append(got, page...)
		if next == "" {
			break
		}
		cursor = next
	}
	// A duplicate costs entries, not termination: resuming after the *last*
	// match skips whatever lies between the two, and that is the failure a
	// client can survive. Looping forever is not.
	assert.Contains(t, got, "d", "the end of the list has to be reachable")
}

// An absurd page size must not be able to panic the slice: start+size overflows
// and a negative bound is a runtime error, and start is reachable because entry
// names are public — a client can build a valid cursor from tools/list.
func TestPaginateSurvivesAnAbsurdPageSize(t *testing.T) {
	t.Parallel()
	items := []string{"a", "b", "c"}
	assert.NotPanics(t, func() {
		page, next, err := Paginate(items, EncodeCursor("a"), math.MaxInt, same)
		require.NoError(t, err)
		assert.Equal(t, []string{"b", "c"}, page)
		assert.Empty(t, next)
	})
}

// The cursor is opaque by the protocol's rule — a client must not parse one —
// so the only thing that has to hold is the round trip.
func TestCursorRoundTrip(t *testing.T) {
	t.Parallel()
	for _, key := range []string{"a", "docs://targets/grafana.md", "имя", "with space", strings.Repeat("x", 200)} {
		got, err := DecodeCursor(EncodeCursor(key))
		require.NoError(t, err)
		assert.Equal(t, key, got)
	}
}
