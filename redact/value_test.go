package redact

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// namedString stands in for the named string types a database driver hands
// back: a plain type assertion misses every one of them.
type namedString string

func TestValue_FastPath(t *testing.T) {
	t.Parallel()
	r := newRedactor(t, Options{})

	t.Run("string", func(t *testing.T) {
		t.Parallel()
		got, res := r.Value("sergey@acme.com")
		assert.Equal(t, "s***@acme.com", got)
		assert.Equal(t, 1, res.Total())
	})

	t.Run("map[string]any, in place", func(t *testing.T) {
		t.Parallel()
		in := map[string]any{"email": "sergey@acme.com", "count": float64(3)}
		got, res := r.Value(in)
		assert.Equal(t, map[string]any{"email": "s***@acme.com", "count": float64(3)}, got)
		assert.Equal(t, 1, res.Total())
	})

	t.Run("[]any", func(t *testing.T) {
		t.Parallel()
		got, res := r.Value([]any{"sergey@acme.com", float64(1), nil})
		assert.Equal(t, []any{"s***@acme.com", float64(1), nil}, got)
		assert.Equal(t, 1, res.Total())
	})

	t.Run("nested", func(t *testing.T) {
		t.Parallel()
		in := map[string]any{"users": []any{map[string]any{"email": "a@x.com"}}}
		got, _ := r.Value(in)
		assert.Equal(t, map[string]any{"users": []any{map[string]any{"email": "a***@x.com"}}}, got)
	})

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		got, res := r.Value(nil)
		assert.Nil(t, got)
		assert.Zero(t, res.Total())
	})

	// Rewriting a number breaks the arithmetic the answer was asked for, and a
	// key is a name — losing it loses the reader the field, not the value.
	t.Run("numbers and keys are left alone", func(t *testing.T) {
		t.Parallel()
		in := map[string]any{"sergey@acme.com": float64(4242424242424242)}
		got, res := r.Value(in)
		assert.Equal(t, in, got)
		assert.Zero(t, res.Total())
	})
}

func TestValue_ReflectPath(t *testing.T) {
	t.Parallel()
	r := newRedactor(t, Options{})

	t.Run("*string, the nullable column", func(t *testing.T) {
		t.Parallel()
		in := "sergey@acme.com"
		got, res := r.Value(&in)
		p, ok := got.(*string)
		require.True(t, ok)
		assert.Equal(t, "s***@acme.com", *p)
		assert.Equal(t, 1, res.Total())
		assert.Equal(t, "sergey@acme.com", in,
			"a pointer is replaced, not written through: the value behind it may belong to a driver")
	})

	t.Run("a nil pointer is left alone", func(t *testing.T) {
		t.Parallel()
		var p *string
		got, res := r.Value(p)
		assert.Equal(t, p, got)
		assert.Zero(t, res.Total())
	})

	t.Run("[]string, the array column", func(t *testing.T) {
		t.Parallel()
		got, res := r.Value([]string{"a@x.com", "plain"})
		assert.Equal(t, []string{"a***@x.com", "plain"}, got)
		assert.Equal(t, 1, res.Total())
	})

	t.Run("map[string]string", func(t *testing.T) {
		t.Parallel()
		got, res := r.Value(map[string]string{"who": "a@x.com"})
		assert.Equal(t, map[string]string{"who": "a***@x.com"}, got)
		assert.Equal(t, 1, res.Total())
	})

	t.Run("a named string type keeps its type", func(t *testing.T) {
		t.Parallel()
		got, res := r.Value(namedString("a@x.com"))
		assert.Equal(t, namedString("a***@x.com"), got)
		assert.Equal(t, 1, res.Total())
	})

	// An array is a value, and the one behind an interface is not addressable.
	// Masking it used to count the hit and write nothing: the audit record then
	// named a rule that never fired while the address travelled on in the clear.
	t.Run("[N]string, the fixed-size column", func(t *testing.T) {
		t.Parallel()
		got, res := r.Value([2]string{"a@x.com", "plain"})
		assert.Equal(t, [2]string{"a***@x.com", "plain"}, got)
		assert.Equal(t, 1, res.Total())
	})

	// A driver that returns rows as structs is not exotic, and a struct that is
	// never walked is a silent leak with a clean Result beside it.
	t.Run("a struct is walked field by field", func(t *testing.T) {
		t.Parallel()
		type row struct {
			Email string
			Note  string
			Count int
		}
		got, res := r.Value(row{Email: "a@x.com", Note: "call +7 916 123 45 67", Count: 3})
		assert.Equal(t, row{Email: "a***@x.com", Note: "call [masked:phone]", Count: 3}, got)
		assert.Equal(t, 2, res.Total())
	})

	t.Run("a pointer to a struct is replaced, not written through", func(t *testing.T) {
		t.Parallel()
		type row struct{ Email string }
		in := &row{Email: "a@x.com"}
		got, res := r.Value(in)
		p, ok := got.(*row)
		require.True(t, ok)
		assert.Equal(t, "a***@x.com", p.Email)
		assert.Equal(t, "a@x.com", in.Email, "the caller's own struct is untouched")
		assert.Equal(t, 1, res.Total())
	})

	t.Run("a slice of structs", func(t *testing.T) {
		t.Parallel()
		type row struct{ Email string }
		got, res := r.Value([]row{{Email: "a@x.com"}, {Email: "plain"}})
		assert.Equal(t, []row{{Email: "a***@x.com"}, {Email: "plain"}}, got)
		assert.Equal(t, 1, res.Total())
	})

	// An unexported field cannot be written through reflection, so it must not
	// be counted either: time.Time is the case that reaches every result set.
	t.Run("unexported fields are neither masked nor counted", func(t *testing.T) {
		t.Parallel()
		got, res := r.Value(withUnexported{Shown: "a@x.com", hidden: "b@y.com"})
		out, ok := got.(withUnexported)
		require.True(t, ok)
		assert.Equal(t, "a***@x.com", out.Shown)
		assert.Equal(t, "b@y.com", out.hidden, "an unexported field is left alone")
		assert.Equal(t, 1, res.Total(), "only the field that was actually masked is counted")
	})

	t.Run("a self-referencing value terminates", func(t *testing.T) {
		t.Parallel()
		type node struct {
			Email string
			Next  *node
		}
		n := &node{Email: "a@x.com"}
		n.Next = n
		assert.NotPanics(t, func() { r.Value(n) }, "a cycle must not spin forever")
	})
}

// withUnexported stands in for time.Time and every driver wrapper built on
// unexported state: reachable, holding strings, and impossible to write to.
type withUnexported struct {
	Shown  string
	hidden string
}

func TestRows(t *testing.T) {
	t.Parallel()
	r := newRedactor(t, Options{})

	nullable := "sergey@acme.com"
	rows := [][]any{
		{"a@x.com", 42, nil},
		{[]string{"b@y.org"}, &nullable, "plain"},
	}
	res := r.Rows(rows)

	assert.Equal(t, "a***@x.com", rows[0][0])
	assert.Equal(t, 42, rows[0][1], "a number stays a number")
	assert.Nil(t, rows[0][2])
	assert.Equal(t, []string{"b***@y.org"}, rows[1][0])

	p, ok := rows[1][1].(*string)
	require.True(t, ok)
	assert.Equal(t, "s***@acme.com", *p)
	assert.Equal(t, "sergey@acme.com", nullable, "the driver's own value is untouched")

	assert.Equal(t, 3, res.Total())
}

func TestRows_OffAndWarn(t *testing.T) {
	t.Parallel()

	t.Run("off changes nothing and counts nothing", func(t *testing.T) {
		t.Parallel()
		rows := [][]any{{"a@x.com"}}
		res := newRedactor(t, Options{Mode: ModeOff}).Rows(rows)
		assert.Equal(t, "a@x.com", rows[0][0])
		assert.Zero(t, res.Total())
	})

	t.Run("warn counts without touching", func(t *testing.T) {
		t.Parallel()
		rows := [][]any{{"a@x.com"}}
		res := newRedactor(t, Options{Mode: ModeWarn}).Rows(rows)
		assert.Equal(t, "a@x.com", rows[0][0])
		assert.Equal(t, 1, res.Total())
	})
}
