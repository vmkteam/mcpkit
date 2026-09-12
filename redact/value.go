package redact

import (
	"encoding/json"
	"reflect"
)

// maxDepth bounds the walk. Decoded JSON is a tree, but a struct or a map
// reached through reflection can point back at itself, and a cycle here would
// spin forever while holding whatever the answer was read from. Thirty-two is
// far past any real payload and far short of a stack overflow.
const maxDepth = 32

// maskAny returns v with every string reachable inside it masked.
//
// The walk is a hybrid on purpose. A type switch covers what a decoded JSON
// document is made of — string, []any, map[string]any — and that is the whole
// of one service's hot path; everything else falls through to reflect, which is
// what reaches a *string from a nullable column, a []string from an array one,
// a struct from a driver that returns rows as structs. Pure reflection would
// charge every JSON string for the reflection it does not need; a pure type
// switch would miss exactly the columns where addresses live.
func (r *Redactor) maskAny(v any, res *Result, depth int) any {
	if depth > maxDepth {
		return v
	}
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		masked := r.maskString(t, res)
		if masked == t {
			// The caller's own interface box, not a fresh one. Almost every cell
			// of a table comes back unchanged, and boxing each of them again put
			// ten thousand allocations on the path whose comment says a copy
			// costs more than the convenience is worth.
			return v
		}
		return masked
	case []any:
		for i, item := range t {
			t[i] = r.maskAny(item, res, depth+1)
		}
		return t
	case map[string]any:
		// Keys are left alone: a key is a name, and rewriting one loses the
		// reader the field rather than the value.
		for k, item := range t {
			t[k] = r.maskAny(item, res, depth+1)
		}
		return t
	case bool, float64, int, int64:
		return v
	case json.Number:
		// A decision, not a fast path. json.Number is a named string type, so
		// without this case it would be masked like prose — and a number is not
		// personal data, while rewriting one breaks the arithmetic the answer
		// was asked for.
		return v
	}
	out, changed := r.maskReflect(reflect.ValueOf(v), res, depth)
	if !changed {
		return v
	}
	return out.Interface()
}

// maskReflect walks one value. It reports whether anything changed, so that an
// unchanged value keeps its original representation — in warn mode nothing is
// rewritten at all, and even under mask most cells are untouched.
//
// The one invariant that matters: a rule is never counted on a string this
// function cannot write back. A hit recorded without the write is worse than a
// missed mask, because the audit record then names a rule that did not fire and
// the value reaches the reader in the clear anyway. Every branch below either
// masks into something writable or does not descend at all.
//
// A slice is mutated in place, its backing storage being shared with the caller
// either way — that is what Rows relies on. An array and a struct are values:
// the one reached through an interface is not addressable, so it is masked into
// an addressable copy and returned. A pointer is replaced with a new one rather
// than written through, so masking never edits a value a driver may still own.
func (r *Redactor) maskReflect(v reflect.Value, res *Result, depth int) (reflect.Value, bool) {
	if depth > maxDepth || !v.IsValid() {
		return v, false
	}
	switch v.Kind() { //nolint:exhaustive // the other kinds cannot hold a string
	case reflect.String:
		str := v.String()
		masked := r.maskString(str, res)
		if masked == str {
			return v, false
		}
		out := reflect.New(v.Type()).Elem() // preserves named string types
		out.SetString(masked)
		return out, true

	case reflect.Interface:
		if v.IsNil() {
			return v, false
		}
		return r.maskReflect(v.Elem(), res, depth+1)

	case reflect.Pointer:
		if v.IsNil() {
			return v, false
		}
		inner, changed := r.maskReflect(v.Elem(), res, depth+1)
		if !changed {
			return v, false
		}
		out := reflect.New(v.Type().Elem())
		out.Elem().Set(inner)
		return out, true

	case reflect.Slice:
		return r.maskSlice(v, res, depth)

	case reflect.Array:
		return r.maskArray(v, res, depth)

	case reflect.Struct:
		return r.maskStruct(v, res, depth)

	case reflect.Map:
		return r.maskMap(v, res, depth)
	}
	return v, false
}

// maskSlice masks in place: the backing storage is shared with the caller
// either way, which is what Rows relies on. An element that cannot be set is
// skipped rather than counted.
func (r *Redactor) maskSlice(v reflect.Value, res *Result, depth int) (reflect.Value, bool) {
	if v.IsNil() {
		return v, false
	}
	changed := false
	for i := range v.Len() {
		e := v.Index(i)
		if !e.CanSet() {
			continue
		}
		inner, c := r.maskReflect(e, res, depth+1)
		if !c {
			continue
		}
		e.Set(inner)
		changed = true
	}
	return v, changed
}

// maskArray masks into a copy. An array is a value and the one behind an
// interface is not addressable, so masking it in place is impossible; counting
// hits against the original and then failing to write them is the bug this
// branch exists to avoid.
func (r *Redactor) maskArray(v reflect.Value, res *Result, depth int) (reflect.Value, bool) {
	out := reflect.New(v.Type()).Elem()
	out.Set(v)
	changed := false
	for i := range out.Len() {
		inner, c := r.maskReflect(out.Index(i), res, depth+1)
		if !c {
			continue
		}
		out.Index(i).Set(inner)
		changed = true
	}
	if !changed {
		return v, false
	}
	return out, true
}

// maskStruct masks exported fields only. An unexported one cannot be written
// through reflection, so descending into it would count a rule against a value
// that stays in the clear — time.Time and every driver wrapper built on
// unexported state passes through untouched, which is correct: there is no
// personal data in a monotonic clock reading.
func (r *Redactor) maskStruct(v reflect.Value, res *Result, depth int) (reflect.Value, bool) {
	t := v.Type()
	out := reflect.New(t).Elem()
	out.Set(v)
	changed := false
	for i := range t.NumField() {
		if !t.Field(i).IsExported() {
			continue
		}
		f := out.Field(i)
		inner, c := r.maskReflect(f, res, depth+1)
		if !c {
			continue
		}
		f.Set(inner)
		changed = true
	}
	if !changed {
		return v, false
	}
	return out, true
}

// maskMap masks values in place; keys are never touched — a key is a column
// name or a field name, not a value a person owns.
func (r *Redactor) maskMap(v reflect.Value, res *Result, depth int) (reflect.Value, bool) {
	if v.IsNil() {
		return v, false
	}
	changed := false
	for _, key := range v.MapKeys() {
		inner, c := r.maskReflect(v.MapIndex(key), res, depth+1)
		if !c {
			continue
		}
		v.SetMapIndex(key, inner)
		changed = true
	}
	return v, changed
}
