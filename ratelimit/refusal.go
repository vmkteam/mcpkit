package ratelimit

// What a refused caller is told. A denial used to be a text/plain 429, which a
// bridge reports to the model as "server unavailable": the model could neither
// wait sensibly nor ask for less, and nobody watching could tell a ban from an
// outage. It is now a JSON-RPC error answering the call that was refused, with
// the limit and the wait in it.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vmkteam/mcpkit/mcp"

	"github.com/valyala/fastjson"
	"github.com/vmkteam/zenrpc/v2"
)

// maxPeekBytes caps how much of a body the limiter reads to find the call
// Exempt is asked about. An MCP call is kilobytes; a body over this is never
// exempt, and is refused the old way, without an envelope.
const maxPeekBytes = 1 << 20 // 1 MiB

// maxRefusalPeekBytes caps what a refusal reads to find the id it answers. A
// refusal is how the limiter sheds load, and reading a megabyte of every
// request it turns away made shedding cost as much as serving; a body over
// this gets the plain 429.
const maxRefusalPeekBytes = 64 << 10 // 64 KiB

// call is what the limiter reads of a request body. The zero value is what an
// unreadable body leaves: no id to answer, nothing to exempt.
type call struct {
	// id is the request id as it arrived, or nil for a notification, which has
	// no answer to carry an error in.
	id     json.RawMessage
	method string
	// name is what Mcp-Name mirrors: the tool of tools/call, the prompt of
	// prompts/get, the URI of resources/read.
	name string
}

// peek reads the JSON-RPC request out of the body and puts the body back, so
// the handler behind reads the same bytes. ok is false when there is no single
// request to read: not JSON, a batch, more than limit bytes of it, or a body
// that repeats a key read here.
//
// The last is what keeps Exempt honest. What the limiter reads has to be what
// the dispatcher runs, and the two readers disagree about a repeated key:
// fastjson takes the first and matches exact bytes, encoding/json — which
// decodes the call for zenrpc — takes the last and ignores case.
// {"name":"help","Name":"db_query"} was exempted as help and run as db_query,
// at no cost to the budget.
func peek(r *http.Request, limit int64) (c call, ok bool) {
	head, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(head), r.Body), r.Body}
	if err != nil || int64(len(head)) > limit {
		return call{}, false
	}

	var p fastjson.Parser
	v, err := p.ParseBytes(head)
	if err != nil || v.Type() != fastjson.TypeObject {
		return call{}, false
	}
	if repeated(v, "method") || repeated(v, "params") {
		return call{}, false
	}
	c.method = string(v.GetStringBytes("method"))
	if path := mcp.NamePathFor(c.method); path != nil {
		last := len(path) - 1
		if repeated(v.Get(path[:last]...), path[last]) {
			return call{}, false
		}
		c.name = string(v.GetStringBytes(path...))
	}
	if id := v.Get("id"); id != nil && id.Type() != fastjson.TypeNull {
		c.id = id.MarshalTo(nil)
	}
	return c, true
}

// repeated reports whether key occurs more than once in the object v, spelt in
// any case: encoding/json folds case, and Unicode's with it, when it matches a
// member to a field. A value that is not an object, or is not there, repeats
// nothing.
func repeated(v *fastjson.Value, key string) bool {
	if v == nil || v.Type() != fastjson.TypeObject {
		return false
	}
	kb, n := []byte(key), 0
	v.GetObject().Visit(func(k []byte, _ *fastjson.Value) {
		if bytes.EqualFold(k, kb) {
			n++
		}
	})
	return n > 1
}

// refusal is one denial, as the caller is told about it.
type refusal struct {
	reason     string
	retryAfter time.Duration
	// budget is set whenever the hourly budget is on, whichever limit refused:
	// how much of it is gone is worth knowing on any denial.
	budget *Budget
}

// refusalFor describes the denial acquire has just returned for userID at now.
//
// The wait is worked out per limit, because no single number is true of all
// four. The budget comes back when the window rolls, which can be most of an
// hour away. The rate bucket knows exactly when its next token lands. A
// concurrency slot frees up when a neighbouring request finishes — soon, but
// nothing here knows when, so the answer is a second.
func (l *Limiter) refusalFor(userID, reason string, now time.Time) refusal {
	rf := refusal{reason: reason, retryAfter: time.Second}

	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[userID]
	if !ok { // entryFor has just created it; only eviction could take it, after hours idle
		return rf
	}
	if l.cfg.CostBudgetPerHour > 0 {
		b := l.budgetOf(e, 0, now)
		rf.budget = &b
	}
	switch reason {
	case reasonCostBudget:
		rf.retryAfter = rf.budget.ResetAt.Sub(now)
	case reasonRPM:
		// Read, not reserved: a reservation is a token spent until it is
		// cancelled, and the refused call would pay for itself.
		missing := 1 - e.rpm.TokensAt(now)
		rf.retryAfter = time.Duration(missing / float64(e.rpm.Limit()) * float64(time.Second))
	}
	return rf
}

// retryAfterSeconds is the wait in whole seconds, rounded up and never zero: a
// client told to retry in 0 retries at once and is refused again.
func (rf refusal) retryAfterSeconds() int {
	return max(1, int((rf.retryAfter+time.Second-1)/time.Second))
}

// logArgs is the denial for the log: enough for whoever is on call to tell a
// ban of an hour from one of a second without asking the caller.
func (rf refusal) logArgs(userID string) []any {
	args := []any{"user", userID, "reason", rf.reason, "retry_after", rf.retryAfterSeconds()}
	if rf.budget != nil {
		args = append(args, "budget_used", formatDuration(rf.budget.Used))
	}
	return args
}

// data is the error's data member: what the model reads to decide whether to
// wait or to ask for less.
func (rf refusal) data() any {
	d := struct {
		Reason      string `json:"reason"`
		RetryAfter  int    `json:"retry_after"`
		BudgetUsed  string `json:"budget_used,omitempty"`
		BudgetLimit string `json:"budget_limit,omitempty"`
		Window      string `json:"window,omitempty"`
	}{Reason: rf.reason, RetryAfter: rf.retryAfterSeconds()}
	if rf.budget != nil {
		d.BudgetUsed = formatDuration(rf.budget.Used)
		d.BudgetLimit = formatDuration(rf.budget.Limit)
		d.Window = formatDuration(budgetWindow)
	}
	return d
}

// refuse answers a denied request, id being what peek read of it.
//
// A request with an id is answered with a JSON-RPC error to that id, which a
// client can show as a failed call rather than as a dead server. Anything else —
// not JSON, a batch, a notification, a body too large to look into — gets the
// plain 429 it always got: there is no id to answer, and the transport behind
// would refuse most of those anyway.
//
// The envelope is zenrpc's, the one every other JSON-RPC error of the server
// goes out in. The status stays 429 under it: that is what a proxy and a
// retrying transport understand, and Retry-After means something only beside
// it.
func refuse(w http.ResponseWriter, rf refusal, id json.RawMessage) {
	w.Header().Set("Retry-After", strconv.Itoa(rf.retryAfterSeconds()))
	message := "rate limit: " + rf.reason

	if id == nil {
		http.Error(w, message, http.StatusTooManyRequests)
		return
	}
	b, err := json.Marshal(zenrpc.NewResponseError(&id, mcp.CodeRateLimited, message, rf.data()))
	if err != nil { // a fixed shape; the id is what fastjson just wrote out
		http.Error(w, message, http.StatusTooManyRequests)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write(b)
}

// formatDuration writes d the way a person would: 5m rather than 5m0s, 1h
// rather than 1h0m0s. Whole seconds from a second up; below that, milliseconds.
func formatDuration(d time.Duration) string {
	if d >= time.Second {
		d = d.Round(time.Second)
	} else {
		d = d.Round(time.Millisecond)
	}
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}
