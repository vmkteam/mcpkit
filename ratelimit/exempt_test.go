package ratelimit

import (
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

const helpCall = `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"help","arguments":{}}}`

func exemptHelp(method, name string) bool { return method == "tools/call" && name == "help" }

// spendAll is a handler every call of which costs twice the budget, so one
// billed call is enough to spend it.
func spendAll(w http.ResponseWriter, r *http.Request) {
	Charge(r.Context(), 2*time.Minute)
	w.WriteHeader(http.StatusOK)
}

// Every MCP tool goes through tools/call, so the method alone cannot tell help
// from a query: the name is what separates them.
func TestExemptPassesWhenTheBudgetIsGone(t *testing.T) {
	l := newLimiter(t, Config{CostBudgetPerHour: time.Minute, Exempt: exemptHelp})
	h := l.Middleware(http.HandlerFunc(spendAll), embedlog.Logger{})

	require.Equal(t, http.StatusOK, post(h, toolCall).Code, "the first call spends the budget")
	assert.Equal(t, http.StatusTooManyRequests, post(h, toolCall).Code, "the next one is refused")
	assert.Equal(t, http.StatusOK, post(h, helpCall).Code, "help is not")
	assert.Equal(t, http.StatusOK, post(h, helpCall).Code, "and never is")
}

// What an exempt call charges does not reach the budget, however much it is.
func TestExemptChargesNothing(t *testing.T) {
	l := newLimiter(t, Config{CostBudgetPerHour: time.Minute, Exempt: exemptHelp})
	h := l.Middleware(http.HandlerFunc(spendAll), embedlog.Logger{})

	require.Equal(t, http.StatusOK, post(h, helpCall).Code)
	require.Equal(t, http.StatusOK, post(h, helpCall).Code)
	assert.Equal(t, http.StatusOK, post(h, toolCall).Code, "two help calls left the budget whole")
	assert.Equal(t, http.StatusTooManyRequests, post(h, toolCall).Code)
}

// The budget is all an exemption spares. The rate still counts, or an exempt
// name would be a way to call at any speed.
func TestExemptStillPaysTheRate(t *testing.T) {
	l := newLimiter(t, Config{PerUserRPM: 1, CostBudgetPerHour: time.Minute, Exempt: exemptHelp})
	h := l.Middleware(http.HandlerFunc(okHandler), embedlog.Logger{})

	require.Equal(t, http.StatusOK, post(h, helpCall).Code)
	rec := post(h, helpCall)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Contains(t, rec.Body.String(), reasonRPM)
}

// Exempt is asked with what Mcp-Name would carry, for whichever method carries
// one — and not at all about a body there is no call in.
func TestExemptIsAskedAboutTheCall(t *testing.T) {
	type asked struct{ method, name string }
	var got []asked
	l := newLimiter(t, Config{CostBudgetPerHour: time.Minute, Exempt: func(method, name string) bool {
		got = append(got, asked{method, name})
		return true
	}})
	h := l.Middleware(http.HandlerFunc(okHandler), embedlog.Logger{})

	post(h, helpCall)
	post(h, `{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"doc://help"}}`)
	post(h, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)
	post(h, `[`+helpCall+`]`)
	post(h, `not json`)

	assert.Equal(t, []asked{
		{"tools/call", "help"},
		{"resources/read", "doc://help"},
		{"tools/list", ""},
	}, got)
}

// A body the limiter could not read is not exempt, whatever Exempt would have
// said about it.
func TestExemptDoesNotCoverAnUnreadableBody(t *testing.T) {
	l := newLimiter(t, Config{CostBudgetPerHour: time.Minute, Exempt: func(string, string) bool { return true }})
	h := l.Middleware(http.HandlerFunc(spendAll), embedlog.Logger{})

	require.Equal(t, http.StatusOK, post(h, `[`+helpCall+`]`).Code, "billed, since it is not exempt")
	assert.Equal(t, http.StatusTooManyRequests, post(h, `[`+helpCall+`]`).Code)
}

// With Exempt set the limiter reads every body, and the handler behind still
// reads all of it.
func TestExemptLeavesTheBodyWhole(t *testing.T) {
	var seen []string
	l := newLimiter(t, Config{CostBudgetPerHour: time.Minute, Exempt: exemptHelp})
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		seen = append(seen, string(b))
		w.WriteHeader(http.StatusOK)
	}), embedlog.Logger{})

	post(h, helpCall)
	post(h, toolCall)
	assert.Equal(t, []string{helpCall, toolCall}, seen)
}

// An exempt name cannot be borrowed by a call that repeats the key: the
// dispatcher would run the last one, and the limiter will not guess.
func TestExemptIsNotFooledByARepeatedKey(t *testing.T) {
	l := newLimiter(t, Config{CostBudgetPerHour: time.Minute, Exempt: exemptHelp})
	h := l.Middleware(http.HandlerFunc(spendAll), embedlog.Logger{})
	require.Equal(t, http.StatusOK, post(h, toolCall).Code, "the budget is spent")

	borrowed := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"help","name":"api_call","arguments":{}}}`
	assert.Equal(t, http.StatusTooManyRequests, post(h, borrowed).Code)
	assert.Equal(t, http.StatusOK, post(h, helpCall).Code, "help itself still passes")
}
