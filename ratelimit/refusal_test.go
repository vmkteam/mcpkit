package ratelimit

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vmkteam/mcpkit/mcp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

const toolCall = `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"api_call","arguments":{}}}`

type rpcAnswer struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   struct {
		Code    int            `json:"code"`
		Message string         `json:"message"`
		Data    map[string]any `json:"data"`
	} `json:"error"`
}

func post(h http.Handler, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body)))
	return rec
}

func okHandler(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }

// A denial answers the call that was refused, so a client shows it as a failed
// call with a reason — not as a server that went away. Whichever limit said no.
func TestRefusalAnswersTheCall(t *testing.T) {
	tests := map[string]struct {
		cfg Config
		// spend brings the limiter to the point of refusing the next call.
		spend func(t *testing.T, l *Limiter, h http.Handler)
	}{
		reasonRPM: {
			cfg: Config{PerUserRPM: 1},
			spend: func(t *testing.T, _ *Limiter, h http.Handler) {
				require.Equal(t, http.StatusOK, post(h, toolCall).Code)
			},
		},
		reasonUserConcurrent: {
			cfg: Config{PerUserConcurrent: 1},
			spend: func(t *testing.T, l *Limiter, _ http.Handler) {
				release, _ := l.acquire(anonymousUser, time.Now(), false)
				require.NotNil(t, release)
				t.Cleanup(func() { release(charge{}) })
			},
		},
		reasonGlobalConcurrent: {
			cfg: Config{GlobalConcurrent: 1},
			spend: func(t *testing.T, l *Limiter, _ http.Handler) {
				release, _ := l.acquire("bob", time.Now(), false)
				require.NotNil(t, release)
				t.Cleanup(func() { release(charge{}) })
			},
		},
		reasonCostBudget: {
			cfg: Config{CostBudgetPerHour: time.Minute},
			spend: func(t *testing.T, _ *Limiter, h http.Handler) {
				require.Equal(t, http.StatusOK, post(h, toolCall).Code)
			},
		},
	}
	for reason, tc := range tests {
		t.Run(reason, func(t *testing.T) {
			l := newLimiter(t, tc.cfg)
			h := l.Middleware(http.HandlerFunc(spendAll), embedlog.Logger{})
			tc.spend(t, l, h)

			rec := post(h, toolCall)
			require.Equal(t, http.StatusTooManyRequests, rec.Code)
			assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

			var got rpcAnswer
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got), rec.Body.String())
			assert.Equal(t, "2.0", got.JSONRPC)
			assert.JSONEq(t, "7", string(got.ID), "the id of the refused call is echoed")
			assert.Equal(t, mcp.CodeRateLimited, got.Error.Code)
			assert.Equal(t, "rate limit: "+reason, got.Error.Message)
			assert.Equal(t, reason, got.Error.Data["reason"])

			retryAfter, ok := got.Error.Data["retry_after"].(float64)
			require.True(t, ok, "retry_after is a number of seconds: %v", got.Error.Data)
			assert.Equal(t, rec.Header().Get("Retry-After"), strconv.Itoa(int(retryAfter)),
				"the header and the body tell the same wait")
		})
	}
}

// What the budget looks like is in the data of a budget denial, in the words a
// person would use.
func TestRefusalCarriesTheBudget(t *testing.T) {
	l := newLimiter(t, Config{CostBudgetPerHour: time.Minute})
	h := l.Middleware(http.HandlerFunc(spendAll), embedlog.Logger{})
	require.Equal(t, http.StatusOK, post(h, toolCall).Code)

	var got rpcAnswer
	require.NoError(t, json.Unmarshal(post(h, toolCall).Body.Bytes(), &got))
	assert.Equal(t, "2m", got.Error.Data["budget_used"])
	assert.Equal(t, "1m", got.Error.Data["budget_limit"])
	assert.Equal(t, "1h", got.Error.Data["window"])
	assert.InDelta(t, 3600, got.Error.Data["retry_after"], 5, "the window opened a moment ago")
}

// A limiter without a budget has no budget to report.
func TestRefusalWithoutBudget(t *testing.T) {
	l := newLimiter(t, Config{PerUserRPM: 1})
	h := l.Middleware(http.HandlerFunc(okHandler), embedlog.Logger{})
	require.Equal(t, http.StatusOK, post(h, toolCall).Code)

	var got rpcAnswer
	require.NoError(t, json.Unmarshal(post(h, toolCall).Body.Bytes(), &got))
	assert.NotContains(t, got.Error.Data, "budget_used")
	assert.NotContains(t, got.Error.Data, "window")
}

// An id is echoed as it arrived: a string stays a string.
func TestRefusalEchoesAStringID(t *testing.T) {
	l := newLimiter(t, Config{PerUserRPM: 1})
	h := l.Middleware(http.HandlerFunc(okHandler), embedlog.Logger{})
	require.Equal(t, http.StatusOK, post(h, toolCall).Code)

	var got rpcAnswer
	require.NoError(t, json.Unmarshal(post(h, `{"jsonrpc":"2.0","id":"a-7","method":"ping"}`).Body.Bytes(), &got))
	assert.JSONEq(t, `"a-7"`, string(got.ID))
}

// Without an id there is nothing to answer, and the denial is the plain 429 it
// always was — with the honest Retry-After all the same.
func TestRefusalWithoutAnIDIsPlain(t *testing.T) {
	bodies := map[string]string{
		"not json":     `rate me`,
		"a batch":      `[` + toolCall + `]`,
		"notification": `{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		"null id":      `{"jsonrpc":"2.0","id":null,"method":"ping"}`,
		"too big":      `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"` + strings.Repeat("x", maxRefusalPeekBytes) + `"}}`,
		"empty":        ``,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			l := newLimiter(t, Config{PerUserConcurrent: 1})
			release, _ := l.acquire(anonymousUser, time.Now(), false)
			require.NotNil(t, release)
			defer release(charge{})

			rec := post(l.Middleware(http.HandlerFunc(okHandler), embedlog.Logger{}), body)
			assert.Equal(t, http.StatusTooManyRequests, rec.Code)
			assert.Contains(t, rec.Header().Get("Content-Type"), "text/plain")
			assert.Equal(t, "rate limit: "+reasonUserConcurrent+"\n", rec.Body.String())
			assert.Equal(t, "1", rec.Header().Get("Retry-After"))
		})
	}
}

// A refusal reads only as much of a body as an honest call takes: shedding
// load must not cost what serving it would.
func TestRefusalReadsLittleOfTheBody(t *testing.T) {
	l := newLimiter(t, Config{PerUserConcurrent: 1})
	release, _ := l.acquire(anonymousUser, time.Now(), false)
	require.NotNil(t, release)
	defer release(charge{})

	body := &countingReader{r: strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"` + strings.Repeat("x", maxPeekBytes) + `"}}`)}
	rec := httptest.NewRecorder()
	l.Middleware(http.HandlerFunc(okHandler), embedlog.Logger{}).
		ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", body))
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.LessOrEqual(t, body.n, maxRefusalPeekBytes+1)
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// Whatever the limiter reads of a body, the handler behind reads all of it —
// including the part past what the limiter was willing to read.
func TestPeekPutsTheBodyBack(t *testing.T) {
	bodies := map[string]string{
		"a call":  toolCall,
		"too big": `{"jsonrpc":"2.0","id":1,"params":{"pad":"` + strings.Repeat("x", maxPeekBytes) + `"}}`,
		"garbage": `rate me`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
			peek(r, maxPeekBytes)
			rest, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			assert.Equal(t, body, string(rest))
			assert.NoError(t, r.Body.Close())
		})
	}
}

func TestPeekReadsTheCall(t *testing.T) {
	tests := map[string]struct {
		body string
		want call
	}{
		"tools/call": {toolCall, call{id: json.RawMessage("7"), method: "tools/call", name: "api_call"}},
		"prompts/get": {`{"jsonrpc":"2.0","id":"p","method":"prompts/get","params":{"name":"triage"}}`,
			call{id: json.RawMessage(`"p"`), method: "prompts/get", name: "triage"}},
		"resources/read": {`{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"doc://help"}}`,
			call{id: json.RawMessage("2"), method: "resources/read", name: "doc://help"}},
		"no name": {`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`, call{id: json.RawMessage("3"), method: "tools/list"}},
		"notification": {`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
			call{method: "notifications/initialized"}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, ok := peek(httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(tc.body)), maxPeekBytes)
			require.True(t, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

// The budget comes back when its window rolls, and the caller is told exactly
// when that is — not ten seconds, after which it would be refused for another
// fifty minutes.
func TestRetryAfterCostBudget(t *testing.T) {
	l := newLimiter(t, Config{CostBudgetPerHour: 5 * time.Minute})
	opened := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	release, _ := l.acquire("alice", opened, false)
	require.NotNil(t, release)
	release(charge{work: 5 * time.Minute, units: 1})

	at := opened.Add(5 * time.Minute)
	denied, reason := l.acquire("alice", at, false)
	require.Nil(t, denied)
	require.Equal(t, reasonCostBudget, reason)

	rf := l.refusalFor("alice", reason, at)
	assert.Equal(t, 55*time.Minute, rf.retryAfter)
	assert.Equal(t, 3300, rf.retryAfterSeconds())

	denied, reason = l.acquire("alice", at.Add(rf.retryAfter-time.Nanosecond), false)
	assert.Nil(t, denied, "a moment early is still refused")
	assert.Equal(t, reasonCostBudget, reason)

	release, reason = l.acquire("alice", at.Add(rf.retryAfter), false)
	require.NotNilf(t, release, "on the dot, the window has rolled: %s", reason)
	release(charge{})
}

// The wait for a rate token is when the next one lands, and asking for it does
// not take it.
func TestRetryAfterRPMSpendsNothing(t *testing.T) {
	l := newLimiter(t, Config{PerUserRPM: 60})
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for range 60 {
		release, _ := l.acquire("alice", now, false)
		require.NotNil(t, release)
		release(charge{})
	}
	denied, reason := l.acquire("alice", now, false)
	require.Nil(t, denied)
	require.Equal(t, reasonRPM, reason)

	rf := l.refusalFor("alice", reason, now)
	assert.Equal(t, time.Second, rf.retryAfter, "60 RPM is a token a second")
	assert.Equal(t, rf, l.refusalFor("alice", reason, now), "asking twice does not move the wait")

	release, reason := l.acquire("alice", now.Add(rf.retryAfter), false)
	require.NotNilf(t, release, "the token the refusal measured is still there: %s", reason)
	release(charge{})
}

func TestRetryAfterConcurrency(t *testing.T) {
	l := newLimiter(t, Config{PerUserConcurrent: 1, GlobalConcurrent: 1})
	now := time.Now()
	release, _ := l.acquire("alice", now, false)
	require.NotNil(t, release)
	defer release(charge{})

	_, reason := l.acquire("alice", now, false)
	require.Equal(t, reasonUserConcurrent, reason)
	assert.Equal(t, time.Second, l.refusalFor("alice", reason, now).retryAfter)

	_, reason = l.acquire("bob", now, false)
	require.Equal(t, reasonGlobalConcurrent, reason)
	assert.Equal(t, time.Second, l.refusalFor("bob", reason, now).retryAfter)
}

func TestRetryAfterSeconds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		d    time.Duration
		want int
	}{
		{0, 1},
		{time.Millisecond, 1},
		{time.Second, 1},
		{time.Second + 1, 2},
		{1200 * time.Millisecond, 2},
		{55 * time.Minute, 3300},
	}
	for _, tc := range tests {
		assert.Equalf(t, tc.want, refusal{retryAfter: tc.d}.retryAfterSeconds(), "%s", tc.d)
	}
}

func TestFormatDuration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		d    time.Duration
		want string
	}{
		{0, "0s"},
		{100 * time.Millisecond, "100ms"},
		{5 * time.Minute, "5m"},
		{5*time.Minute + 2*time.Second, "5m2s"},
		{5*time.Minute + 2400*time.Millisecond, "5m2s"},
		{20 * time.Minute, "20m"},
		{time.Hour, "1h"},
		{time.Hour + 5*time.Minute, "1h5m"},
		{time.Hour + 5*time.Second, "1h0m5s"},
	}
	for _, tc := range tests {
		assert.Equalf(t, tc.want, formatDuration(tc.d), "%s", tc.d)
	}
}

// A key the limiter reads, repeated, is read differently by the dispatcher:
// first wins here, last wins in encoding/json, which also ignores case. Such a
// body is not read at all.
// A repeat anywhere the limiter does not look is none of its business.
func TestPeekRefusesARepeatedKey(t *testing.T) {
	repeats := map[string]string{
		"name":   `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"help","name":"db_query"}}`,
		"params": `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"help"},"params":{"name":"db_query"}}`,
		"method": `{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call","params":{"name":"db_query"}}`,
		"uri":    `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"doc://help","uri":"doc://secret"}}`,
		// Folded as encoding/json folds them: one member to the dispatcher.
		"Name":   `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"help","Name":"db_query"}}`,
		"Params": `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"help"},"Params":{"name":"db_query"}}`,
		"paramſ": `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"help"},"paramſ":{"name":"db_query"}}`,
		"Method": `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"help","name":"db_query"},"Method":"tools.call"}`,
	}
	for name, body := range repeats {
		t.Run(name, func(t *testing.T) {
			_, ok := peek(httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body)), maxPeekBytes)
			assert.False(t, ok)
		})
	}

	t.Run("elsewhere", func(t *testing.T) {
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"help","arguments":{"q":1,"q":2}}}`
		c, ok := peek(httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body)), maxPeekBytes)
		require.True(t, ok)
		assert.Equal(t, "help", c.name)
	})
}

// Whoever is on call reads the wait and the spend in the log line, without
// asking the caller what they were told.
func TestRefusalLogArgs(t *testing.T) {
	t.Parallel()
	spent := refusal{
		reason:     reasonCostBudget,
		retryAfter: 55 * time.Minute,
		budget:     &Budget{Used: 21 * time.Minute, Limit: 20 * time.Minute},
	}
	assert.Equal(t, []any{"user", "alice", "reason", reasonCostBudget, "retry_after", 3300, "budget_used", "21m"},
		spent.logArgs("alice"))

	rate := refusal{reason: reasonRPM, retryAfter: time.Second}
	assert.Equal(t, []any{"user", "alice", "reason", reasonRPM, "retry_after", 1}, rate.logArgs("alice"))
}
