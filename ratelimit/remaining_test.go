package ratelimit

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

// What Remaining reports is what a refusal reports: one number, read from one
// place, whichever way the caller learns it.
func TestRemainingAgreesWithTheRefusal(t *testing.T) {
	var (
		seen Budget
		ok   bool
	)
	l := newLimiter(t, Config{CostBudgetPerHour: time.Minute, Exempt: exemptHelp})
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), `"help"`) {
			seen, ok = Remaining(r.Context())
		} else {
			Charge(r.Context(), 90*time.Second)
		}
		w.WriteHeader(http.StatusOK)
	}), embedlog.Logger{})

	before := time.Now()
	require.Equal(t, http.StatusOK, post(h, toolCall).Code)

	var refused rpcAnswer
	require.NoError(t, json.Unmarshal(post(h, toolCall).Body.Bytes(), &refused))
	require.Equal(t, reasonCostBudget, refused.Error.Data["reason"])

	require.Equal(t, http.StatusOK, post(h, helpCall).Code)
	require.True(t, ok)
	assert.Equal(t, refused.Error.Data["budget_used"], formatDuration(seen.Used))
	assert.Equal(t, refused.Error.Data["budget_limit"], formatDuration(seen.Limit))
	assert.Equal(t, 90*time.Second, seen.Used)
	assert.Equal(t, time.Minute, seen.Limit)
	assert.Zero(t, seen.Left(), "overspent is nothing left, not a negative")
	assert.WithinRange(t, seen.ResetAt, before.Add(budgetWindow), time.Now().Add(budgetWindow))
}

// A running request sees its own charges as it makes them; the next one sees
// them settled.
func TestRemainingCountsThisRequest(t *testing.T) {
	var used []time.Duration
	l := newLimiter(t, Config{CostBudgetPerHour: time.Hour})
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for range 2 {
			b, ok := Remaining(r.Context())
			assert.True(t, ok)
			used = append(used, b.Used)
			Charge(r.Context(), 10*time.Second)
		}
		w.WriteHeader(http.StatusOK)
	}), embedlog.Logger{})

	post(h, toolCall)
	post(h, toolCall)
	assert.Equal(t, []time.Duration{0, 10 * time.Second, 20 * time.Second, 30 * time.Second}, used)
}

// An exempt call spends nothing, so what it charges is not shown as spent.
func TestRemainingLeavesOutAnExemptCall(t *testing.T) {
	var seen Budget
	l := newLimiter(t, Config{CostBudgetPerHour: time.Hour, Exempt: exemptHelp})
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Charge(r.Context(), 10*time.Second)
		seen, _ = Remaining(r.Context())
		w.WriteHeader(http.StatusOK)
	}), embedlog.Logger{})

	post(h, helpCall)
	assert.Zero(t, seen.Used)
	post(h, toolCall)
	assert.Equal(t, 10*time.Second, seen.Used, "the help call before it left nothing behind")
}

// No budget, nothing to report — and a context that never went through the
// middleware has no caller to report on.
func TestRemainingWithoutABudget(t *testing.T) {
	ok := true
	l := newLimiter(t, Config{PerUserRPM: 10})
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok = Remaining(r.Context())
		w.WriteHeader(http.StatusOK)
	}), embedlog.Logger{})
	post(h, toolCall)
	assert.False(t, ok, "the budget is off")

	_, ok = Remaining(context.Background())
	assert.False(t, ok, "no middleware")

	ctx, _ := WithCost(context.Background())
	_, ok = Remaining(ctx)
	assert.False(t, ok, "an accumulator of its own, and no caller behind it")
}

func TestBudgetLeft(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 15*time.Second, Budget{Used: 45 * time.Second, Limit: time.Minute}.Left())
	assert.Zero(t, Budget{Used: 90 * time.Second, Limit: time.Minute}.Left())
}

// A window that is over is empty before the caller comes back to roll it:
// what a request still running charges lands in the old window and goes with
// it, and the next window ends no earlier than an hour from now.
func TestRemainingOnceTheWindowIsOver(t *testing.T) {
	l := newLimiter(t, Config{CostBudgetPerHour: time.Hour})
	opened := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	release, _ := l.acquire("alice", opened, false)
	require.NotNil(t, release)
	release(charge{work: 90 * time.Second, units: 1})

	b, ok := l.budget("alice", 5*time.Second, opened.Add(30*time.Minute))
	require.True(t, ok)
	assert.Equal(t, 95*time.Second, b.Used, "finished plus running")
	assert.Equal(t, opened.Add(budgetWindow), b.ResetAt)

	over := opened.Add(budgetWindow)
	b, ok = l.budget("alice", 5*time.Second, over)
	require.True(t, ok)
	assert.Zero(t, b.Used)
	assert.Equal(t, time.Hour, b.Left())
	assert.Equal(t, over.Add(budgetWindow), b.ResetAt)
}
