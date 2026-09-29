package ratelimit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/vmkteam/mcpkit/auth"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

func newLimiter(t *testing.T, cfg Config) *Limiter {
	t.Helper()
	l := New(cfg)
	t.Cleanup(l.Stop)
	return l
}

func TestRPM(t *testing.T) {
	l := newLimiter(t, Config{PerUserRPM: 60})
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for i := range 60 {
		release, reason := l.acquire("alice", now, false)
		require.NotNilf(t, release, "call %d denied: %s", i, reason)
		release(charge{})
	}
	release, reason := l.acquire("alice", now, false)
	assert.Nil(t, release, "61st call should be denied")
	assert.Equal(t, reasonRPM, reason)

	// Other users are independent.
	release, reason = l.acquire("bob", now, false)
	require.NotNilf(t, release, "bob blocked by alice's bucket: %s", reason)
	release(charge{})
}

func TestPerUserConcurrent(t *testing.T) {
	l := newLimiter(t, Config{PerUserConcurrent: 2})
	now := time.Now()
	r1, _ := l.acquire("alice", now, false)
	r2, _ := l.acquire("alice", now, false)
	require.NotNil(t, r1)
	require.NotNil(t, r2)

	r3, reason := l.acquire("alice", now, false)
	assert.Nil(t, r3, "third should be denied")
	assert.Equal(t, reasonUserConcurrent, reason)

	r1(charge{})
	r3, _ = l.acquire("alice", now, false)
	require.NotNil(t, r3, "after release, slot should reopen")
	r3(charge{})
	r2(charge{})
}

func TestGlobalConcurrent(t *testing.T) {
	l := newLimiter(t, Config{GlobalConcurrent: 1})
	now := time.Now()
	r1, _ := l.acquire("alice", now, false)
	require.NotNil(t, r1, "alice should pass")

	r2, reason := l.acquire("bob", now, false)
	assert.Nil(t, r2, "bob should hit global")
	assert.Equal(t, reasonGlobalConcurrent, reason)

	r1(charge{})
	r2, _ = l.acquire("bob", now, false)
	require.NotNil(t, r2, "after release, bob should pass")
	r2(charge{})
}

// The user slot taken on the way to a full global semaphore has to come back,
// or one global denial costs the user a slot forever.
func TestGlobalDenialReturnsTheUserSlot(t *testing.T) {
	l := newLimiter(t, Config{PerUserConcurrent: 1, GlobalConcurrent: 1})
	now := time.Now()

	held, _ := l.acquire("alice", now, false)
	require.NotNil(t, held)

	denied, reason := l.acquire("bob", now, false)
	require.Nil(t, denied)
	require.Equal(t, reasonGlobalConcurrent, reason)

	held(charge{})
	r, reason := l.acquire("bob", now, false)
	require.NotNilf(t, r, "bob's own slot was never returned: %s", reason)
	r(charge{})
}

func TestCostBudget(t *testing.T) {
	l := newLimiter(t, Config{CostBudgetPerHour: 100 * time.Millisecond})
	now := time.Now()
	r, _ := l.acquire("alice", now, false)
	r(charge{work: 60 * time.Millisecond, units: 1})
	r, _ = l.acquire("alice", now, false)
	r(charge{work: 50 * time.Millisecond, units: 1})

	r2, reason := l.acquire("alice", now, false)
	assert.Nil(t, r2, "expected cost budget denial")
	assert.Equal(t, reasonCostBudget, reason)

	// After hour rollover the budget resets.
	r3, _ := l.acquire("alice", now.Add(time.Hour+time.Minute), false)
	require.NotNil(t, r3, "budget didn't reset after hour")
	r3(charge{})
}

// One POST can carry N calls. acquire prices it as one before the work is
// known, and release pays the rest — without that, twenty parallel upstream
// calls would cost one token and the longest of them, and both limits would
// mean N times less than they say.
func TestChargePerItem(t *testing.T) {
	t.Run("rpm counts every item", func(t *testing.T) {
		l := newLimiter(t, Config{PerUserRPM: 60})
		now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
		l.clock = func() time.Time { return now }
		for range 3 {
			release, reason := l.acquire("alice", now, false)
			require.NotNilf(t, release, "denied too early: %s", reason)
			release(charge{work: time.Second, units: 20})
		}
		release, reason := l.acquire("alice", now, false)
		assert.Nil(t, release, "three requests of twenty calls are sixty, the bucket is empty")
		assert.Equal(t, reasonRPM, reason)
	})

	// ReserveN charges nothing at all when asked for more than the burst, so a
	// request bigger than the whole per-minute allowance is paid in steps.
	t.Run("more calls than the burst is still paid", func(t *testing.T) {
		l := newLimiter(t, Config{PerUserRPM: 10})
		now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
		l.clock = func() time.Time { return now }
		release, _ := l.acquire("alice", now, false)
		require.NotNil(t, release)
		release(charge{work: time.Second, units: 20})

		next, reason := l.acquire("alice", now, false)
		assert.Nil(t, next, "twenty calls on a 10 RPM limiter must leave the bucket empty")
		assert.Equal(t, reasonRPM, reason)
	})

	// The budget is the work the server did, not the time the client waited.
	t.Run("budget counts the sum, not the wall clock", func(t *testing.T) {
		l := newLimiter(t, Config{CostBudgetPerHour: 100 * time.Millisecond})
		now := time.Now()
		release, _ := l.acquire("alice", now, false)
		require.NotNil(t, release)
		release(charge{work: 120 * time.Millisecond, units: 4})

		next, reason := l.acquire("alice", now, false)
		assert.Nil(t, next, "four 30ms calls in one request spend 120ms, not the 30ms they took")
		assert.Equal(t, reasonCostBudget, reason)
	})
}

// The rest of a slow request's calls is priced when it finishes. Priced at the
// instant it was admitted, the bucket's clock went back over everything
// admitted meanwhile, and the next caller was handed those seconds again.
func TestSlowRequestDoesNotRefundItself(t *testing.T) {
	l := newLimiter(t, Config{PerUserRPM: 60}) // a token a second
	opened := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for range 60 {
		release, _ := l.acquire("alice", opened, false)
		require.NotNil(t, release)
		release(charge{units: 1})
	}

	slow, _ := l.acquire("alice", opened.Add(time.Second), false)
	require.NotNil(t, slow, "the token that came back in the first second")

	finished := opened.Add(11 * time.Second)
	l.clock = func() time.Time { return finished }
	quick, _ := l.acquire("alice", finished, false)
	require.NotNil(t, quick, "ten more came back while the slow one ran; one of them is spent")
	quick(charge{units: 1})
	slow(charge{units: 11}) // ten more calls than acquire charged for: nine left, minus ten

	next, reason := l.acquire("alice", finished, false)
	assert.Nil(t, next, "the slow request's ten calls were paid for, not refunded")
	assert.Equal(t, reasonRPM, reason)
}

// A request that charges nothing is priced by its wall clock, the way every
// request was before one request could carry many calls.
func TestCostSettleFallsBackToWallClock(t *testing.T) {
	t.Parallel()
	_, cost := WithCost(context.Background())
	got := cost.settle(50 * time.Millisecond)
	assert.Equal(t, charge{work: 50 * time.Millisecond, units: 1}, got)

	ctx, cost := WithCost(context.Background())
	Charge(ctx, 10*time.Millisecond)
	Charge(ctx, 30*time.Millisecond)
	got = cost.settle(15 * time.Millisecond)
	assert.Equal(t, charge{work: 40 * time.Millisecond, units: 2}, got,
		"once anything is charged, the wall clock is not consulted at all")
}

// Charge on a context without an accumulator is a no-op: a handler must not
// have to know whether rate limiting is switched on.
func TestChargeWithoutAccumulator(t *testing.T) {
	t.Parallel()
	assert.NotPanics(t, func() { Charge(context.Background(), time.Second) })
}

func TestEvictIdle(t *testing.T) {
	l := newLimiter(t, Config{PerUserRPM: 60})
	now := time.Now()
	r, _ := l.acquire("alice", now, false)
	r(charge{})
	require.Contains(t, l.entries, "alice")

	// One hour idle is within TTL — must stay.
	l.evictIdle(now.Add(time.Hour))
	assert.Contains(t, l.entries, "alice", "alice evicted within TTL")

	// Past TTL with empty semaphore — must go.
	l.evictIdle(now.Add(idleTTL + time.Minute))
	assert.NotContains(t, l.entries, "alice", "alice not evicted after TTL")
}

func TestEvictSkipsBusy(t *testing.T) {
	l := newLimiter(t, Config{PerUserConcurrent: 1})
	now := time.Now()
	r, _ := l.acquire("alice", now, false)
	require.NotNil(t, r)

	// Don't release — entry holds an in-flight slot.
	l.evictIdle(now.Add(idleTTL + time.Hour))
	assert.Contains(t, l.entries, "alice", "entry with in-flight request must not be evicted")

	r(charge{})
	l.evictIdle(now.Add(idleTTL + time.Hour))
	assert.NotContains(t, l.entries, "alice", "entry should be evicted after release + idle")
}

func TestStopIsIdempotent(t *testing.T) {
	t.Parallel()
	l := New(Config{PerUserRPM: 1})
	assert.NotPanics(t, func() {
		l.Stop()
		l.Stop()
	})
}

// Sequentially idempotent was never the hard case. The check-then-close this
// replaced let two goroutines both observe the channel open and both close it,
// and closing a closed channel panics — so a service calling Stop from a
// shutdown path and from a defer took the process down on the way out.
func TestStopIsIdempotentUnderConcurrency(t *testing.T) {
	t.Parallel()
	l := New(Config{PerUserRPM: 1})

	assert.NotPanics(t, func() {
		var wg sync.WaitGroup
		start := make(chan struct{})
		for range 32 {
			wg.Go(func() {
				<-start // all at once, so the race has a chance to happen
				l.Stop()
			})
		}
		close(start)
		wg.Wait()
	})
}

func TestDisabled(t *testing.T) {
	t.Parallel()
	l := New(Config{})
	assert.True(t, l.Disabled(), "zero config should be Disabled")

	release, reason := l.acquire("anyone", time.Now(), false)
	require.NotNilf(t, release, "disabled limiter should never deny: reason=%q", reason)
	release(charge{})

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	assert.Equal(t, reflect.ValueOf(next).Pointer(), reflect.ValueOf(l.Middleware(next, embedlog.Logger{})).Pointer(),
		"a disabled limiter must not wrap the handler")
}

// The Streamable HTTP listening stream (GET) is a long-lived connection: if the
// middleware counted it, every connected bridge would hold a concurrency slot
// for its whole lifetime and reconnects would drain the RPM bucket. Only POST —
// the requests that do actual work — is limited.
func TestMiddlewareSkipsNonPOST(t *testing.T) {
	l := newLimiter(t, Config{PerUserConcurrent: 1})
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := l.Middleware(next, embedlog.Logger{})

	// Occupy the single concurrency slot.
	release, _ := l.acquire(anonymousUser, time.Now(), false)
	require.NotNil(t, release)
	defer func() { release(charge{}) }()

	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, "/mcp", nil))
		assert.Equalf(t, http.StatusOK, rec.Code, "%s must bypass the limiter", method)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	assert.Equal(t, http.StatusTooManyRequests, rec.Code, "POST must still be limited")
	assert.Equal(t, "1", rec.Header().Get("Retry-After"), "a concurrency slot frees up when a neighbour finishes")
	assert.Contains(t, rec.Body.String(), reasonUserConcurrent)
}

// The bucket is keyed by the principal the auth middleware put in the context.
// Without one everybody shares the anonymous bucket — which is why the limiter
// belongs inside authentication, not outside it.
func TestMiddlewareKeysOnPrincipal(t *testing.T) {
	l := newLimiter(t, Config{PerUserRPM: 1})
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), embedlog.Logger{})

	as := func(userID string) int {
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		if userID != "" {
			req = req.WithContext(auth.NewContext(req.Context(), auth.Principal{UserID: userID}))
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	assert.Equal(t, http.StatusOK, as("alice"))
	assert.Equal(t, http.StatusTooManyRequests, as("alice"), "alice spent her minute")
	assert.Equal(t, http.StatusOK, as("bob"), "bob has his own bucket")
	assert.Equal(t, http.StatusOK, as(""), "and so does everyone without a principal")
	assert.Equal(t, http.StatusTooManyRequests, as(""), "who all share one")
}

// The handler prices itself; the middleware only settles what it reported.
func TestMiddlewareChargesFromTheHandler(t *testing.T) {
	l := newLimiter(t, Config{CostBudgetPerHour: 100 * time.Millisecond})
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Charge(r.Context(), 120*time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}), embedlog.Logger{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	assert.Equal(t, http.StatusTooManyRequests, rec.Code,
		"the 120ms the handler reported spent the hourly budget")
}

// Every reason and scope is published from the start, and the gauge comes back
// to zero once the request that took the slot is done.
func TestMetrics(t *testing.T) {
	registerMetrics()
	assert.Equal(t, 4, testutil.CollectAndCount(deniedTotal), "one series per reason, from the start")
	assert.Equal(t, 2, testutil.CollectAndCount(inflightGauge), "one series per scope, from the start")

	l := newLimiter(t, Config{PerUserConcurrent: 1, GlobalConcurrent: 1})
	before := testutil.ToFloat64(inflightGauge.WithLabelValues(scopeUser))

	release, _ := l.acquire("alice", time.Now(), false)
	require.NotNil(t, release)
	assert.InDelta(t, before+1, testutil.ToFloat64(inflightGauge.WithLabelValues(scopeUser)), 0)

	release(charge{})
	assert.InDelta(t, before, testutil.ToFloat64(inflightGauge.WithLabelValues(scopeUser)), 0)
}
