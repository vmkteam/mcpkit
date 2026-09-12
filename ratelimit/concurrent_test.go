package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vmkteam/mcpkit/auth"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

// The tests in this file are the ones that need `go test -race` to mean
// anything: a limiter is a shared mutable map plus two semaphores, and every
// claim the package makes about it is a claim about several goroutines at once.

// GlobalConcurrent is a promise about a number that is never exceeded, and the
// only way to break it is from several goroutines. The handler holds its slot
// until the test lets it go, so the peak is observed rather than inferred.
func TestGlobalConcurrentIsNeverExceeded(t *testing.T) {
	const (
		limit   = 4
		callers = 16
	)
	l := newLimiter(t, Config{GlobalConcurrent: limit})

	var (
		mu      sync.Mutex
		current int
		peak    int
	)
	gate := make(chan struct{})
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		current++
		if current > peak {
			peak = current
		}
		mu.Unlock()

		<-gate

		mu.Lock()
		current--
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}), embedlog.Logger{})

	var (
		wg       sync.WaitGroup
		accepted atomic.Int64
		denied   atomic.Int64
	)
	for i := range callers {
		wg.Go(func() {
			req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
			req = req.WithContext(auth.NewContext(req.Context(), auth.Principal{
				UserID: "user-" + string(rune('a'+i)),
			}))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code == http.StatusTooManyRequests {
				denied.Add(1)
				return
			}
			accepted.Add(1)
		})
	}

	// Let the denials land, then release everyone still holding a slot.
	assert.Eventually(t, func() bool {
		return accepted.Load()+denied.Load() >= callers-limit
	}, 5*time.Second, time.Millisecond)
	close(gate)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	assert.LessOrEqual(t, peak, limit, "more requests were inside the handler than GlobalConcurrent allows")
	assert.Positive(t, denied.Load(), "with four slots and sixteen callers something must be refused")
	assert.Equal(t, int64(callers), accepted.Load()+denied.Load())
}

// Charge is documented as safe to call concurrently, which is exactly the kind
// of claim that is true until it is not.
func TestChargeIsSafeUnderConcurrency(t *testing.T) {
	t.Parallel()
	const (
		goroutines = 8
		perRoutine = 250
	)
	ctx, cost := WithCost(t.Context())

	var wg sync.WaitGroup
	for range goroutines {
		wg.Go(func() {
			for range perRoutine {
				Charge(ctx, time.Millisecond)
			}
		})
	}
	wg.Wait()

	c := cost.settle(time.Hour)
	assert.Equal(t, goroutines*perRoutine, c.units, "every charge must be counted exactly once")
	assert.Equal(t, time.Duration(goroutines*perRoutine)*time.Millisecond, c.work)
}

// The per-user semaphore has to hold under parallel requests from one caller,
// and the slots have to come back: a leak shows up as a limiter that answers
// 429 forever once the burst is over.
func TestPerUserConcurrentReleasesEverySlot(t *testing.T) {
	const (
		limit = 2
		burst = 12
	)
	l := newLimiter(t, Config{PerUserConcurrent: limit})

	var inside atomic.Int64
	var peak atomic.Int64
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := inside.Add(1)
		for {
			old := peak.Load()
			if n <= old || peak.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(time.Millisecond)
		inside.Add(-1)
		w.WriteHeader(http.StatusOK)
	}), embedlog.Logger{})

	call := func() int {
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
		req = req.WithContext(auth.NewContext(req.Context(), auth.Principal{UserID: "alice"}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	var wg sync.WaitGroup
	for range burst {
		wg.Go(func() { call() })
	}
	wg.Wait()

	assert.LessOrEqual(t, peak.Load(), int64(limit), "PerUserConcurrent exceeded")

	// Every slot came back: the next request is served, not refused.
	assert.Equal(t, http.StatusOK, call(), "a slot was leaked — the caller is throttled forever")

	l.mu.Lock()
	defer l.mu.Unlock()
	assert.Zero(t, l.entries["alice"].inflight, "inflight must settle back to zero")
}

// Two callers hitting one limiter create the entry for their own bucket at the
// same time as the eviction loop walks the map.
func TestAcquireAndEvictRunTogether(t *testing.T) {
	l := newLimiter(t, Config{PerUserRPM: 6000, CostBudgetPerHour: time.Hour})

	stop := make(chan struct{})
	var evictor sync.WaitGroup
	evictor.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				l.evictIdle(time.Now())
			}
		}
	})

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			user := "user-" + string(rune('a'+i))
			for range 100 {
				release, reason := l.acquire(user, time.Now())
				if release == nil {
					require.NotEmpty(t, reason)
					continue
				}
				release(charge{work: time.Microsecond, units: 1})
			}
		})
	}
	wg.Wait()
	close(stop)
	evictor.Wait()
}

// An entry serving a request must survive eviction even when PerUserConcurrent
// is off: sem is nil then, len(nil) is 0, and the old check read that as idle.
func TestEvictSkipsBusyWithoutAConcurrencyLimit(t *testing.T) {
	t.Parallel()
	l := newLimiter(t, Config{CostBudgetPerHour: time.Hour})
	now := time.Now()

	release, reason := l.acquire("alice", now)
	require.NotNil(t, release, reason)

	l.evictIdle(now.Add(idleTTL + time.Hour))
	require.Contains(t, l.entries, "alice",
		"an entry with a request in flight was evicted; its hourly budget goes with it")

	// The charge lands on the entry that is still there, not on an orphan.
	release(charge{work: 30 * time.Minute, units: 1})
	l.mu.Lock()
	used := l.entries["alice"].used
	l.mu.Unlock()
	assert.Equal(t, 30*time.Minute, used, "the budget of a live entry must record the work")

	l.evictIdle(now.Add(idleTTL + time.Hour))
	assert.NotContains(t, l.entries, "alice", "once released it is idle and goes")
}
