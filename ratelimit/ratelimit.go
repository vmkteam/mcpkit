// Package ratelimit is the gate in front of an MCP endpoint: request rate,
// concurrency and an hourly work budget, all per caller.
//
// Everything is in memory and resets with the process. This is a limiter
// against a client that lost its mind, not a billing quota — a quota would
// need a store that survives a restart and a window that does not.
//
// The caller is Principal.UserID from the request context, so the limiter has
// to run inside the authentication middleware; outside it every caller is
// anonymous and the per-user limit means nothing.
package ratelimit

import (
	"net/http"
	"sync"
	"time"

	"github.com/vmkteam/mcpkit/auth"

	"github.com/vmkteam/embedlog"
	"golang.org/x/time/rate"
)

// anonymousUser is the bucket every unauthenticated caller shares. Collapsing
// them into one is deliberate: a dev server without authentication should not
// hand out unlimited capacity by the number of connections.
const anonymousUser = "anonymous"

// idleTTL is how long an entry can be idle (no acquire) before it is evicted.
// Two cost-budget windows, so even a user who silently hit the budget is
// reaped, without churning entries of live users.
const idleTTL = 2 * time.Hour

// evictEvery is how often the eviction loop runs.
const evictEvery = 15 * time.Minute

// Config is the set of limits. Each one is switched off by a value ≤ 0, and
// all four off means Disabled: Middleware then returns the handler unwrapped.
type Config struct {
	PerUserRPM        int
	PerUserConcurrent int
	GlobalConcurrent  int
	CostBudgetPerHour time.Duration
}

type entry struct {
	rpm *rate.Limiter
	sem chan struct{}
	// inflight counts the requests this entry is currently serving. It is not
	// len(sem): with PerUserConcurrent switched off sem is nil, len(nil) is 0,
	// and eviction would then drop an entry out from under a request that is
	// still running — taking its hourly budget with it.
	inflight int
	used     time.Duration
	resetAt  time.Time
	lastSeen time.Time
}

// Limiter enforces Config across callers.
type Limiter struct {
	cfg     Config
	mu      sync.Mutex
	entries map[string]*entry
	global  chan struct{}

	stop     chan struct{}
	stopOnce sync.Once
}

// New returns a limiter and, unless it is disabled, starts the goroutine that
// evicts idle entries. Call Stop when done — in tests especially, where the
// goroutine would otherwise outlive the test.
func New(cfg Config) *Limiter {
	l := &Limiter{cfg: cfg, entries: map[string]*entry{}, stop: make(chan struct{})}
	if cfg.GlobalConcurrent > 0 {
		l.global = make(chan struct{}, cfg.GlobalConcurrent)
	}
	if !l.Disabled() {
		registerMetrics()
		go l.evictLoop(evictEvery)
	}
	return l
}

// Disabled reports whether every limit is switched off.
func (l *Limiter) Disabled() bool {
	c := l.cfg
	return c.PerUserRPM <= 0 && c.PerUserConcurrent <= 0 && c.GlobalConcurrent <= 0 && c.CostBudgetPerHour <= 0
}

// Stop terminates the eviction goroutine. Idempotent.
func (l *Limiter) Stop() {
	// sync.Once, not a select on the channel: the select reads and closes in two
	// steps, so two goroutines both saw it open and both closed it — and closing
	// a closed channel panics. A service that calls Stop from a shutdown path
	// and from a defer, which this doc invites, took the process down with it.
	l.stopOnce.Do(func() { close(l.stop) })
}

// Middleware gates the wrapped handler. It must sit inside the authentication
// middleware: the key of the bucket is Principal.UserID, and outside auth
// there is no principal to read.
func (l *Limiter) Middleware(next http.Handler, logger embedlog.Logger) http.Handler {
	if l.Disabled() {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only POST does real work in Streamable HTTP. GET is the listening
		// stream — a long-lived connection that would otherwise hold a
		// concurrency slot for the bridge's whole lifetime, and whose
		// reconnects would drain the RPM bucket; DELETE is session teardown.
		// Both are gated by authentication above and cost nothing.
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}
		userID := anonymousUser
		if p, ok := auth.PrincipalFromContext(r.Context()); ok && p.UserID != "" {
			userID = p.UserID
		}
		release, reason := l.acquire(userID, time.Now())
		if release == nil {
			logger.Error(r.Context(), "mcp rate limit", "user", userID, "reason", reason)
			w.Header().Set("Retry-After", "10")
			http.Error(w, "rate limit: "+reason, http.StatusTooManyRequests)
			return
		}
		// The handler prices itself through the accumulator; the wall clock is
		// only the fallback for a request that did no billable work of its own.
		ctx, cost := WithCost(r.Context())
		start := time.Now()
		defer func() { release(cost.settle(time.Since(start))) }()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (l *Limiter) evictLoop(every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case now := <-t.C:
			l.evictIdle(now)
		}
	}
}

// evictIdle drops entries idle longer than idleTTL that are serving nothing.
// Idempotent — safe to call from tests.
func (l *Limiter) evictIdle(now time.Time) {
	cutoff := now.Add(-idleTTL)
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, e := range l.entries {
		if e.lastSeen.Before(cutoff) && e.inflight == 0 {
			delete(l.entries, k)
		}
	}
}

// entryFor returns this user's bucket, creating it on first sight, and reports
// the cost budget if it is already spent.
//
// The budget is read here, before anything else is taken: it is a comparison,
// and a call refused by it should cost nothing.
func (l *Limiter) entryFor(userID string, now time.Time) (e *entry, reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	e, ok := l.entries[userID]
	if !ok {
		e = &entry{resetAt: now.Add(time.Hour)}
		if l.cfg.PerUserRPM > 0 {
			e.rpm = rate.NewLimiter(rate.Limit(float64(l.cfg.PerUserRPM)/60.0), maxBurst(l.cfg.PerUserRPM))
		}
		if l.cfg.PerUserConcurrent > 0 {
			e.sem = make(chan struct{}, l.cfg.PerUserConcurrent)
		}
		l.entries[userID] = e
	}
	// Roll the cost-budget window first, so a user who comes back after an hour
	// of being rpm-throttled gets the budget reset instead of the stale `used`.
	if now.After(e.resetAt) {
		e.used = 0
		e.resetAt = now.Add(time.Hour)
	}
	e.lastSeen = now
	if l.cfg.CostBudgetPerHour > 0 && e.used >= l.cfg.CostBudgetPerHour {
		return e, reasonCostBudget
	}
	return e, ""
}

// takeSlots takes the two concurrency slots and then one rate token, giving
// back whatever was already taken when a later limit refuses.
//
// The order is the point. A slot taken and given back costs the caller nothing,
// so a refusal by either semaphore is free; the rate bucket goes last because a
// token is the one thing that does not come back. Spending it first meant a
// burst of parallel calls paid RPM for every request the concurrency limit had
// already turned away, and the caller was throttled for work the server never
// did.
func (l *Limiter) takeSlots(e *entry, now time.Time) (reason string) {
	if e.sem != nil {
		select {
		case e.sem <- struct{}{}:
		default:
			return reasonUserConcurrent
		}
	}
	if l.global != nil {
		select {
		case l.global <- struct{}{}:
		default:
			if e.sem != nil {
				<-e.sem
			}
			return reasonGlobalConcurrent
		}
	}
	if e.rpm != nil && !e.rpm.AllowN(now, 1) {
		if l.global != nil {
			<-l.global
		}
		if e.sem != nil {
			<-e.sem
		}
		return reasonRPM
	}
	return ""
}

// acquire reserves the slot. release is non-nil iff reason == "" (allowed).
func (l *Limiter) acquire(userID string, now time.Time) (release func(charge), reason string) {
	e, reason := l.entryFor(userID, now)
	if reason != "" {
		metric().WithLabelValues(reason).Inc()
		return nil, reason
	}
	if reason := l.takeSlots(e, now); reason != "" {
		metric().WithLabelValues(reason).Inc()
		return nil, reason
	}

	l.mu.Lock()
	e.inflight++
	l.mu.Unlock()

	inflight().WithLabelValues(scopeUser).Inc()
	if l.global != nil {
		inflight().WithLabelValues(scopeGlobal).Inc()
	}

	return func(c charge) {
		if e.sem != nil {
			<-e.sem
		}
		if l.global != nil {
			<-l.global
			inflight().WithLabelValues(scopeGlobal).Dec()
		}
		inflight().WithLabelValues(scopeUser).Dec()
		l.mu.Lock()
		e.inflight--
		if l.cfg.CostBudgetPerHour > 0 {
			e.used += c.work
		}
		l.mu.Unlock()
		// acquire spent one token before the work was known; a request that
		// turned out to carry several calls pays the rest here. ReserveN rather
		// than AllowN: the work is already done, so the tokens have to come out
		// of the bucket even when that leaves it empty — which is what
		// throttles the next call instead of letting twenty calls cost the same
		// as one.
		//
		// Priced at `now`, the instant acquire admitted the call, not at
		// release: the bucket refills while the work runs, and charging at the
		// later instant would refund a slow request part of what it just spent.
		//
		// In burst-sized steps, because ReserveN refuses outright when n is over
		// the bucket's burst and silently charges nothing: a limiter configured
		// at 10 RPM would otherwise let twenty calls through free, which is the
		// exact case this accounting exists for.
		if e.rpm != nil && c.units > 1 {
			for left := c.units - 1; left > 0; {
				step := min(left, e.rpm.Burst())
				e.rpm.ReserveN(now, step)
				left -= step
			}
		}
	}, ""
}

func maxBurst(rpm int) int {
	if rpm < 1 {
		return 1
	}
	return rpm
}
