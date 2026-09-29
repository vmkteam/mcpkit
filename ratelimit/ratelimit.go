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

// budgetWindow is the length of the fixed cost-budget window.
const budgetWindow = time.Hour

// Config is the set of limits. Each one is switched off by a value ≤ 0, and
// all four off means Disabled: Middleware then returns the handler unwrapped.
type Config struct {
	PerUserRPM        int
	PerUserConcurrent int
	GlobalConcurrent  int
	CostBudgetPerHour time.Duration

	// Exempt names the calls the hourly budget does not apply to. They are
	// the cheap ones that teach a caller to spend less — a help tool, a static
	// resource — and without this they are the first to stop answering once
	// the budget is gone. name is what Mcp-Name mirrors: the tool of
	// tools/call, the prompt of prompts/get, the URI of resources/read; empty
	// for any other method.
	//
	// Only the budget. An exempt call still takes a rate token and a
	// concurrency slot, or it would be a hole anything could be pushed through
	// at any rate. Setting it costs a parse of every POST body while the budget
	// is on; nil exempts nothing and reads a body only to answer a refusal.
	Exempt func(method, name string) bool
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

	// clock is time.Now; a test sets it to say when a request finished.
	clock func() time.Time
}

// New returns a limiter and, unless it is disabled, starts the goroutine that
// evicts idle entries. Call Stop when done — in tests especially, where the
// goroutine would otherwise outlive the test.
func New(cfg Config) *Limiter {
	l := &Limiter{cfg: cfg, entries: map[string]*entry{}, stop: make(chan struct{}), clock: time.Now}
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
		// The body is read here when Exempt needs it, and otherwise only to
		// answer a refusal. Exempt is about the budget alone, so with the budget
		// off there is nothing to ask it. A body that cannot be read is not a
		// call anyone could have exempted, so Exempt is never asked about one.
		var (
			c            call
			read, exempt bool
		)
		if l.cfg.Exempt != nil && l.cfg.CostBudgetPerHour > 0 {
			var ok bool
			c, ok = peek(r, maxPeekBytes)
			read, exempt = true, ok && l.cfg.Exempt(c.method, c.name)
		}

		now := l.clock()
		release, reason := l.acquire(userID, now, exempt)
		if release == nil {
			if !read {
				c, _ = peek(r, maxRefusalPeekBytes)
			}
			rf := l.refusalFor(userID, reason, now)
			logger.Error(r.Context(), "mcp rate limit", rf.logArgs(userID)...)
			refuse(w, rf, c.id)
			return
		}
		// The handler prices itself through the accumulator; the wall clock is
		// only the fallback for a request that did no billable work of its own.
		// The accumulator also knows whose budget it is, for Remaining.
		ctx, cost := WithCost(r.Context())
		cost.limiter, cost.userID, cost.exempt = l, userID, exempt
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

// evictIdle drops entries idle longer than idleTTL that are serving nothing,
// and their budget series with them. Idempotent — safe to call from tests.
//
// An entry whose budget window is over but which is not idle enough to go has
// its series put to zero, if it spent anything to have one. The window rolls
// only when the caller comes back, and until then the gauge would go on showing
// the old one — for up to two hours, with an alert on it firing for someone who
// has the whole budget back.
func (l *Limiter) evictIdle(now time.Time) {
	cutoff := now.Add(-idleTTL)
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, e := range l.entries {
		switch {
		case e.lastSeen.Before(cutoff) && e.inflight == 0:
			delete(l.entries, k)
			budgetUsed().DeleteLabelValues(k)
		case e.used > 0 && !now.Before(e.resetAt):
			budgetUsed().WithLabelValues(k).Set(0)
		}
	}
}

// entryFor returns this user's bucket, creating it on first sight, and reports
// the cost budget if it is already spent — unless the call is exempt from it.
//
// The budget is read here, before anything else is taken: it is a comparison,
// and a call refused by it should cost nothing.
func (l *Limiter) entryFor(userID string, now time.Time, exempt bool) (e *entry, reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	e, ok := l.entries[userID]
	if !ok {
		e = &entry{resetAt: now.Add(budgetWindow)}
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
	//
	// At resetAt, not after it: a denial tells the caller to come back in
	// resetAt−now seconds, and one who does so to the nanosecond must find the
	// window rolled.
	if !now.Before(e.resetAt) {
		if e.used > 0 {
			budgetUsed().WithLabelValues(userID).Set(0)
		}
		e.used = 0
		e.resetAt = now.Add(budgetWindow)
	}
	e.lastSeen = now
	if !exempt && l.cfg.CostBudgetPerHour > 0 && e.used >= l.cfg.CostBudgetPerHour {
		return e, reasonCostBudget
	}
	return e, ""
}

// budget is userID's budget at now with own added to what is already spent —
// the part of a running request that release has not paid in yet. ok is false
// with the budget off.
//
// The entry is there for as long as a request of the user is: eviction skips
// an entry with anything in flight.
func (l *Limiter) budget(userID string, own time.Duration, now time.Time) (b Budget, ok bool) {
	if l.cfg.CostBudgetPerHour <= 0 {
		return Budget{}, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[userID]
	if !ok {
		return Budget{}, false
	}
	return l.budgetOf(e, own, now), true
}

// budgetOf is the budget of e at now, own added to what is spent. Called with
// l.mu held, so a refusal and Remaining read one number the same way.
func (l *Limiter) budgetOf(e *entry, own time.Duration, now time.Time) Budget {
	// A window that is over rolls on the caller's next request, and nothing
	// is spent in the one that opens then — what a request still running
	// charges lands in the old window and goes with it. The new one ends an
	// hour after it opens, so no earlier than an hour from now.
	if !now.Before(e.resetAt) {
		return Budget{Limit: l.cfg.CostBudgetPerHour, ResetAt: now.Add(budgetWindow)}
	}
	return Budget{Used: e.used + own, Limit: l.cfg.CostBudgetPerHour, ResetAt: e.resetAt}
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
// An exempt call is not refused for the budget; what it is charged is the
// caller's business, in release.
func (l *Limiter) acquire(userID string, now time.Time, exempt bool) (release func(charge), reason string) {
	e, reason := l.entryFor(userID, now, exempt)
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
		done := l.clock()
		l.mu.Lock()
		e.inflight--
		if l.cfg.CostBudgetPerHour > 0 {
			e.used += c.work
			// Under the lock, unlike the other metrics here, because the value
			// is state and not an event: set outside it, two releases of one
			// caller could land in the wrong order, and a release that lost a
			// race with eviction would bring back the series of a caller
			// already gone. What the window has spent, as Remaining reads it:
			// nothing, once the window is over.
			budgetUsed().WithLabelValues(userID).Set(l.budgetOf(e, 0, done).Used.Seconds())
		}
		l.mu.Unlock()
		// acquire spent one token before the work was known; a request that
		// turned out to carry several calls pays the rest here. ReserveN rather
		// than AllowN: the work is already done, so the tokens have to come out
		// of the bucket even when that leaves it empty — which is what
		// throttles the next call instead of letting twenty calls cost the same
		// as one.
		//
		// Priced now, when the work is done, and not at the instant acquire
		// admitted it. rate.Limiter takes an instant earlier than its last
		// event as its new last event, so pricing at admission wound the
		// bucket's clock back over every call admitted in the meantime, and
		// the next one was credited that stretch a second time: a slow batch
		// refunded itself about its own duration in tokens. Pricing later is
		// never the cheaper option either — the bucket is capped at its burst,
		// so charging after the refill spends at least as much as before it.
		//
		// In burst-sized steps, because ReserveN refuses outright when n is over
		// the bucket's burst and silently charges nothing: a limiter configured
		// at 10 RPM would otherwise let twenty calls through free, which is the
		// exact case this accounting exists for.
		if e.rpm != nil && c.units > 1 {
			for left := c.units - 1; left > 0; {
				step := min(left, e.rpm.Burst())
				e.rpm.ReserveN(done, step)
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
