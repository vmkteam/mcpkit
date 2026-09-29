package ratelimit

// Cost accounting for the limiter. It lives beside the limiter because it is
// the limiter's unit of work, and a handler that reports it or asks what is
// left needs only the exported functions here.

import (
	"context"
	"sync"
	"time"
)

// Cost is how a handler tells the middleware what a request actually did. The
// middleware puts one in the request context; whoever does the upstream work
// calls Charge.
//
// It exists because one HTTP request stopped meaning one unit of work. A
// single POST can carry a list of calls that run at once, so the wall clock
// reports the longest of them while the server did the sum — twenty
// one-second calls would be billed as one second, and CostBudgetPerHour would
// stop meaning what it says. A request that charges nothing is still priced by
// its wall clock, exactly as before.
type Cost struct {
	mu    sync.Mutex
	work  time.Duration
	units int

	// Set by the middleware before the handler runs, and zero on an
	// accumulator made by WithCost alone: whose budget this is, for Remaining,
	// and whether the call is exempt from it.
	limiter *Limiter
	userID  string
	exempt  bool
}

// charge is what one served request costs: work against the hourly budget,
// units against the per-minute rate.
type charge struct {
	work  time.Duration
	units int
}

type costKey struct{}

// WithCost returns ctx carrying a fresh accumulator, and the accumulator.
func WithCost(ctx context.Context) (context.Context, *Cost) {
	c := &Cost{}
	return context.WithValue(ctx, costKey{}, c), c
}

// Charge records one piece of billable work done while serving ctx. Safe to
// call concurrently, and a no-op when ctx carries no accumulator — a handler
// must not have to know whether rate limiting is switched on.
//
// It is ChargeFor without a label.
func Charge(ctx context.Context, work time.Duration) { ChargeFor(ctx, "", work) }

// ChargeFor is Charge that says what did the work, and the label is what
// app_mcp_ratelimit_charge_seconds breaks the budget down by — the question
// "who ate the budget" answered from Prometheus rather than from an audit log.
//
// The label is per charge, not per request: the calls of one request can go
// to different upstreams, and a label per request would fold together exactly
// the split that is worth seeing.
//
// Each label is a series, so it must be a name from the service's own
// catalogue — "grafana", "postgres" — and never a value from the request: a
// query, a URL, a user. That keeps the cardinality the size of the catalogue.
func ChargeFor(ctx context.Context, label string, work time.Duration) {
	c, ok := ctx.Value(costKey{}).(*Cost)
	if !ok {
		return
	}
	c.mu.Lock()
	c.work += work
	c.units++
	c.mu.Unlock()

	if c.observed() {
		if label == "" {
			label = labelUnlabelled
		}
		charged().WithLabelValues(label).Observe(work.Seconds())
	}
}

// Budget is a caller's hourly budget at one moment.
type Budget struct {
	Used    time.Duration
	Limit   time.Duration
	ResetAt time.Time
}

// Left is what remains of the budget, never below zero.
func (b Budget) Left() time.Duration { return max(0, b.Limit-b.Used) }

// Remaining reports the budget of the caller ctx is serving: what their
// finished requests have spent in this window, plus what this request has
// charged so far. ok is false when the budget is off or ctx did not come
// through the middleware.
//
// It is a snapshot. Other requests of the same caller that are still running
// are not in it until they finish, and change it when they do. An exempt call
// charges the budget nothing, so what it charged is not added either.
//
// It is what lets a long investigation narrow its own queries before it runs
// into the ceiling instead of after: the service puts it in its answers.
func Remaining(ctx context.Context) (b Budget, ok bool) {
	c, ok := ctx.Value(costKey{}).(*Cost)
	if !ok || c.limiter == nil {
		return Budget{}, false
	}
	var own time.Duration
	if !c.exempt {
		c.mu.Lock()
		own = c.work
		c.mu.Unlock()
	}
	return c.limiter.budget(c.userID, own, c.limiter.clock())
}

// settle prices the finished request. Nothing charged means nothing billable
// ran — an initialize, a tools/list, a refusal before the upstream — and those
// are priced by the wall clock, exactly as every request was before one
// request could carry many calls.
//
// An exempt call spends no budget whatever it did; its units still count
// against the rate.
func (c *Cost) settle(wall time.Duration) charge {
	c.mu.Lock()
	ch := charge{work: c.work, units: c.units}
	c.mu.Unlock()

	if ch.units == 0 {
		ch = charge{work: wall, units: 1}
		// Every charged piece was observed as it was charged; only the wall
		// clock is left to observe, so the histogram sums to what the budget
		// was spent.
		if c.observed() {
			charged().WithLabelValues(labelWallClock).Observe(wall.Seconds())
		}
	}
	if c.exempt {
		ch.work = 0
	}
	return ch
}

// observed reports whether a charge made here goes into the histogram: only
// when it goes into a budget. An accumulator made by WithCost alone belongs to
// no limiter, a limiter may have the budget off, and an exempt call spends
// nothing. What it reads is set before the handler runs and never changes, so
// it needs no lock.
func (c *Cost) observed() bool {
	return c.limiter != nil && c.limiter.cfg.CostBudgetPerHour > 0 && !c.exempt
}
