package ratelimit

// Cost accounting for the limiter. It lives beside the limiter because it is
// the limiter's unit of work, and a handler that reports it needs only the two
// exported functions.

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
func Charge(ctx context.Context, work time.Duration) {
	c, ok := ctx.Value(costKey{}).(*Cost)
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.work += work
	c.units++
}

// settle prices the finished request. Nothing charged means nothing billable
// ran — an initialize, a tools/list, a refusal before the upstream — and those
// are priced by the wall clock, exactly as every request was before one
// request could carry many calls.
func (c *Cost) settle(wall time.Duration) charge {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.units == 0 {
		return charge{work: wall, units: 1}
	}
	return charge{work: c.work, units: c.units}
}
