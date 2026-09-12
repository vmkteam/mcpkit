package metrics

import (
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

// The reason the warm-up is a parameter and not an afterthought: a counter that
// appears with the first event cannot be told apart from one nobody scraped.
func TestCounterStartsItsSeriesAtZero(t *testing.T) {
	t.Parallel()
	g := NewGroup()
	c := g.Counter("warmed_total", "help.", "reason", "a", "b", "c")

	assert.Equal(t, 0, testutil.CollectAndCount(c), "nothing exists before Register")
	g.Register()
	assert.Equal(t, 3, testutil.CollectAndCount(c), "one series per value, from the start")
	assert.InDelta(t, 0.0, testutil.ToFloat64(c.WithLabelValues("a")), 0)
}

// A label whose values this library cannot enumerate — a tool name — has no
// series to start from, and saying so is the point of the second constructor.
func TestCounterVecWarmsNothingByDefault(t *testing.T) {
	t.Parallel()
	g := NewGroup()
	c := g.CounterVec("unwarmed_total", "help.", []string{"tool", "outcome"})

	g.Register()
	assert.Equal(t, 0, testutil.CollectAndCount(c))
	c.WithLabelValues("x", "ok").Inc()
	assert.Equal(t, 1, testutil.CollectAndCount(c))
}

// The combinations it can name are the ones an alert fires on before they have
// ever happened — a caller inventing tool names, say.
func TestCounterVecWarmsTheCombinationsItIsGiven(t *testing.T) {
	t.Parallel()
	g := NewGroup()
	c := g.CounterVec("partly_warmed_total", "help.", []string{"tool", "outcome"},
		[]string{"unknown", "error"})

	g.Register()
	assert.Equal(t, 1, testutil.CollectAndCount(c))
	assert.InDelta(t, 0.0, testutil.ToFloat64(c.WithLabelValues("unknown", "error")), 0)
}

func TestGaugeStartsItsSeriesAtZero(t *testing.T) {
	t.Parallel()
	g := NewGroup()
	gauge := g.Gauge("warmed_inflight", "help.", "scope", "user", "global")

	g.Register()
	assert.Equal(t, 2, testutil.CollectAndCount(gauge))
}

// Register is called from every entry point that touches a metric, so it is
// reached concurrently and reached often. Registering the same collector twice
// panics, which is what the Once is for.
func TestRegisterIsIdempotentAndConcurrent(t *testing.T) {
	t.Parallel()
	g := NewGroup()
	c := g.Counter("once_total", "help.", "reason", "a")

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			assert.NotPanics(t, g.Register)
		})
	}
	wg.Wait()
	assert.Equal(t, 1, testutil.CollectAndCount(c))
}

// Every series this library publishes is app_mcp_something: the prefix says
// which library a series came from, and it is now written in one place instead
// of four.
func TestNamesCarryThePrefix(t *testing.T) {
	t.Parallel()
	g := NewGroup()
	counter := g.Counter("prefixed_total", "help.", "reason", "a")
	gauge := g.Gauge("prefixed_inflight", "help.", "scope", "user")

	assert.Contains(t, counter.WithLabelValues("a").Desc().String(), "app_mcp_prefixed_total")
	assert.Contains(t, gauge.WithLabelValues("user").Desc().String(), "app_mcp_prefixed_inflight")
}
