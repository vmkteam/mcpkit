package ratelimit

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

// The histogram is one per process and every test here writes to it, so these
// read differences on labels of their own, and none of them is parallel.

type observations struct {
	count uint64
	sum   float64
	found bool
}

// histogram reads one series of app_mcp_ratelimit_charge_seconds.
func histogram(t *testing.T, label string) observations {
	t.Helper()
	registerMetrics()
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(chargeSeconds))
	families, err := reg.Gather()
	require.NoError(t, err)
	for _, f := range families {
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "label" && l.GetValue() == label {
					h := m.GetHistogram()
					return observations{count: h.GetSampleCount(), sum: h.GetSampleSum(), found: true}
				}
			}
		}
	}
	return observations{}
}

// The two labels the library writes itself are there before anything is
// charged; the ones a service names cannot be.
func TestChargeHistogramStartsAtZero(t *testing.T) {
	assert.True(t, histogram(t, labelUnlabelled).found)
	assert.True(t, histogram(t, labelWallClock).found)
}

// Each charge is one observation under its own label, so the calls of one
// request to different upstreams stay apart.
func TestChargeForIsObservedByLabel(t *testing.T) {
	grafana, sentry, unlabelled, wall := histogram(t, "by-label-grafana"), histogram(t, "by-label-sentry"),
		histogram(t, labelUnlabelled), histogram(t, labelWallClock)

	l := newLimiter(t, Config{CostBudgetPerHour: time.Hour})
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ChargeFor(r.Context(), "by-label-grafana", 3*time.Second)
		ChargeFor(r.Context(), "by-label-grafana", 2*time.Second)
		ChargeFor(r.Context(), "by-label-sentry", time.Second)
		Charge(r.Context(), 500*time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}), embedlog.Logger{})
	post(h, toolCall)

	got := histogram(t, "by-label-grafana")
	assert.Equal(t, grafana.count+2, got.count)
	assert.InDelta(t, grafana.sum+5, got.sum, 1e-9)
	got = histogram(t, "by-label-sentry")
	assert.Equal(t, sentry.count+1, got.count)
	assert.InDelta(t, sentry.sum+1, got.sum, 1e-9)
	got = histogram(t, labelUnlabelled)
	assert.Equal(t, unlabelled.count+1, got.count, "Charge is ChargeFor with no label")
	assert.InDelta(t, unlabelled.sum+0.5, got.sum, 1e-9)
	assert.Equal(t, wall.count, histogram(t, labelWallClock).count,
		"a request that charged anything is not priced by its wall clock")
}

// The histogram adds up to the budget: what a request charged, and what one
// that charged nothing cost by its wall clock.
func TestChargeHistogramAddsUpToTheBudget(t *testing.T) {
	charged0, wall0 := histogram(t, "adds-up"), histogram(t, labelWallClock)

	l := newLimiter(t, Config{CostBudgetPerHour: time.Hour})
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"help"`) {
			ChargeFor(r.Context(), "adds-up", 4*time.Second)
		}
		w.WriteHeader(http.StatusOK)
	}), embedlog.Logger{})
	post(h, toolCall) // four seconds upstream
	post(h, helpCall) // nothing charged: priced by its wall clock

	charged, wall := histogram(t, "adds-up"), histogram(t, labelWallClock)
	assert.Equal(t, charged0.count+1, charged.count)
	assert.Equal(t, wall0.count+1, wall.count, "the request that charged nothing")

	spent, ok := l.budget(anonymousUser, 0, time.Now())
	require.True(t, ok)
	assert.InDelta(t, spent.Used.Seconds(), (charged.sum-charged0.sum)+(wall.sum-wall0.sum), 1e-6)
}

// Only work that goes into a budget is observed: an exempt call spends none,
// and neither does a limiter with the budget off.
func TestChargeHistogramSkipsWhatSpendsNothing(t *testing.T) {
	l := newLimiter(t, Config{CostBudgetPerHour: time.Hour, Exempt: exemptHelp})
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ChargeFor(r.Context(), "skips-exempt", time.Second)
		w.WriteHeader(http.StatusOK)
	}), embedlog.Logger{})
	post(h, helpCall)
	assert.False(t, histogram(t, "skips-exempt").found, "an exempt call")

	l = newLimiter(t, Config{PerUserRPM: 10})
	h = l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ChargeFor(r.Context(), "skips-off", time.Second)
		w.WriteHeader(http.StatusOK)
	}), embedlog.Logger{})
	post(h, toolCall)
	assert.False(t, histogram(t, "skips-off").found, "no budget")
}

// The gauge is what a caller has spent in the window that is running: set as
// requests settle, zero once the window is over, gone with the entry.
func TestBudgetUsedGauge(t *testing.T) {
	const user = "gauge-alice"
	l := newLimiter(t, Config{CostBudgetPerHour: time.Hour})
	opened := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	l.clock = func() time.Time { return opened }

	release, _ := l.acquire(user, opened, false)
	require.NotNil(t, release)
	release(charge{work: 90 * time.Second, units: 1})
	assert.InDelta(t, 90, testutil.ToFloat64(budgetUsedGauge.WithLabelValues(user)), 1e-9)

	l.evictIdle(opened.Add(30 * time.Minute))
	assert.InDelta(t, 90, testutil.ToFloat64(budgetUsedGauge.WithLabelValues(user)), 1e-9,
		"the window is still running")

	l.evictIdle(opened.Add(budgetWindow))
	require.Contains(t, l.entries, user, "an hour idle is not idle enough to go")
	assert.Zero(t, testutil.ToFloat64(budgetUsedGauge.WithLabelValues(user)),
		"the window is over: the caller has the whole budget back")

	l.evictIdle(opened.Add(idleTTL + time.Minute))
	require.NotContains(t, l.entries, user)
	assert.False(t, budgetUsedGauge.DeleteLabelValues(user), "the series went with the entry")
}

// The gauge follows the window, not the lazy roll of the entry: a caller who
// comes back is shown the fresh window at once, and a request that finished
// after its window ended does not bring the dead one back.
func TestBudgetUsedGaugeFollowsTheWindow(t *testing.T) {
	gauge := func(user string) float64 { return testutil.ToFloat64(budgetUsedGauge.WithLabelValues(user)) }
	opened := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	t.Run("the caller comes back", func(t *testing.T) {
		const user = "gauge-back"
		l := newLimiter(t, Config{CostBudgetPerHour: time.Hour})
		l.clock = func() time.Time { return opened }
		release, _ := l.acquire(user, opened, false)
		release(charge{work: 90 * time.Second, units: 1})
		require.InDelta(t, 90, gauge(user), 1e-9)

		held, _ := l.acquire(user, opened.Add(budgetWindow+time.Minute), false)
		require.NotNil(t, held)
		assert.Zero(t, gauge(user), "the window rolled while the request still runs")
		held(charge{})
	})

	t.Run("a request outlives its window", func(t *testing.T) {
		const user = "gauge-late"
		l := newLimiter(t, Config{CostBudgetPerHour: time.Hour})
		slow, _ := l.acquire(user, opened, false)
		require.NotNil(t, slow)
		l.clock = func() time.Time { return opened.Add(budgetWindow + time.Minute) }
		slow(charge{work: 90 * time.Second, units: 1})
		assert.Zero(t, gauge(user), "what lands in a window that is over is not shown as spent")
	})

	t.Run("a caller who never settled", func(t *testing.T) {
		const user = "gauge-never"
		l := newLimiter(t, Config{CostBudgetPerHour: time.Hour})
		held, _ := l.acquire(user, opened, false)
		require.NotNil(t, held)
		defer held(charge{})
		l.evictIdle(opened.Add(budgetWindow))
		assert.False(t, budgetUsedGauge.DeleteLabelValues(user), "eviction made a series for nobody")
	})
}
