// Package metrics is the Prometheus wiring every package of this library needs
// and each one used to write out for itself: the app_mcp_ prefix, a lazy
// registration in the default registry, and the zero-valued series that keep
// rate() honest before the first event.
//
// It is internal on purpose. A service publishes its own metrics under its own
// conventions; what is shared here is only this library's own packages agreeing
// on one prefix, and that agreement is not an API anyone outside should build
// on.
package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// Everything mcpkit publishes lives under app_mcp_: the prefix says which
// library the series comes from, and it does not collide with a rate limiter or
// a token verifier the same process runs for something else.
//
// This is the one place the two words are written. Four packages spelled them
// out identically, which is four chances for the fifth to differ.
const (
	Namespace = "app"
	Subsystem = "mcp"
)

// Group is the metrics of one package.
//
// The registration stays one per package, which is the shape this library has:
// the donor registered the lot in a single place because its limiter and its
// verifier lived in one package, and splitting them left every new package
// repeating the same sync.Once. A Group is what holds that Once now, so a
// package the service never wired still publishes nothing.
type Group struct {
	once       sync.Once
	collectors []prometheus.Collector
	warm       []func()
}

// NewGroup returns the Group a package declares its metrics on.
func NewGroup() *Group { return &Group{} }

// Counter declares a counter with one label, and the series it starts at zero.
//
// The values are less optional than a variadic makes them look: rate() over a
// counter that springs into existence with the first event cannot tell "nothing
// happened" from "nothing was scraped", and the alert worth having is the one
// about the first event. Passing none is for a label whose values are not known
// where the metric is declared, and is a decision rather than an oversight — one
// that owes the series a warm somewhere else, at the moment they are known.
func (g *Group) Counter(name, help, label string, values ...string) *prometheus.CounterVec {
	c := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Subsystem: Subsystem,
		Name:      name,
		Help:      help,
	}, []string{label})
	g.add(c, func() {
		for _, v := range values {
			c.WithLabelValues(v)
		}
	})
	return c
}

// CounterVec declares a counter over several labels, and the combinations it
// starts at zero — one warm per series, each naming a value for every label.
//
// Not every combination can be named here: a tool name belongs to the service,
// and a var block runs before any service has said what its tools are. Such a
// counter is warmed by whoever does learn the values — mcptool warms one series
// per tool when the registry is built — and what is named here is what the
// library knows on its own.
func (g *Group) CounterVec(name, help string, labels []string, warm ...[]string) *prometheus.CounterVec {
	c := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Subsystem: Subsystem,
		Name:      name,
		Help:      help,
	}, labels)
	g.add(c, func() {
		for _, values := range warm {
			c.WithLabelValues(values...)
		}
	})
	return c
}

// Gauge declares a gauge with one label, and the series it starts at zero.
func (g *Group) Gauge(name, help, label string, values ...string) *prometheus.GaugeVec {
	gv := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Subsystem: Subsystem,
		Name:      name,
		Help:      help,
	}, []string{label})
	g.add(gv, func() {
		for _, v := range values {
			gv.WithLabelValues(v)
		}
	})
	return gv
}

// Histogram declares a histogram with one label, and the series it starts at
// zero.
func (g *Group) Histogram(name, help, label string, buckets []float64, values ...string) *prometheus.HistogramVec {
	h := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: Namespace,
		Subsystem: Subsystem,
		Name:      name,
		Help:      help,
		Buckets:   buckets,
	}, []string{label})
	g.add(h, func() {
		for _, v := range values {
			h.WithLabelValues(v)
		}
	})
	return h
}

// add collects a metric and how to warm it. It runs while the declaring
// package's var block does, which is before anything can reach Register: the
// slices are unguarded because at that point there is nobody to guard them
// from.
func (g *Group) add(c prometheus.Collector, warm func()) {
	g.collectors = append(g.collectors, c)
	if warm != nil {
		g.warm = append(g.warm, warm)
	}
}

// Register publishes the group in the default registry, once, and starts its
// series at zero.
//
// Every entry point that touches one of these metrics calls it: registering
// from an init would publish series for a package the service never wired, and
// registering the same collector twice panics.
func (g *Group) Register() {
	g.once.Do(func() {
		prometheus.MustRegister(g.collectors...)
		for _, warm := range g.warm {
			warm()
		}
	})
}
