package ratelimit

import (
	"github.com/vmkteam/mcpkit/internal/metrics"

	"github.com/prometheus/client_golang/prometheus"
)

// reason labels on app_mcp_ratelimit_denied_total — fixed cardinality.
const (
	reasonRPM              = "rpm"
	reasonUserConcurrent   = "user_concurrent"
	reasonGlobalConcurrent = "global_concurrent"
	reasonCostBudget       = "cost_budget"
)

// scope labels on app_mcp_ratelimit_inflight.
const (
	scopeUser   = "user"
	scopeGlobal = "global"
)

// The label values of app_mcp_ratelimit_charge_seconds the library writes on
// its own. Everything else is a name a service passed to ChargeFor.
const (
	// labelUnlabelled is Charge, or ChargeFor with no label.
	labelUnlabelled = "unlabelled"
	// labelWallClock is a request that charged nothing and was priced by its
	// wall clock. It is what makes the histogram add up to the budget: without
	// it a service that never calls Charge would spend its budget invisibly.
	labelWallClock = "wall_clock"
)

// chargeBuckets run from 10ms to a minute. An upstream call takes anywhere from
// a few milliseconds to a timeout of tens of seconds, and everything worth
// telling apart is in the upper half.
var chargeBuckets = []float64{.01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 15, 20, 30, 60}

// Metrics of this package are registered once, on first use, in the default
// registry — the same one the service publishes, so registering twice would
// panic and the Group's sync.Once is what keeps that from happening.
//
// Every series starts at zero: rate() over a counter that appears with the
// first denial cannot tell "nothing was denied" from "no data".
var (
	group = metrics.NewGroup()

	deniedTotal = group.Counter(
		"ratelimit_denied_total",
		"Requests rejected by ratelimit, labelled by reason.",
		"reason",
		reasonRPM, reasonUserConcurrent, reasonGlobalConcurrent, reasonCostBudget,
	)

	inflightGauge = group.Gauge(
		"ratelimit_inflight",
		"In-flight requests holding a ratelimit slot.",
		"scope",
		scopeUser, scopeGlobal,
	)

	chargeSeconds = group.Histogram(
		"ratelimit_charge_seconds",
		"Work charged against the hourly budget, labelled by what did it.",
		"label",
		chargeBuckets,
		labelUnlabelled, labelWallClock,
	)

	// Not warmed: there is no user to start from until one is served. A series
	// appears with a user's first settled request and goes with their entry.
	//
	// The label is Principal.UserID as it is. Where authentication calls a
	// user by e-mail, that e-mail is in /metrics.
	budgetUsedGauge = group.Gauge(
		"ratelimit_budget_used_seconds",
		"Hourly budget each caller has spent in the current window.",
		"user",
	)
)

func registerMetrics() { group.Register() }

func charged() *prometheus.HistogramVec {
	registerMetrics()
	return chargeSeconds
}

func budgetUsed() *prometheus.GaugeVec {
	registerMetrics()
	return budgetUsedGauge
}

func metric() *prometheus.CounterVec {
	registerMetrics()
	return deniedTotal
}

func inflight() *prometheus.GaugeVec {
	registerMetrics()
	return inflightGauge
}
