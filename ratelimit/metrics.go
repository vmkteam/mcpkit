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
)

func registerMetrics() { group.Register() }

func metric() *prometheus.CounterVec {
	registerMetrics()
	return deniedTotal
}

func inflight() *prometheus.GaugeVec {
	registerMetrics()
	return inflightGauge
}
