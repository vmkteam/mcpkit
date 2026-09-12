package auth

import (
	"github.com/vmkteam/mcpkit/internal/metrics"

	"github.com/prometheus/client_golang/prometheus"
)

// Verify outcomes used as the `result` label on app_mcp_oidc_verify_total.
// `forbidden` = signature/iss/aud OK, RequiredRoles missed — the most
// actionable signal of the five.
const (
	resultOK        = "ok"
	resultMissing   = "missing"
	resultInvalid   = "invalid"
	resultExpired   = "expired"
	resultForbidden = "forbidden"
)

// Metrics of this package are registered once, on first use, in the default
// registry — the same one the service publishes, so registering twice would
// panic and the Group's sync.Once is what keeps that from happening.
//
// Every series starts at zero: rate() over a counter that appears with the
// first failure cannot tell "no errors" from "no data", and the alert that
// matters is the one about the first failure.
var (
	group = metrics.NewGroup()

	verifyTotal = group.Counter(
		"oidc_verify_total",
		"OIDC JWT verification attempts on /mcp by outcome.",
		"result",
		resultOK, resultMissing, resultInvalid, resultExpired, resultForbidden,
	)
)

func registerMetrics() { group.Register() }

func metric() *prometheus.CounterVec {
	registerMetrics()
	return verifyTotal
}
