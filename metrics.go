package mcpkit

import (
	"github.com/vmkteam/mcpkit/internal/metrics"
)

// reason labels on app_mcp_transport_rejected_total — fixed cardinality.
//
// A request refused by the transport never reaches a handler, so it appears in
// no other series this library publishes: without this counter a client that
// sends batches, or one whose JSON is broken, is visible only in somebody
// else's access log.
const (
	reasonBatch          = "batch"
	reasonParse          = "parse"
	reasonTooLarge       = "too_large"
	reasonReadBody       = "read_body"
	reasonDispatch       = "dispatch"
	reasonBadMethod      = "method_not_allowed"
	reasonOrigin         = "origin"
	reasonHost           = "host"
	reasonHeaderMismatch = "header_mismatch"
	reasonBadVersion     = "bad_version"
	reasonMissingMeta    = "missing_meta"
)

// era labels on app_mcp_requests_total.
const (
	eraModern = "modern"
	eraLegacy = "legacy"
)

// Every series starts at zero: rate() over a counter that appears with the
// first refusal cannot tell "nothing was refused" from "no data".
var (
	group = metrics.NewGroup()

	rejectedTotal = group.Counter(
		"transport_rejected_total",
		"MCP requests refused by the transport before dispatch, by reason.",
		"reason",
		reasonBatch, reasonParse, reasonTooLarge,
		reasonReadBody, reasonDispatch, reasonBadMethod, reasonOrigin, reasonHost,
		reasonHeaderMismatch, reasonBadVersion, reasonMissingMeta,
	)

	// Which era clients actually speak. This is the number that decides when
	// the legacy half can be switched off — a question nothing else here can
	// answer, since the era is per request and leaves no other trace.
	requestsTotal = group.Counter(
		"requests_total",
		"MCP requests dispatched, by protocol era.",
		"era",
		eraModern, eraLegacy,
	)
)

func registerMetrics() { group.Register() }

func rejected(reason string) {
	registerMetrics()
	rejectedTotal.WithLabelValues(reason).Inc()
}

func dispatched(era string) {
	registerMetrics()
	requestsTotal.WithLabelValues(era).Inc()
}
