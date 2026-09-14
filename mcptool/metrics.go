package mcptool

import (
	"github.com/vmkteam/mcpkit/internal/metrics"
	"github.com/vmkteam/mcpkit/mcp"
)

// outcome labels on app_mcp_tool_calls_total — fixed cardinality.
//
// Two values, not five: the registry knows whether a tool refused, and why it
// refused is a word in the service's vocabulary. A service that wants its own
// codes on a metric counts them in its AfterHook, where it has the code.
const (
	outcomeOK    = "ok"
	outcomeError = "error"
)

// One series can be named here, where elsewhere in the library the whole set
// can: the tool label is the service's own set of names, and a var block runs
// before any service has said what its tools are. The rest are warmed in
// warmTools, at the first moment the set exists.
//
// The one that can is the name this package owns. Every unregistered name is
// counted as metricNameUnknown, and a caller inventing tool names is worth an
// alert from the first second rather than from the first invention — which is
// what the zero buys. It pairs only with outcomeError: an unknown tool is a
// refusal by construction.
var (
	group = metrics.NewGroup()

	toolCalls = group.CounterVec(
		"tool_calls_total",
		"MCP tools/call dispatches by tool and outcome.",
		[]string{"tool", "outcome"},
		[]string{metricNameUnknown, outcomeError},
	)
)

func registerMetrics() { group.Register() }

// warmTools starts both series of every registered tool at zero.
//
// This is the rule the rest of the library already keeps, arriving late because
// it had to: rate() over a counter that springs into existence with the first
// event cannot tell "nothing happened" from "nothing was scraped", so
// rate(app_mcp_tool_calls_total{outcome="error"}[5m]) had nothing to rate until
// the first failure — a service that has never failed read exactly like one that
// stopped being scraped, and the alert worth having is the one about the first
// failure.
//
// It runs from NewRegistry rather than from the var block above because that is
// where the names are: the set is the service's, and this package learns it when
// the registry is built. Both outcomes, because a ratio needs the denominator to
// exist too.
func warmTools(tools []Tool) {
	for _, t := range tools {
		toolCalls.WithLabelValues(t.Name(), outcomeOK)
		toolCalls.WithLabelValues(t.Name(), outcomeError)
	}
}

// observe counts one dispatch.
func observe(tool, result string) {
	registerMetrics()
	toolCalls.WithLabelValues(tool, result).Inc()
}

func outcome(res mcp.ToolCallResult) string {
	if res.IsError {
		return outcomeError
	}
	return outcomeOK
}
