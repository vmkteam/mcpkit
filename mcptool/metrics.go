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

// Only one series starts at zero here, where elsewhere in the library every
// series does: the tool label is the service's own set of names, and this
// package does not learn it until a registry is built.
//
// The exception is the one name this package owns. Every unregistered name is
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
