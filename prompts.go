package mcpkit

import (
	"errors"

	"github.com/vmkteam/mcpkit/mcp"

	"github.com/vmkteam/zenrpc/v2"
)

// PromptSource is what the prompts namespace needs from a store. Render returns
// finished text: a template is a detail of whoever loaded the prompt, and it
// has no business leaving that package.
type PromptSource interface {
	Prompts() []mcp.PromptEntry
	Render(name string, args map[string]string) (description, text string, err error)
}

// PromptsService implements the MCP prompts namespace: the ready-made scenarios
// a server offers, parameterised by their declared arguments.
type PromptsService struct {
	zenrpc.Service
	src      PromptSource
	hint     mcp.CacheHint
	pageSize int
}

// PromptsOption tunes PromptsService.
type PromptsOption func(*PromptsService)

// WithPromptCache sets the caching hints of prompts/list. The default is the
// zero value: no freshness, private.
func WithPromptCache(h mcp.CacheHint) PromptsOption {
	return func(s *PromptsService) { s.hint = h }
}

// WithPromptPageSize caps how many entries one prompts/list answers with. The
// default, zero, is the whole list in one answer.
func WithPromptPageSize(n int) PromptsOption {
	return func(s *PromptsService) { s.pageSize = n }
}

// NewPromptsService wires a source into the prompts dispatcher.
func NewPromptsService(src PromptSource, opts ...PromptsOption) PromptsService {
	s := PromptsService{src: src}
	for _, o := range opts {
		o(&s)
	}
	return s
}

// List returns the catalogue of prompts advertised by this server.
//
//zenrpc:cursor nextCursor from the previous page; empty for the first
//zenrpc:return the prompts this server offers
func (s PromptsService) List(cursor string) (mcp.PromptList, error) {
	// An empty list marshals as [] rather than null: clients with strict
	// schemas reject null where an array was promised.
	entries := []mcp.PromptEntry{}
	if s.src != nil {
		if got := s.src.Prompts(); got != nil {
			entries = got
		}
	}
	page, next, err := mcp.Paginate(entries, cursor, s.pageSize, func(e mcp.PromptEntry) string { return e.Name })
	if err != nil {
		return mcp.PromptList{}, RPCError("prompts.list", err)
	}
	return mcp.PromptList{Prompts: page, NextCursor: next, CacheHint: s.hint.Normalized()}, nil
}

// Get renders a prompt by name with the supplied arguments. The answer is a
// single user message; multi-message prompts are part of the format and no
// server here has needed one.
//
//zenrpc:name name of the prompt, from prompts/list
//zenrpc:arguments values for the declared placeholders
//zenrpc:return the rendered prompt as one user message
func (s PromptsService) Get(name string, arguments map[string]string) (mcp.RenderedPrompt, error) {
	if s.src == nil {
		return mcp.RenderedPrompt{}, errors.New("prompts.get: no prompt source configured")
	}
	description, text, err := s.src.Render(name, arguments)
	if err != nil {
		return mcp.RenderedPrompt{}, RPCError("prompts.get", err)
	}
	return mcp.RenderedPrompt{
		Description: description,
		Messages: []mcp.PromptMessage{{
			Role:    mcp.RoleUser,
			Content: mcp.PromptMessageContent{Type: mcp.ContentTypeText, Text: text},
		}},
	}, nil
}
