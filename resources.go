package mcpkit

import (
	"context"
	"encoding/base64"
	"errors"
	"unicode/utf8"

	"github.com/vmkteam/mcpkit/mcp"

	"github.com/vmkteam/zenrpc/v2"
)

// ResourceSource is what the resources namespace needs from a store. A
// doc.Library satisfies it as is, and so does a service that keeps its own
// catalogue — the interface is the extension point, not a layer of adapters.
type ResourceSource interface {
	Resources() []mcp.ResourceEntry
	Read(uri string) (data []byte, mimeType string, err error)
}

// URINormalizer is an optional half of a ResourceSource. When a source can
// canonicalise a URI, the answer of resources/read names the resource the way
// resources/list did, rather than echoing back the bare path the model typed.
type URINormalizer interface {
	NormalizeURI(uri string) string
}

// ReadHook is called after each resources/read and resources/list. It is how a
// service audits catalogue reads without this package knowing what an audit is.
// On list, uri is empty.
type ReadHook func(ctx context.Context, uri string, bytesOut int, err error)

// ResourcesOption tunes ResourcesService.
type ResourcesOption func(*ResourcesService)

// ResourcesService implements the MCP resources namespace: a read-only view of
// whatever the service calls its catalogue.
type ResourcesService struct {
	zenrpc.Service
	src      ResourceSource
	hook     ReadHook
	hint     mcp.CacheHint
	pageSize int
}

// NewResourcesService wires a source into the resources dispatcher.
func NewResourcesService(src ResourceSource, opts ...ResourcesOption) ResourcesService {
	s := ResourcesService{src: src}
	for _, o := range opts {
		o(&s)
	}
	return s
}

// WithReadHook installs fn as the hook called after every list and read.
func WithReadHook(fn ReadHook) ResourcesOption {
	return func(s *ResourcesService) { s.hook = fn }
}

// WithResourceCache sets the caching hints of resources/list and resources/read.
//
// The default is the zero value: no freshness, private. Raising the TTL and
// declaring the scope public is a statement about the catalogue that only the
// service can make — public means any cache in between may serve this answer to
// any caller, which is right for a catalogue identical for everyone and a leak
// for one that is not.
func WithResourceCache(h mcp.CacheHint) ResourcesOption {
	return func(s *ResourcesService) { s.hint = h }
}

// WithResourcePageSize caps how many entries one resources/list answers with.
//
// The default, zero, is the whole catalogue in one answer. A page is a round
// trip the model waits through before it can use any of the list, so paging is
// worth turning on when the catalogue is large enough that sending it whole
// costs more than the extra calls — which the service knows and this package
// does not.
func WithResourcePageSize(n int) ResourcesOption {
	return func(s *ResourcesService) { s.pageSize = n }
}

// List returns the catalogue of resources advertised by this server.
//
// The cursor is the one from the previous answer and nothing else: it is opaque
// by the protocol's own rule, and the format behind it is free to change.
//
//zenrpc:cursor nextCursor from the previous page; empty for the first
//zenrpc:return the resources this server serves
func (s ResourcesService) List(ctx context.Context, cursor string) (mcp.ResourceList, error) {
	// An absent source is an empty catalogue rather than a failure: a dev run
	// with no documents embedded still has to answer the handshake.
	entries := []mcp.ResourceEntry{}
	if s.src != nil {
		if got := s.src.Resources(); got != nil {
			entries = got
		}
	}
	page, next, err := mcp.Paginate(entries, cursor, s.pageSize, func(e mcp.ResourceEntry) string { return e.URI })
	if err != nil {
		err = RPCError("resources.list", err)
		s.notify(ctx, "", 0, err)
		return mcp.ResourceList{}, err
	}
	n := 0
	for _, e := range page {
		n += len(e.URI) + len(e.Name) + len(e.Description)
	}
	s.notify(ctx, "", n, nil)
	return mcp.ResourceList{Resources: page, NextCursor: next, CacheHint: s.hint}, nil
}

// Read returns the text of one resource. The argument is the canonical URI from
// resources/list, but a bare path is accepted too: the model types these out of
// the instruction text and drops the scheme regularly. Normalising is the
// source's job, because the scheme is the source's to know.
//
//zenrpc:uri canonical URI from resources/list, or the bare path
//zenrpc:return resource contents, one block per spec
func (s ResourcesService) Read(ctx context.Context, uri string) (mcp.ResourceData, error) {
	if s.src == nil {
		err := errors.New("resources.read: no resource source configured")
		s.notify(ctx, uri, 0, err)
		return mcp.ResourceData{}, err
	}
	// Canonical for the hook as well as for the answer. The model types these
	// out of instruction text and drops the scheme, so "hello.md" and
	// "docs://hello.md" are the same read — and an audit that logged them under
	// two different names could not be grouped by resource, nor joined against
	// the URIs resources/list handed out.
	canonical := s.canonical(uri)
	data, mimeType, err := s.src.Read(uri)
	if err != nil {
		err = RPCError("resources.read", err)
		s.notify(ctx, canonical, 0, err)
		return mcp.ResourceData{}, err
	}
	s.notify(ctx, canonical, len(data), nil)
	return mcp.ResourceData{
		Contents:  []mcp.ResourceContent{resourceContent(canonical, mimeType, data)},
		CacheHint: s.hint,
	}, nil
}

// resourceContent carries the bytes as text when they are text, and as base64
// in blob when they are not.
//
// The MIME type alone is not the test: doc.detectMime answers text/plain for
// any extension the standard library does not know, so a file that is not text
// can arrive labelled as one. Bytes that are not valid UTF-8 are therefore
// binary whatever the label says — pushing them through Text hands the JSON
// encoder something it can only render as U+FFFD, and the caller receives a
// document that parses and is wrong.
func resourceContent(uri, mimeType string, data []byte) mcp.ResourceContent {
	c := mcp.ResourceContent{URI: uri, MimeType: mimeType}
	if mcp.IsTextualMIME(mimeType) && utf8.Valid(data) {
		c.Text = string(data)
		return c
	}
	c.Blob = base64.StdEncoding.EncodeToString(data)
	return c
}

// canonical names the resource the way resources/list named it, when the source
// knows how.
func (s ResourcesService) canonical(uri string) string {
	if n, ok := s.src.(URINormalizer); ok {
		return n.NormalizeURI(uri)
	}
	return uri
}

func (s ResourcesService) notify(ctx context.Context, uri string, bytesOut int, err error) {
	if s.hook != nil {
		s.hook(ctx, uri, bytesOut, err)
	}
}
