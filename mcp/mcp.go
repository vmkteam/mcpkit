// Package mcp is the wire format of the Model Context Protocol: the structs
// that go over JSON-RPC, thin enough that a round trip through encoding/json
// holds no surprises.
//
// Beside them it carries the pure functions that describe the protocol rather
// than any one server's use of it — the revisions and NegotiateVersion, plus
// DecodeArgs, SchemaFor, Truncate and CutBytes. No I/O, no state, and nothing
// that depends on another package here: what a server does with a Tool, where a
// ResourceEntry comes from, what an instruction says all belong to the packages
// above and to the service.
package mcp

import (
	"encoding/base64"
	"encoding/json"
)

// Roles and content types the protocol names.
const (
	RoleUser        = "user"
	ContentTypeText = "text"
	// ContentTypeImage and ContentTypeAudio carry bytes as base64 in Data.
	ContentTypeImage = "image"
	ContentTypeAudio = "audio"
	// ContentTypeResourceLink points at something in the catalogue rather than
	// inlining it; ContentTypeResource inlines it.
	ContentTypeResourceLink = "resource_link"
	ContentTypeResource     = "resource"
)

// ResultTypeComplete is the resultType of a finished answer. Since 2026-07-28
// "the result MUST include a resultType field"; the other value the core
// protocol defines, input_required, belongs to a server that asks the client
// for something mid-call, and this library never does.
const ResultTypeComplete = "complete"

// completeResult writes resultType into an already-encoded result object.
//
// It is done at the encoder rather than as a field on every struct so that the
// invariant does not depend on anyone remembering it: a service that builds an
// mcp.ToolList by hand gets a conforming answer, and a client of an older
// revision ignores the extra key — which its own revision requires it to do.
func completeResult(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	const field = `"resultType":"` + ResultTypeComplete + `"`
	if len(b) < 2 || b[0] != '{' {
		return b, nil // not an object: nothing this rule applies to
	}
	out := make([]byte, 0, len(b)+len(field)+1)
	out = append(out, '{')
	out = append(out, field...)
	if b[1] != '}' { // an empty object takes no separator
		out = append(out, ',')
	}
	return append(out, b[1:]...), nil
}

// --- initialize / capabilities ----------------------------------------------

type ToolsCapability struct {
	ListChanged bool `json:"listChanged"`
}

type ResourcesCapability struct {
	Subscribe   bool `json:"subscribe"`
	ListChanged bool `json:"listChanged"`
}

type PromptsCapability struct {
	ListChanged bool `json:"listChanged"`
}

// Capabilities is what the server says it can do. The three are pointers so
// that not declaring one is expressible: "Servers that declare the prompts
// capability MUST respond to prompts/list requests", and a server that
// registered only tools used to declare all three, sending the client to a
// namespace that answers -32601.
type Capabilities struct {
	Tools     *ToolsCapability     `json:"tools,omitempty"`
	Resources *ResourcesCapability `json:"resources,omitempty"`
	Prompts   *PromptsCapability   `json:"prompts,omitempty"`
}

// ServerInfo is who the server says it is. Name and Version are the identity;
// the rest is what SEP-973 added so that a client has something to show a human
// — a display name, a sentence, a link to the documentation, an icon.
//
// All of it is self-reported, and the spec says so plainly: display, logging
// and debugging, never a security decision.
type ServerInfo struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	WebsiteURL  string `json:"websiteUrl,omitempty"`
	Icons       []Icon `json:"icons,omitempty"`
}

type InitializeResult struct {
	ProtocolVersion string       `json:"protocolVersion"`
	Capabilities    Capabilities `json:"capabilities"`
	ServerInfo      ServerInfo   `json:"serverInfo"`
	Instructions    string       `json:"instructions"`
}

// PingResult is the empty object the spec asks for.
type PingResult struct{}

// --- server/discover ----------------------------------------------------------

// CacheScope is who may hold a cacheable answer.
//
// It has its own type because its default is not its zero value: the field is
// required on every cacheable result, and an empty string names no scope at all
// — worse than sending nothing. Marshaling fills it in, so the invariant lives
// in the type rather than in the memory of whoever built the result. That is the
// same reason resultType is written by the encoder below, and the reason a
// result type added later gets this for free.
type CacheScope string

// Cache scopes a cacheable result may declare.
const (
	// CacheScopePublic says the answer holds nothing user-specific, and any
	// client, gateway or proxy may serve it to anyone. It is a promise about
	// the content, and the spec is blunt about the consequence: such an answer
	// "may be shared between callers even if the Result is coming from an
	// authenticated endpoint".
	CacheScopePublic CacheScope = "public"
	// CacheScopePrivate keeps the answer inside one authorization context.
	CacheScopePrivate CacheScope = "private"
)

// MarshalJSON writes the effective scope: private unless the server said
// otherwise. A missing scope must not read as public — the default has to be
// the one that cannot leak.
func (s CacheScope) MarshalJSON() ([]byte, error) {
	if s == "" {
		s = CacheScopePrivate
	}
	return json.Marshal(string(s))
}

// CacheHint is what every cacheable result carries: how long the client may
// consider it fresh, and who may hold it.
//
// The zero value — no freshness, private — is the answer a server gives when it
// does not know how often its own catalogue changes, which is the only thing
// this library can honestly say on a service's behalf.
//
// It carries no MarshalJSON of its own on purpose: an embedded type that has one
// would take over the encoding of whatever embeds it, and these two fields
// belong beside the result's own, not nested under a key of their own.
type CacheHint struct {
	TTLMs      int64      `json:"ttlMs"`
	CacheScope CacheScope `json:"cacheScope"`
}

// Scope returns the declared scope, defaulting to private. It is the reading
// half of what MarshalJSON does for the wire, for code that has to branch on
// the scope rather than send it.
func (h CacheHint) Scope() CacheScope {
	if h.CacheScope == "" {
		return CacheScopePrivate
	}
	return h.CacheScope
}

// ResultMeta is the _meta of a result. Since 2026-07-28 the server's identity
// travels here rather than beside the payload.
type ResultMeta struct {
	ServerInfo *ServerInfo `json:"io.modelcontextprotocol/serverInfo,omitempty"`
}

// DiscoverResult answers server/discover, which replaced the initialize
// handshake: "Servers MUST implement it." A client may call it to learn what
// the server speaks before sending anything else, or skip it and handle
// UnsupportedProtocolVersionError instead.
type DiscoverResult struct {
	SupportedVersions []string     `json:"supportedVersions"`
	Capabilities      Capabilities `json:"capabilities"`
	Instructions      string       `json:"instructions,omitempty"`
	// A pointer, so that omitempty means what it says: encoding/json ignores
	// omitempty on a struct, and a DiscoverResult built without serverInfo used
	// to ship "_meta":{} — an empty object in a namespace the spec reserves.
	Meta *ResultMeta `json:"_meta,omitempty"`
	CacheHint
}

// --- tools ------------------------------------------------------------------

// ToolAnnotations are the protocol hints a client uses to decide whether a call
// may be auto-approved. A server that sends none makes the client ask a human
// about every read it performs.
//
// The hints are pointers because their spec defaults are not all false:
// destructiveHint and openWorldHint default to true. A plain bool left unset
// marshalled as false and told the client the opposite of the default — that an
// unannotated tool is safe to auto-approve. Write one as new(true).
type ToolAnnotations struct {
	Title           string `json:"title,omitempty"`
	ReadOnlyHint    *bool  `json:"readOnlyHint,omitempty"`
	DestructiveHint *bool  `json:"destructiveHint,omitempty"`
	IdempotentHint  *bool  `json:"idempotentHint,omitempty"`
	OpenWorldHint   *bool  `json:"openWorldHint,omitempty"`
}

type Tool struct {
	Name        string          `json:"name"`
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	// OutputSchema describes the shape of StructuredContent. Declaring one is a
	// promise: "Servers MUST provide structured results that conform to this
	// schema", and clients validate against it. SchemaFor builds one from the
	// same struct the tool returns.
	OutputSchema json.RawMessage  `json:"outputSchema,omitempty"`
	Icons        []Icon           `json:"icons,omitempty"`
	Annotations  *ToolAnnotations `json:"annotations,omitempty"`
}

// Icon is a visual identifier a client may render beside a tool, a resource or
// a prompt. Src is an https: or data: URI; a client is required to reject any
// other scheme, so there is no point in sending one.
type Icon struct {
	Src      string   `json:"src"`
	MimeType string   `json:"mimeType,omitempty"`
	Sizes    []string `json:"sizes,omitempty"`
	Theme    string   `json:"theme,omitempty"`
}

// Annotations say who a piece of content is for and how much it matters. The
// same block is used by tools, resources and prompts.
type Annotations struct {
	Audience     []string `json:"audience,omitempty"`
	Priority     *float64 `json:"priority,omitempty"`
	LastModified string   `json:"lastModified,omitempty"`
}

// ToolList is a cacheable result: the caching hints are required on it, and
// the scope is private unless the server says otherwise — this list is computed
// per caller, and a public one may be served to anyone by any cache in between.
type ToolList struct {
	Tools []Tool `json:"tools"`
	// NextCursor continues the enumeration. Its absence is the end of it —
	// there is no other signal, so it must be omitted rather than sent empty.
	NextCursor string `json:"nextCursor,omitempty"`
	CacheHint
}

// ContentBlock is one piece of a tool's answer. The protocol defines five
// kinds and they share a field set, so this is one struct with the union
// written out rather than five types and a discriminator at every use.
//
// Which fields belong to which Type:
//
//	text           Text
//	image, audio   Data (base64), MimeType
//	resource_link  URI, Name, and the catalogue fields a ResourceEntry carries
//	resource       Resource — the contents inline, for an answer that should
//	               not cost a second round trip
type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
	// Data is base64, and it has to be: "Binary data MUST be properly encoded",
	// and raw bytes in a JSON string come out as U+FFFD.
	Data     string `json:"data,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
	// The resource_link fields. A link is how a tool points the model at
	// something in the catalogue instead of inlining it — the model reads the
	// description and decides whether the resource is worth a resources/read.
	URI         string `json:"uri,omitempty"`
	Name        string `json:"name,omitempty"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Size        int64  `json:"size,omitempty"`
	Icons       []Icon `json:"icons,omitempty"`
	// Resource carries a resource inline, for type "resource".
	Resource    *ResourceContent `json:"resource,omitempty"`
	Annotations *Annotations     `json:"annotations,omitempty"`
}

// ToolCallResult is the envelope of a tool answer. It carries no error code:
// a code is what a dispatcher needs to label a metric, and this type is the
// format. The code lives with the dispatcher, in mcptool.
type ToolCallResult struct {
	Content []ContentBlock `json:"content"`
	// StructuredContent is the answer as data rather than as text. A tool that
	// returns it "SHOULD also return the serialized JSON in a TextContent
	// block", which is why OKResult fills both: the field is what a client
	// validates and parses, the text block is what an older one reads.
	StructuredContent any  `json:"structuredContent,omitempty"`
	IsError           bool `json:"isError,omitempty"`
}

// Size is what the answer costs on the wire, in bytes — what an audit record
// reports as bytes_out for a tool that has no pre-cut figure of its own.
//
// Base64 counts. An image is the largest thing a tool can return, and leaving
// it out of the figure would make the one answer worth watching the one that
// reports zero.
func (r ToolCallResult) Size() int {
	n := 0
	for _, c := range r.Content {
		n += len(c.Text) + len(c.Data)
	}
	return n
}

// --- resources --------------------------------------------------------------

type ResourceEntry struct {
	URI         string       `json:"uri"`
	Name        string       `json:"name"`
	Title       string       `json:"title,omitempty"`
	Description string       `json:"description,omitempty"`
	MimeType    string       `json:"mimeType,omitempty"`
	Size        int64        `json:"size,omitempty"`
	Icons       []Icon       `json:"icons,omitempty"`
	Annotations *Annotations `json:"annotations,omitempty"`
}

// ResourceList is a cacheable result.
type ResourceList struct {
	Resources  []ResourceEntry `json:"resources"`
	NextCursor string          `json:"nextCursor,omitempty"`
	CacheHint
}

// ResourceContent carries one resource either as text or as base64 in Blob —
// "Binary data MUST be properly encoded", and a PNG pushed through Text comes
// out of the JSON encoder with U+FFFD in place of every byte that was not valid
// UTF-8. Exactly one of the two is set; an empty text resource sets neither,
// which a client reads as the empty string it is.
type ResourceContent struct {
	URI      string `json:"uri"`
	MimeType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"`
	Blob     string `json:"blob,omitempty"`
}

// ResourceData is a cacheable result: resources/read is on the list of
// operations whose answer carries caching hints.
type ResourceData struct {
	Contents []ResourceContent `json:"contents"`
	CacheHint
}

// --- prompts ----------------------------------------------------------------

// Argument is one declared input of a prompt. It lives here rather than in the
// package that loads prompts, so that the wire format does not depend on where
// prompts are stored.
type Argument struct {
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description,omitempty" yaml:"description"`
	Required    bool   `json:"required,omitempty" yaml:"required"`
}

type PromptEntry struct {
	Name        string     `json:"name"`
	Title       string     `json:"title,omitempty" yaml:"title"`
	Description string     `json:"description,omitempty"`
	Arguments   []Argument `json:"arguments,omitempty"`
	Icons       []Icon     `json:"icons,omitempty"`
}

// PromptList is a cacheable result.
type PromptList struct {
	Prompts    []PromptEntry `json:"prompts"`
	NextCursor string        `json:"nextCursor,omitempty"`
	CacheHint
}

type PromptMessageContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type PromptMessage struct {
	Role    string               `json:"role"`
	Content PromptMessageContent `json:"content"`
}

type RenderedPrompt struct {
	Description string          `json:"description,omitempty"`
	Messages    []PromptMessage `json:"messages"`
}

// --- envelopes ---------------------------------------------------------------

// TextResult wraps a plain string as a successful tool answer.
func TextResult(s string) ToolCallResult {
	return ToolCallResult{Content: []ContentBlock{{Type: ContentTypeText, Text: s}}}
}

// ErrorResult wraps a message as a failed tool answer. The protocol carries a
// tool failure inside a successful JSON-RPC response — the model is meant to
// read it and try again, which it cannot do with a transport-level error.
func ErrorResult(s string) ToolCallResult {
	return ToolCallResult{Content: []ContentBlock{{Type: ContentTypeText, Text: s}}, IsError: true}
}

// JSONResult marshals v and wraps it as a successful tool answer.
func JSONResult(v any) (ToolCallResult, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return ToolCallResult{}, err
	}
	return TextResult(string(b)), nil
}

// ImageBlock wraps raw bytes as an image block, encoding them itself so that no
// caller has to remember which of the two forms this field takes.
func ImageBlock(data []byte, mimeType string) ContentBlock {
	return binaryBlock(ContentTypeImage, data, mimeType)
}

// AudioBlock is ImageBlock for audio.
func AudioBlock(data []byte, mimeType string) ContentBlock {
	return binaryBlock(ContentTypeAudio, data, mimeType)
}

func binaryBlock(kind string, data []byte, mimeType string) ContentBlock {
	return ContentBlock{
		Type:     kind,
		Data:     base64.StdEncoding.EncodeToString(data),
		MimeType: mimeType,
	}
}

// ResourceLinkBlock points the model at a catalogue entry instead of inlining
// it. The entry is the same one resources/list hands out, so a tool that
// searches the catalogue returns what it found rather than a description of it.
func ResourceLinkBlock(e ResourceEntry) ContentBlock {
	return ContentBlock{
		Type:        ContentTypeResourceLink,
		URI:         e.URI,
		Name:        e.Name,
		Title:       e.Title,
		Description: e.Description,
		MimeType:    e.MimeType,
		Size:        e.Size,
		Icons:       e.Icons,
		Annotations: e.Annotations,
	}
}

// ResourceBlock carries a resource inline — the answer for something the model
// will certainly read, where a link would only buy a second round trip.
func ResourceBlock(c ResourceContent) ContentBlock {
	return ContentBlock{Type: ContentTypeResource, Resource: &c}
}

// --- resultType ---------------------------------------------------------------
//
// Every top-level result carries it; the nested objects (Tool, ResourceEntry,
// ContentBlock, …) do not, because the field marks an answer, not a value
// inside one. The alias type in each method is what stops MarshalJSON from
// calling itself.

func (r InitializeResult) MarshalJSON() ([]byte, error) {
	type alias InitializeResult
	return completeResult(alias(r))
}

func (r PingResult) MarshalJSON() ([]byte, error) {
	type alias PingResult
	return completeResult(alias(r))
}

func (r DiscoverResult) MarshalJSON() ([]byte, error) {
	type alias DiscoverResult
	return completeResult(alias(r))
}

func (r ToolList) MarshalJSON() ([]byte, error) {
	type alias ToolList
	return completeResult(alias(r))
}

func (r ToolCallResult) MarshalJSON() ([]byte, error) {
	type alias ToolCallResult
	return completeResult(alias(r))
}

func (r ResourceList) MarshalJSON() ([]byte, error) {
	type alias ResourceList
	return completeResult(alias(r))
}

func (r ResourceData) MarshalJSON() ([]byte, error) {
	type alias ResourceData
	return completeResult(alias(r))
}

func (r PromptList) MarshalJSON() ([]byte, error) {
	type alias PromptList
	return completeResult(alias(r))
}

func (r RenderedPrompt) MarshalJSON() ([]byte, error) {
	type alias RenderedPrompt
	return completeResult(alias(r))
}

// Map converts a slice of T to a slice of M with the given converter.
func Map[T, M any](a []T, f func(T) M) []M {
	n := make([]M, len(a))
	for i := range a {
		n[i] = f(a[i])
	}
	return n
}
