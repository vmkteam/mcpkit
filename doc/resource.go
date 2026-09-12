package doc

import (
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"path"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/vmkteam/mcpkit/mcp"
)

// errNoScheme is what Load returns when it was given documents but no scheme to
// name them with.
var errNoScheme = errors.New("doc: Options.URIScheme is required")

// MIME types the standard library does not know.
const (
	MimeMarkdown = "text/markdown"
	MimeYAML     = "application/yaml"
	MimeTOML     = "application/toml"
)

var registerMimeOnce sync.Once

// Resources returns every loaded resource in walk order. The slice is shared —
// do not mutate it.
func (l *Library) Resources() []mcp.ResourceEntry { return l.resources }

// NormalizeURI expands a bare path to the canonical URI and leaves an
// already-canonical URI untouched.
//
// It is not cosmetic: these URIs arrive typed by the model out of instruction
// text, and the scheme goes missing regularly.
func (l *Library) NormalizeURI(uri string) string {
	uri = strings.TrimSpace(uri)
	if uri == "" || strings.HasPrefix(uri, l.opts.URIScheme) {
		return uri
	}
	return l.opts.URIScheme + strings.TrimPrefix(uri, "/")
}

// Read returns the bytes and MIME type of a resource by URI, accepting the
// canonical URI or the bare path.
func (l *Library) Read(uri string) ([]byte, string, error) {
	idx, ok := l.byURI[l.NormalizeURI(uri)]
	if !ok {
		return nil, "", fmt.Errorf("doc: unknown resource %q: %w", uri, mcp.ErrInvalidParams)
	}
	entry, f := l.resources[idx], l.files[idx]
	data, err := fs.ReadFile(f.fsys, f.path)
	if err != nil {
		return nil, "", err
	}
	return data, entry.MimeType, nil
}

func (l *Library) addResource(fsys fs.FS, p, rel string) error {
	entry := mcp.ResourceEntry{
		URI:      l.opts.URIScheme + rel,
		Name:     rel,
		MimeType: detectMime(path.Base(p)),
	}
	data, err := fs.ReadFile(fsys, p)
	if err != nil {
		return fmt.Errorf("doc: read %s: %w", p, err)
	}
	// Only a text file gets read for a name and a description. A binary one has
	// no frontmatter to find and no first paragraph to derive: the parser hands
	// the whole file back unchanged, and the first 240 bytes of a PNG became the
	// description the model reads — rendered by the JSON encoder as a row of
	// U+FFFD, because those bytes are not text. Scanning it was also the most
	// expensive thing the loader did: a split of the entire file to take a
	// paragraph that does not exist.
	if mcp.IsTextualMIME(entry.MimeType) && utf8.Valid(data) {
		if name, title, desc := l.scanFrontmatter(data); name != "" || title != "" || desc != "" {
			if name != "" {
				entry.Name = name
			}
			// Title is taken only when the file says so: a title invented from
			// the path would be a second name with no authority behind it.
			entry.Title = title
			entry.Description = desc
		}
	}
	entry.Size = int64(len(data))
	// A duplicate URI is a load failure, not a silent overwrite: which of the
	// two files won would be decided by walk order, and nobody would notice.
	if _, dup := l.byURI[entry.URI]; dup {
		return fmt.Errorf("doc: duplicate resource uri %q", entry.URI)
	}
	l.byURI[entry.URI] = len(l.resources)
	l.resources = append(l.resources, entry)
	l.files = append(l.files, file{fsys: fsys, path: p})
	return nil
}

// detectMime returns a coarse MIME type by file extension, registering the
// extensions the standard library misses on first call.
func detectMime(filename string) string {
	registerMimeOnce.Do(func() {
		for e, mimeType := range map[string]string{
			".md":       MimeMarkdown,
			".markdown": MimeMarkdown,
			".yaml":     MimeYAML,
			".yml":      MimeYAML,
			".toml":     MimeTOML,
		} {
			_ = mime.AddExtensionType(e, mimeType)
		}
	})
	if t := mime.TypeByExtension(strings.ToLower(path.Ext(filename))); t != "" {
		// Strip ;charset=… — MCP clients want the bare type.
		before, _, _ := strings.Cut(t, ";")
		return strings.TrimSpace(before)
	}
	return "text/plain"
}
