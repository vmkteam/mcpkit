// Package doc loads a tree of markdown and serves it over MCP: everything
// outside the prompts subtree as a resource, the prompts subtree as prompts.
// Both are markdown with YAML frontmatter, read from one fs.FS at startup — an
// embed.FS in production, an os.DirFS in a dev run so that editing a file needs
// no rebuild, an fstest.MapFS in a test.
//
//	md/targets/grafana.md     → resource <scheme>targets/grafana.md
//	md/prompts/investigate.md → prompt  "investigate"
//
// The library speaks the protocol types directly: *Library is what
// mcpkit.NewResourcesService and mcpkit.NewPromptsService take, with no adapter
// in between and no second vocabulary for the same thing.
package doc

import (
	"bytes"
	"io/fs"
	"strings"

	"github.com/vmkteam/mcpkit/mcp"

	"github.com/adrg/frontmatter"
)

// DefaultPromptsDir is the subtree that holds prompts when Options names none.
const DefaultPromptsDir = "prompts"

// DefaultDescMaxLen caps a description derived from the body of a file.
const DefaultDescMaxLen = 240

// Options configures Load.
type Options struct {
	// URIScheme prefixes every resource URI, e.g. "docs://" or "srv://catalog/".
	// Required: a library with no scheme cannot name its resources.
	URIScheme string
	// PromptsDir is the one subtree that holds prompts. Empty means
	// DefaultPromptsDir.
	PromptsDir string
	// DescMaxLen caps a description derived from the body; 0 means
	// DefaultDescMaxLen.
	DescMaxLen int
}

// Library is an in-memory index of everything loaded from one fs.FS.
type Library struct {
	opts Options

	resources []mcp.ResourceEntry
	files     []file
	byURI     map[string]int

	prompts []mcp.PromptEntry
	byName  map[string]*prompt
}

// file is where a resource actually lives; it is kept beside the protocol entry
// rather than inside it, so that resources/list hands out the wire form with no
// conversion.
type file struct {
	fsys fs.FS
	path string
}

// Load walks fsys from root and indexes every regular file: markdown under the
// prompts subtree as a prompt, everything else as a resource.
//
// A nil fsys produces an empty library rather than an error — a dev run with no
// documents still has to boot.
func Load(fsys fs.FS, root string, opts Options) (*Library, error) {
	if opts.PromptsDir == "" {
		opts.PromptsDir = DefaultPromptsDir
	}
	if opts.DescMaxLen <= 0 {
		opts.DescMaxLen = DefaultDescMaxLen
	}
	l := &Library{opts: opts, byURI: map[string]int{}, byName: map[string]*prompt{}}
	if fsys == nil {
		return l, nil
	}
	if opts.URIScheme == "" {
		return nil, errNoScheme
	}
	if root == "" {
		root = "."
	}
	err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// A hidden directory is skipped whole, not walked with its files
		// admitted one by one: on the os.DirFS of a dev run the tree contains
		// .git, and a resource catalogue full of loose objects is not a
		// catalogue. The root itself is never skipped — it may legitimately be
		// named "." or live under a dot-directory the caller chose.
		if d.IsDir() {
			if p != root && strings.HasPrefix(d.Name(), ".") {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(d.Name(), ".") {
			return nil
		}
		rel := relTo(root, p)
		if l.isPrompt(rel) {
			return l.addPrompt(fsys, p)
		}
		return l.addResource(fsys, p, rel)
	})
	if err != nil {
		return nil, err
	}
	l.sortPrompts()
	return l, nil
}

func relTo(root, p string) string {
	if root == "." {
		return p
	}
	return strings.TrimPrefix(p, root+"/")
}

func (l *Library) isPrompt(rel string) bool {
	return strings.HasPrefix(rel, l.opts.PromptsDir+"/") && strings.EqualFold(ext(rel), ".md")
}

func ext(p string) string {
	if i := strings.LastIndex(p, "."); i >= 0 {
		return p[i:]
	}
	return ""
}

// metadata is the subset of the frontmatter shared by resources and prompts.
type metadata struct {
	Name        string `yaml:"name"`
	Title       string `yaml:"title"`
	Description string `yaml:"description"`
}

// scanFrontmatter returns the name and description of a file. The description
// prefers the frontmatter field and falls back to the first prose paragraph of
// the body: the model sees it in resources/list, and an entry with no
// description costs a call to find out what it is.
func (l *Library) scanFrontmatter(data []byte) (name, title, description string) {
	var meta metadata
	rest, err := frontmatter.Parse(bytes.NewReader(data), &meta)
	if err != nil {
		// Broken frontmatter does not fail a resource: the file is simply taken
		// whole. A prompt is stricter — without a name there is nothing to call
		// it by — and parsePrompt says so.
		rest = data
	}
	desc := meta.Description
	if desc == "" {
		desc = firstParagraph(rest)
	}
	// On a rune boundary, not on a byte offset: this description goes into
	// resources/list as JSON, and a cut through the middle of a character makes
	// the encoder substitute U+FFFD for the half it got. Every non-ASCII
	// description longer than the cap hit that.
	if cut, ok := mcp.CutRunes(desc, l.opts.DescMaxLen); ok {
		desc = cut + "..."
	}
	return meta.Name, meta.Title, desc
}

func firstParagraph(body []byte) string {
	src := strings.Split(string(body), "\n")
	lines := make([]string, 0, len(src))
	for _, line := range src {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			if len(lines) > 0 {
				break
			}
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		lines = append(lines, trimmed)
	}
	return strings.Join(lines, " ")
}
