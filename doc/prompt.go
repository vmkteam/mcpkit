package doc

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"text/template"

	"github.com/vmkteam/mcpkit/mcp"

	"github.com/adrg/frontmatter"
)

// prompt is one parsed prompt file. The parsed template stays inside the
// package: a template is a detail of loading, and what leaves is the rendered
// text.
//
// The file is markdown with YAML frontmatter:
//
//	---
//	name: investigate
//	description: Short human description.
//	arguments:
//	  - name: service
//	    description: ...
//	    required: true
//	---
//
//	Body with {{service}} placeholders.
type prompt struct {
	entry mcp.PromptEntry
	tpl   *template.Template
}

// promptMeta is the frontmatter of a prompt file.
type promptMeta struct {
	Name        string         `yaml:"name"`
	Description string         `yaml:"description"`
	Arguments   []mcp.Argument `yaml:"arguments"`
}

// placeholderRE rewrites {{name}} into {{.name}} so that text/template
// understands it. A human writing markdown is not required to know about Go
// templates — that is the whole point of the rewrite. An already-prefixed
// {{.name}} is left alone.
var placeholderRE = regexp.MustCompile(`\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}`)

// Prompts returns every loaded prompt, sorted by name. The slice is shared — do
// not mutate it.
func (l *Library) Prompts() []mcp.PromptEntry { return l.prompts }

// Prompt returns one prompt's declaration by name.
func (l *Library) Prompt(name string) (mcp.PromptEntry, error) {
	p, ok := l.byName[name]
	if !ok {
		return mcp.PromptEntry{}, fmt.Errorf("doc: unknown prompt %q: %w", name, mcp.ErrInvalidParams)
	}
	return p.entry, nil
}

// Render fills the placeholders of a prompt and returns its description and the
// finished text. An unknown argument renders as an empty string; a missing
// required one is an error.
func (l *Library) Render(name string, args map[string]string) (description, text string, err error) {
	p, ok := l.byName[name]
	if !ok {
		return "", "", fmt.Errorf("doc: unknown prompt %q: %w", name, mcp.ErrInvalidParams)
	}
	for _, a := range p.entry.Arguments {
		if !a.Required {
			continue
		}
		if _, has := args[a.Name]; !has {
			return "", "", fmt.Errorf("doc: missing required argument %q: %w", a.Name, mcp.ErrInvalidParams)
		}
	}
	var buf bytes.Buffer
	if err := p.tpl.Execute(&buf, args); err != nil {
		return "", "", fmt.Errorf("doc: render %s: %w", name, err)
	}
	return p.entry.Description, buf.String(), nil
}

func (l *Library) addPrompt(fsys fs.FS, p string) error {
	data, err := fs.ReadFile(fsys, p)
	if err != nil {
		return fmt.Errorf("doc: read %s: %w", p, err)
	}
	parsed, err := parsePrompt(data)
	if err != nil {
		return fmt.Errorf("doc: %s: %w", p, err)
	}
	if _, dup := l.byName[parsed.entry.Name]; dup {
		return fmt.Errorf("doc: duplicate prompt name %q in %s", parsed.entry.Name, p)
	}
	l.byName[parsed.entry.Name] = parsed
	l.prompts = append(l.prompts, parsed.entry)
	return nil
}

func (l *Library) sortPrompts() {
	sort.Slice(l.prompts, func(i, j int) bool { return l.prompts[i].Name < l.prompts[j].Name })
}

func parsePrompt(data []byte) (*prompt, error) {
	var meta promptMeta
	rest, err := frontmatter.Parse(bytes.NewReader(data), &meta)
	if err != nil {
		return nil, fmt.Errorf("frontmatter: %w", err)
	}
	if meta.Name == "" {
		return nil, errors.New("frontmatter is missing required field name")
	}
	body := placeholderRE.ReplaceAllString(string(rest), "{{.$1}}")
	tpl, err := template.New(meta.Name).Option("missingkey=zero").Parse(body)
	if err != nil {
		return nil, fmt.Errorf("template: %w", err)
	}
	return &prompt{
		entry: mcp.PromptEntry{
			Name:        meta.Name,
			Description: meta.Description,
			Arguments:   meta.Arguments,
		},
		tpl: tpl,
	}, nil
}
