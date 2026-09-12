package doc

import (
	"strings"
	"testing"
	"testing/fstest"
	"unicode/utf8"

	"github.com/vmkteam/mcpkit/mcp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A description derived from a non-ASCII body used to be cut at a byte offset,
// which lands mid-rune for every alphabet that is not English: the JSON encoder
// then substituted U+FFFD for the half it got.
func TestDescriptionCutsOnARuneBoundary(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"cyrillic":        strings.Repeat("я", 300),
		"cyrillic offset": "x" + strings.Repeat("я", 300),
		"cjk":             strings.Repeat("世", 300),
		"emoji":           strings.Repeat("🙂", 200),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			l, err := Load(
				fstest.MapFS{"md/a.md": &fstest.MapFile{Data: []byte(body)}},
				"md", Options{URIScheme: "docs://"},
			)
			require.NoError(t, err)
			desc := l.Resources()[0].Description
			assert.True(t, utf8.ValidString(desc), "description must stay valid UTF-8: %q", desc)
			assert.True(t, strings.HasSuffix(desc, "..."), "a cut description says so")
		})
	}
}

// A dev run loads documents from an os.DirFS, and that tree has a .git in it.
func TestHiddenDirectoriesAreSkipped(t *testing.T) {
	t.Parallel()
	l, err := Load(fstest.MapFS{
		"md/keep.md":              &fstest.MapFile{Data: []byte("kept")},
		"md/.git/objects/ab/cdef": &fstest.MapFile{Data: []byte("loose object")},
		"md/.hidden/secret.md":    &fstest.MapFile{Data: []byte("not a document")},
		"md/nested/.git/config":   &fstest.MapFile{Data: []byte("[core]")},
		"md/nested/also-kept.md":  &fstest.MapFile{Data: []byte("kept too")},
	}, "md", Options{URIScheme: "docs://"})
	require.NoError(t, err)

	uris := make([]string, 0, len(l.Resources()))
	for _, r := range l.Resources() {
		uris = append(uris, r.URI)
	}
	assert.ElementsMatch(t, []string{"docs://keep.md", "docs://nested/also-kept.md"}, uris)
}

const testScheme = "docs://"

func testFS() fstest.MapFS {
	return fstest.MapFS{
		"md/targets/grafana.md": &fstest.MapFile{Data: []byte(
			"---\nname: grafana\ndescription: Dashboards and panels.\n---\n\nBody.\n")},
		"md/targets/sentry.md": &fstest.MapFile{Data: []byte(
			"# Heading\n\nFirst prose paragraph\nsecond line.\n\nSecond paragraph.\n")},
		"md/schema.yaml":        &fstest.MapFile{Data: []byte("key: value\n")},
		"md/.hidden.md":         &fstest.MapFile{Data: []byte("skipped")},
		"md/prompts/triage.md":  &fstest.MapFile{Data: []byte("---\nname: triage\ndescription: Triage a alert.\narguments:\n  - name: service\n    description: Service name.\n    required: true\n  - name: since\n    description: Window.\n---\n\nLook at {{service}} since {{since}}.\n")},
		"md/prompts/notes.txt":  &fstest.MapFile{Data: []byte("not a prompt, it is a resource")},
		"md/prompts/explain.md": &fstest.MapFile{Data: []byte("---\nname: explain\n---\n\nExplain it.\n")},
	}
}

func load(t *testing.T) *Library {
	t.Helper()
	l, err := Load(testFS(), "md", Options{URIScheme: testScheme})
	require.NoError(t, err)
	return l
}

func TestLoad_SplitsPromptsFromResources(t *testing.T) {
	t.Parallel()
	l := load(t)

	uris := mcp.Map(l.Resources(), func(r mcp.ResourceEntry) string { return r.URI })
	assert.ElementsMatch(t, []string{
		testScheme + "targets/grafana.md",
		testScheme + "targets/sentry.md",
		testScheme + "schema.yaml",
		testScheme + "prompts/notes.txt", // not markdown — a resource, not a prompt
	}, uris, "everything outside the prompts subtree, plus non-markdown inside it")

	names := mcp.Map(l.Prompts(), func(p mcp.PromptEntry) string { return p.Name })
	assert.Equal(t, []string{"explain", "triage"}, names, "prompts are sorted by name")

	assert.NotContains(t, uris, testScheme+".hidden.md", "dotfiles are skipped")
}

func TestLoad_Descriptions(t *testing.T) {
	t.Parallel()
	l := load(t)
	byURI := map[string]mcp.ResourceEntry{}
	for _, r := range l.Resources() {
		byURI[r.URI] = r
	}

	t.Run("from frontmatter", func(t *testing.T) {
		t.Parallel()
		r := byURI[testScheme+"targets/grafana.md"]
		assert.Equal(t, "grafana", r.Name, "the frontmatter name wins over the path")
		assert.Equal(t, "Dashboards and panels.", r.Description)
	})

	// The description is what the model reads in resources/list; an entry
	// without one costs a call to find out what it is.
	t.Run("falls back to the first prose paragraph", func(t *testing.T) {
		t.Parallel()
		r := byURI[testScheme+"targets/sentry.md"]
		assert.Equal(t, "targets/sentry.md", r.Name, "no frontmatter name — the path is the name")
		assert.Equal(t, "First prose paragraph second line.", r.Description,
			"headings are skipped and the paragraph is joined into one line")
	})

	t.Run("capped at DescMaxLen", func(t *testing.T) {
		t.Parallel()
		long := fstest.MapFS{"a.md": &fstest.MapFile{Data: []byte("aaaaaaaaaaaaaaaaaaaa")}}
		l, err := Load(long, ".", Options{URIScheme: testScheme, DescMaxLen: 5})
		require.NoError(t, err)
		assert.Equal(t, "aaaaa...", l.Resources()[0].Description)
	})
}

func TestLoad_MimeTypes(t *testing.T) {
	t.Parallel()
	l := load(t)
	byURI := map[string]mcp.ResourceEntry{}
	for _, r := range l.Resources() {
		byURI[r.URI] = r
	}
	assert.Equal(t, MimeMarkdown, byURI[testScheme+"targets/grafana.md"].MimeType)
	assert.Equal(t, MimeYAML, byURI[testScheme+"schema.yaml"].MimeType) //nolint:testifylint // a mime type, not a yaml document
	assert.Equal(t, "text/plain", byURI[testScheme+"prompts/notes.txt"].MimeType,
		"an unknown extension is text/plain, and the charset is stripped")
}

// URIs reach Read typed by the model out of instruction text, and the scheme
// goes missing regularly.
func TestRead_AcceptsBarePaths(t *testing.T) {
	t.Parallel()
	l := load(t)

	canonical, mimeType, err := l.Read(testScheme + "targets/grafana.md")
	require.NoError(t, err)
	assert.Contains(t, string(canonical), "Body.")
	assert.Equal(t, MimeMarkdown, mimeType)

	for _, form := range []string{"targets/grafana.md", "/targets/grafana.md", "  targets/grafana.md  "} {
		bare, _, readErr := l.Read(form)
		require.NoErrorf(t, readErr, "form %q", form)
		assert.Equal(t, canonical, bare, "form %q", form)
	}

	_, _, err = l.Read("targets/nope.md")
	assert.ErrorContains(t, err, "unknown resource")
}

func TestNormalizeURI(t *testing.T) {
	t.Parallel()
	l := load(t)
	assert.Equal(t, testScheme+"a/b.md", l.NormalizeURI("a/b.md"))
	assert.Equal(t, testScheme+"a/b.md", l.NormalizeURI("/a/b.md"))
	assert.Equal(t, testScheme+"a/b.md", l.NormalizeURI(testScheme+"a/b.md"), "already canonical")
	assert.Empty(t, l.NormalizeURI(""))
}

// The scheme is an option rather than a constant, and a different one produces
// different URIs from the same tree — that is how a service keeps the URIs its
// instruction texts already name.
func TestURISchemeComesFromOptions(t *testing.T) {
	t.Parallel()
	l, err := Load(testFS(), "md", Options{URIScheme: "srv://catalog/"})
	require.NoError(t, err)
	assert.Contains(t,
		mcp.Map(l.Resources(), func(r mcp.ResourceEntry) string { return r.URI }),
		"srv://catalog/targets/grafana.md")
}

func TestPromptsDirComesFromOptions(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{
		"scenarios/one.md": &fstest.MapFile{Data: []byte("---\nname: one\n---\nbody")},
		"prompts/two.md":   &fstest.MapFile{Data: []byte("---\nname: two\n---\nbody")},
	}
	l, err := Load(fsys, ".", Options{URIScheme: testScheme, PromptsDir: "scenarios"})
	require.NoError(t, err)

	assert.Equal(t, []string{"one"}, mcp.Map(l.Prompts(), func(p mcp.PromptEntry) string { return p.Name }))
	assert.Contains(t,
		mcp.Map(l.Resources(), func(r mcp.ResourceEntry) string { return r.URI }),
		testScheme+"prompts/two.md", "the default subtree is just a subtree now")
}

func TestRender(t *testing.T) {
	t.Parallel()
	l := load(t)

	t.Run("placeholders are filled", func(t *testing.T) {
		t.Parallel()
		desc, text, err := l.Render("triage", map[string]string{"service": "apisrv", "since": "now-1h"})
		require.NoError(t, err)
		assert.Equal(t, "Triage a alert.", desc)
		assert.Equal(t, "\nLook at apisrv since now-1h.\n", text,
			"the body starts where the frontmatter ended, blank line and all")
	})

	// A human writing markdown is not required to know about Go templates.
	t.Run("an optional argument left out renders empty", func(t *testing.T) {
		t.Parallel()
		_, text, err := l.Render("triage", map[string]string{"service": "apisrv"})
		require.NoError(t, err)
		assert.Equal(t, "\nLook at apisrv since .\n", text)
	})

	t.Run("a missing required argument is an error", func(t *testing.T) {
		t.Parallel()
		_, _, err := l.Render("triage", map[string]string{"since": "now-1h"})
		assert.ErrorContains(t, err, `missing required argument "service"`)
	})

	t.Run("unknown prompt", func(t *testing.T) {
		t.Parallel()
		_, _, err := l.Render("nope", nil)
		assert.ErrorContains(t, err, `unknown prompt "nope"`)
	})
}

func TestPromptDeclaration(t *testing.T) {
	t.Parallel()
	l := load(t)

	p, err := l.Prompt("triage")
	require.NoError(t, err)
	assert.Equal(t, "Triage a alert.", p.Description)
	require.Len(t, p.Arguments, 2)
	assert.Equal(t, mcp.Argument{Name: "service", Description: "Service name.", Required: true}, p.Arguments[0])
	assert.False(t, p.Arguments[1].Required)

	_, err = l.Prompt("nope")
	assert.ErrorContains(t, err, "unknown prompt")
}

// A dev run without documents embedded still has to boot.
func TestNilFsysIsEmptyLibrary(t *testing.T) {
	t.Parallel()
	l, err := Load(nil, "", Options{})
	require.NoError(t, err)
	assert.Empty(t, l.Resources())
	assert.Empty(t, l.Prompts())
}

// A library with documents but no scheme cannot name them.
func TestSchemeIsRequiredWithDocuments(t *testing.T) {
	t.Parallel()
	_, err := Load(testFS(), "md", Options{})
	assert.ErrorIs(t, err, errNoScheme)
}

// Of two files claiming one name the winner would be decided by walk order, and
// nobody would notice.
func TestDuplicatesAreRejected(t *testing.T) {
	t.Parallel()

	t.Run("prompt name", func(t *testing.T) {
		t.Parallel()
		fsys := fstest.MapFS{
			"prompts/a.md": &fstest.MapFile{Data: []byte("---\nname: same\n---\nA")},
			"prompts/b.md": &fstest.MapFile{Data: []byte("---\nname: same\n---\nB")},
		}
		_, err := Load(fsys, ".", Options{URIScheme: testScheme})
		assert.ErrorContains(t, err, `duplicate prompt name "same"`)
	})

	t.Run("resource uri", func(t *testing.T) {
		t.Parallel()
		// Two roots folded onto one URI by the scheme.
		fsys := fstest.MapFS{"a.md": &fstest.MapFile{Data: []byte("A")}}
		l, err := Load(fsys, ".", Options{URIScheme: testScheme})
		require.NoError(t, err)
		require.Len(t, l.Resources(), 1)
		assert.ErrorContains(t, l.addResource(fsys, "a.md", "a.md"), "duplicate resource uri")
	})
}

func TestPromptWithoutNameRejected(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{"prompts/a.md": &fstest.MapFile{Data: []byte("---\ndescription: no name\n---\nbody")}}
	_, err := Load(fsys, ".", Options{URIScheme: testScheme})
	assert.ErrorContains(t, err, "missing required field name")
}

// Broken frontmatter does not fail a resource: there is nothing in a resource
// that the file cannot do without, so the file is taken whole.
func TestResourceWithBrokenFrontmatterLoadsWhole(t *testing.T) {
	t.Parallel()
	body := "---\nname: [unclosed\n---\n\nStill readable.\n"
	fsys := fstest.MapFS{"a.md": &fstest.MapFile{Data: []byte(body)}}
	l, err := Load(fsys, ".", Options{URIScheme: testScheme})
	require.NoError(t, err)

	require.Len(t, l.Resources(), 1)
	assert.Equal(t, "a.md", l.Resources()[0].Name)
	data, _, err := l.Read("a.md")
	require.NoError(t, err)
	assert.Equal(t, body, string(data))
}

func TestDetectMime(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"a.md":       MimeMarkdown,
		"a.markdown": MimeMarkdown,
		"a.yaml":     MimeYAML,
		"a.yml":      MimeYAML,
		"a.toml":     MimeTOML,
		"a.txt":      "text/plain",
		"a.unknown":  "text/plain",
		"a":          "text/plain",
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := detectMime(name)
			assert.Equal(t, want, got)
			assert.NotContains(t, got, "charset", "clients want the bare type")
		})
	}
}

// A catalogue indexes every file of the tree it is given, and not every file is
// text. The description used to be derived from the raw bytes of all of them:
// frontmatter.Parse hands a file with no front matter back unchanged, so the
// first 240 bytes of a PNG became the description the model reads — rendered by
// the JSON encoder as a row of U+FFFD, because those bytes are not text.
func TestBinaryFilesGetNoDerivedDescription(t *testing.T) {
	t.Parallel()
	png := append([]byte("\x89PNG\r\n\x1a\n"), 0xff, 0xfe, 0xfd, 0x80, 0x81)

	l, err := Load(fstest.MapFS{
		"md/logo.png":   &fstest.MapFile{Data: png},
		"md/broken.txt": &fstest.MapFile{Data: []byte{0x48, 0xff, 0xfe, 0x69}},
		"md/hello.md":   &fstest.MapFile{Data: []byte("---\nname: hello\n---\n\nA sentence.\n")},
	}, "md", Options{URIScheme: "docs://"})
	require.NoError(t, err)

	byURI := map[string]mcp.ResourceEntry{}
	for _, e := range l.Resources() {
		byURI[e.URI] = e
	}

	for _, uri := range []string{"docs://logo.png", "docs://broken.txt"} {
		e := byURI[uri]
		assert.Emptyf(t, e.Description, "%s: a binary file describes nothing", uri)
		assert.Truef(t, utf8.ValidString(e.Name), "%s: the name has to survive the JSON encoder", uri)
		assert.Positivef(t, e.Size, "%s: it is still a resource, and still has a size", uri)
	}

	// The control: a text file is still read, so the guard did not cost the
	// catalogue what it is for.
	assert.Equal(t, "hello", byURI["docs://hello.md"].Name)
	assert.Equal(t, "A sentence.", byURI["docs://hello.md"].Description)
}
