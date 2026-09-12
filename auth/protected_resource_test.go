package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fetchMetadata(t *testing.T, p ProtectedResource) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	p.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil))
	if rec.Code != http.StatusOK {
		return rec, nil
	}
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	return rec, body
}

func TestProtectedResource(t *testing.T) {
	t.Parallel()
	const (
		resource = "https://mcp.example.com/mcp"
		issuer   = "https://idp.example.com/application/o/mcp/"
	)

	t.Run("the document points at the issuer", func(t *testing.T) {
		t.Parallel()
		rec, body := fetchMetadata(t, ProtectedResource{Resource: resource, Issuer: issuer})

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
		assert.Equal(t, resource, body["resource"], "the canonical URI, byte for byte")
		assert.Equal(t, []any{issuer}, body["authorization_servers"])
		assert.Equal(t, []any{"header"}, body["bearer_methods_supported"])
	})

	t.Run("scopes default to the openid set", func(t *testing.T) {
		t.Parallel()
		_, body := fetchMetadata(t, ProtectedResource{Resource: resource, Issuer: issuer})

		want := make([]any, 0, len(DefaultScopes))
		for _, s := range DefaultScopes {
			want = append(want, s)
		}
		assert.Equal(t, want, body["scopes_supported"])
	})

	t.Run("configured scopes replace the default set", func(t *testing.T) {
		t.Parallel()
		_, body := fetchMetadata(t, ProtectedResource{
			Resource: resource, Issuer: issuer, Scopes: []string{"openid", "mcp:read"},
		})
		assert.Equal(t, []any{"openid", "mcp:read"}, body["scopes_supported"])
	})

	// Without an issuer the document has nothing to point at. Publishing it
	// anyway says "this resource is protected" and gives no way to
	// authenticate: a client finds it, starts OAuth and dies on a missing
	// client_id against a server that wanted no auth at all.
	t.Run("no issuer means no metadata at all", func(t *testing.T) {
		t.Parallel()
		rec, _ := fetchMetadata(t, ProtectedResource{Resource: resource})
		assert.Equal(t, http.StatusNotFound, rec.Code)
		assert.Empty(t, rec.Body.String())
	})
}
