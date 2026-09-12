package auth

import (
	"encoding/json"
	"net/http"
)

// DefaultScopes is what the metadata advertises when ProtectedResource names
// no scopes of its own.
var DefaultScopes = []string{"openid", "profile", "email", "groups"}

// ProtectedResource serves RFC 9728 protected-resource metadata. MCP clients
// fetch it after a 401 and drive OAuth against
// authorization_servers[0]/.well-known/openid-configuration.
//
// Mount it at /.well-known/oauth-protected-resource.
type ProtectedResource struct {
	// Resource is the canonical URI of the MCP endpoint, e.g.
	// https://host/mcp. The service computes it: it has the base URL from its
	// own config, and the request to fall back on when that is empty.
	Resource string
	// Issuer is the OIDC issuer clients should authenticate against.
	Issuer string
	// Scopes advertised to the client; nil means DefaultScopes.
	Scopes []string
}

// Handler returns the metadata endpoint.
//
// Without an issuer it answers 404 rather than a document with an empty list:
// the document tells a client "this resource is protected", and the client
// then starts OAuth against a server that wants no authentication at all and
// dies on a missing client_id. A server with no issuer has nothing to point
// at, and saying so is the only honest answer.
func (p ProtectedResource) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if p.Issuer == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		scopes := p.Scopes
		if scopes == nil {
			scopes = DefaultScopes
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":                 p.Resource,
			"authorization_servers":    []string{p.Issuer},
			"bearer_methods_supported": []string{"header"},
			"scopes_supported":         scopes,
		})
	})
}
