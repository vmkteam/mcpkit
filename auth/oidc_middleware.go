package auth

import (
	"errors"
	"net/http"

	"github.com/vmkteam/embedlog"
)

// Middleware enforces OIDC JWT auth on the wrapped handler. On 401 it sets
// WWW-Authenticate per RFC 9728 §5.1 with resource_metadata — that is what
// makes an MCP client auto-discover the authorization server instead of
// reporting a dead endpoint.
func (v *Verifier) Middleware(next http.Handler, logger embedlog.Logger) http.Handler {
	m := metric()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := BearerFromRequest(r)
		if token == "" {
			m.WithLabelValues(resultMissing).Inc()
			logger.Error(r.Context(), "mcp oidc auth missing token", "remote", r.RemoteAddr)
			w.Header().Set("WWW-Authenticate", v.wwwAuthenticate(""))
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		claims, err := v.Verify(r.Context(), token)
		if err != nil {
			result := resultInvalid
			status := http.StatusUnauthorized
			// What the caller is told and what the operator is told are not the
			// same thing. The error carries the roles and groups of the token
			// and the audience this server expects; the first is the caller's
			// own data and the second is configuration, and neither belongs in
			// a response to a request that just failed to authenticate.
			public := "invalid token"
			switch {
			case errors.Is(err, ErrExpiredToken):
				result, public = resultExpired, "token expired"
			case errors.Is(err, ErrNoRoles):
				result, status, public = resultForbidden, http.StatusForbidden, "insufficient permissions"
			}
			m.WithLabelValues(result).Inc()
			logger.Error(r.Context(), "mcp oidc auth failed", "remote", r.RemoteAddr, "err", err.Error())
			w.Header().Set("WWW-Authenticate", v.wwwAuthenticate(`error="invalid_token"`))
			http.Error(w, public, status)
			return
		}
		m.WithLabelValues(resultOK).Inc()
		p := Principal{
			UserID: claims.Subject,
			Email:  claims.Email,
			Roles:  claims.Roles,
			Groups: claims.Groups,
		}
		next.ServeHTTP(w, r.WithContext(NewContext(r.Context(), p)))
	})
}

func (v *Verifier) wwwAuthenticate(extra string) string {
	head := `Bearer realm="` + v.cfg.Issuer + `"`
	if v.cfg.ResourceMetadataURL != "" {
		head = `Bearer resource_metadata="` + v.cfg.ResourceMetadataURL + `"`
	}
	if extra != "" {
		head += ", " + extra
	}
	return head
}
