package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vmkteam/mcpkit/auth/authtest"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

// counterValue reads app_mcp_oidc_verify_total{result=label} out of the vector the
// verifier publishes.
func counterValue(t *testing.T, label string) float64 {
	t.Helper()
	return testutil.ToFloat64(metric().WithLabelValues(label))
}

func newMiddlewareServer(t *testing.T, fi *authtest.Issuer, requiredRoles []string) (http.Handler, *recordingHandler) {
	t.Helper()
	v, err := NewVerifier(context.Background(), OIDCConfig{
		Issuer:        fi.URL,
		ClientID:      fi.ClientID,
		RequiredRoles: requiredRoles,
	})
	require.NoError(t, err)
	inner := &recordingHandler{}
	return v.Middleware(inner, embedlog.Logger{}), inner
}

type recordingHandler struct {
	called    bool
	principal Principal
}

func (c *recordingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.called = true
	if p, ok := PrincipalFromContext(r.Context()); ok {
		c.principal = p
	}
	w.WriteHeader(http.StatusOK)
}

func TestMiddleware_OK_PropagatesPrincipal(t *testing.T) {
	fi := authtest.NewIssuer(t, testClientID)
	mw, inner := newMiddlewareServer(t, fi, []string{"analyst"})

	before := counterValue(t, resultOK)
	tok := fi.SignToken(t, map[string]any{
		"sub":                "alice-uuid",
		"email":              "alice@example.com",
		"preferred_username": "alice",
		"azp":                testClientID,
		"exp":                time.Now().Add(time.Hour).Unix(),
		"realm_access":       map[string]any{"roles": []string{"analyst"}},
		"groups":             []string{"/acme-admin"},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	mw.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.True(t, inner.called, "inner handler not called")
	assert.Equal(t, "alice-uuid", inner.principal.UserID)
	assert.Equal(t, "alice@example.com", inner.principal.Email)
	assert.Contains(t, inner.principal.Roles, "analyst")
	assert.Contains(t, inner.principal.Groups, "acme-admin", "leading / must be stripped")
	assert.Greater(t, counterValue(t, resultOK), before, "ok counter not incremented")
}

func TestMiddleware_MissingToken(t *testing.T) {
	fi := authtest.NewIssuer(t, testClientID)
	mw, inner := newMiddlewareServer(t, fi, nil)

	before := counterValue(t, resultMissing)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	mw.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.False(t, inner.called, "inner handler must not run on missing token")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "Bearer realm=")
	assert.Greater(t, counterValue(t, resultMissing), before, "missing counter not incremented")
}

func TestMiddleware_Expired(t *testing.T) {
	fi := authtest.NewIssuer(t, testClientID)
	mw, _ := newMiddlewareServer(t, fi, nil)

	before := counterValue(t, resultExpired)
	tok := fi.SignToken(t, map[string]any{
		"sub": "alice",
		"azp": testClientID,
		"exp": time.Now().Add(-time.Minute).Unix(),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	mw.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Greater(t, counterValue(t, resultExpired), before, "expired counter not incremented")
}

func TestMiddleware_Forbidden(t *testing.T) {
	fi := authtest.NewIssuer(t, testClientID)
	mw, inner := newMiddlewareServer(t, fi, []string{"analyst"})

	before := counterValue(t, resultForbidden)
	tok := fi.SignToken(t, map[string]any{
		"sub":          "stranger",
		"azp":          testClientID,
		"exp":          time.Now().Add(time.Hour).Unix(),
		"realm_access": map[string]any{"roles": []string{"some-other-role"}},
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	mw.ServeHTTP(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
	assert.False(t, inner.called, "inner must not run on forbidden")
	assert.Greater(t, counterValue(t, resultForbidden), before, "forbidden counter not incremented")
}

func TestMiddleware_Invalid(t *testing.T) {
	fi := authtest.NewIssuer(t, testClientID)
	mw, _ := newMiddlewareServer(t, fi, nil)

	before := counterValue(t, resultInvalid)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer not.a.jwt")
	mw.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Greater(t, counterValue(t, resultInvalid), before, "invalid counter not incremented")
}

// RFC 9728 §5.1: resource_metadata in WWW-Authenticate is what sends a client
// looking for the authorization server rather than reporting a dead endpoint.
func TestMiddleware_ResourceMetadataHeader(t *testing.T) {
	fi := authtest.NewIssuer(t, testClientID)
	const prm = "https://mcp.example.com/.well-known/oauth-protected-resource"
	v, err := NewVerifier(context.Background(), OIDCConfig{
		Issuer: fi.URL, ClientID: fi.ClientID, ResourceMetadataURL: prm,
	})
	require.NoError(t, err)
	mw := v.Middleware(&recordingHandler{}, embedlog.Logger{})

	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	assert.Equal(t, `Bearer resource_metadata="`+prm+`"`, rec.Header().Get("WWW-Authenticate"))

	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer not.a.jwt")
	mw.ServeHTTP(rec, req)
	assert.Equal(t, `Bearer resource_metadata="`+prm+`", error="invalid_token"`, rec.Header().Get("WWW-Authenticate"))
}

// The body of a failed authentication used to be err.Error(): the roles and
// groups of the token on a 403, and the audience this server expects on a 401.
// The first is the caller's own data and the second is configuration; the
// operator gets both from the log, the caller gets neither.
func TestMiddleware_ErrorBodyLeaksNothing(t *testing.T) {
	fi := authtest.NewIssuer(t, testClientID)

	t.Run("forbidden does not list the roles", func(t *testing.T) {
		mw, _ := newMiddlewareServer(t, fi, []string{"analyst"})
		tok := fi.SignToken(t, map[string]any{
			"sub":          "stranger",
			"azp":          testClientID,
			"exp":          time.Now().Add(time.Hour).Unix(),
			"realm_access": map[string]any{"roles": []string{"secret-internal-role"}},
			"groups":       []string{"secret-internal-group"},
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		mw.ServeHTTP(rec, req)

		require.Equal(t, http.StatusForbidden, rec.Code)
		body := rec.Body.String()
		assert.NotContains(t, body, "secret-internal-role")
		assert.NotContains(t, body, "secret-internal-group")
		assert.Contains(t, body, "insufficient permissions")
	})

	t.Run("wrong audience does not name the audience", func(t *testing.T) {
		const secretAudience = "https://internal.example.com/mcp"
		v, err := NewVerifier(context.Background(), OIDCConfig{
			Issuer: fi.URL, ClientID: fi.ClientID, Audience: secretAudience,
		})
		require.NoError(t, err)
		tok := fi.SignToken(t, map[string]any{
			"sub": "alice", "aud": "someone-else",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		v.Middleware(&recordingHandler{}, embedlog.Logger{}).ServeHTTP(rec, req)

		require.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.NotContains(t, rec.Body.String(), secretAudience)
		assert.Contains(t, rec.Body.String(), "invalid token")
	})
}

// The metrics of this package go into the default registry, the same one the
// service publishes: registering twice would panic.
func TestMetric_SyncOnceIdempotent(t *testing.T) {
	a := metric()
	b := metric()
	assert.Same(t, a, b, "metric() must return the same CounterVec instance")
}

// Every outcome is published from the start: rate() over a counter that
// appears with the first failure cannot tell "no errors" from "no data".
func TestMetric_SeriesStartAtZero(t *testing.T) {
	registerMetrics()
	assert.Equal(t, 5, testutil.CollectAndCount(verifyTotal),
		"all five result series must exist before anything is verified")
}
