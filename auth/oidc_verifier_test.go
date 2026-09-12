package auth

import (
	"context"
	"testing"
	"time"

	"github.com/vmkteam/mcpkit/auth/authtest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testClientID = "mcp-server"

func TestVerify(t *testing.T) {
	fi := authtest.NewIssuer(t, testClientID)
	now := time.Now()
	exp := now.Add(time.Hour).Unix()

	v, err := NewVerifier(context.Background(), OIDCConfig{
		Issuer:        fi.URL,
		ClientID:      testClientID,
		RequiredRoles: []string{"analyst", "admin"},
	})
	require.NoError(t, err)

	t.Run("ok via azp + realm role", func(t *testing.T) {
		tok := fi.SignToken(t, map[string]any{
			"sub":                "alice-uuid",
			"email":              "alice@example.com",
			"preferred_username": "alice",
			"azp":                testClientID,
			"exp":                exp,
			"iat":                now.Unix(),
			"realm_access":       map[string]any{"roles": []string{"analyst", "other"}},
		})
		c, err := v.Verify(context.Background(), tok)
		require.NoError(t, err)
		assert.Equal(t, "alice-uuid", c.Subject)
		assert.Equal(t, "alice@example.com", c.Email)
		assert.Equal(t, "alice", c.Username)
		assert.Contains(t, c.Roles, "analyst")
	})

	t.Run("ok via aud array", func(t *testing.T) {
		tok := fi.SignToken(t, map[string]any{
			"sub":          "bob",
			"aud":          []string{"account", testClientID},
			"exp":          exp,
			"realm_access": map[string]any{"roles": []string{"admin"}},
		})
		_, err := v.Verify(context.Background(), tok)
		assert.NoError(t, err)
	})

	t.Run("ok via resource_access role", func(t *testing.T) {
		tok := fi.SignToken(t, map[string]any{
			"sub": "carol",
			"azp": testClientID,
			"exp": exp,
			"resource_access": map[string]any{
				testClientID: map[string]any{"roles": []string{"admin"}},
			},
		})
		c, err := v.Verify(context.Background(), tok)
		require.NoError(t, err)
		assert.Contains(t, c.Roles, "admin")
	})

	t.Run("expired", func(t *testing.T) {
		tok := fi.SignToken(t, map[string]any{
			"sub":          "alice",
			"azp":          testClientID,
			"exp":          now.Add(-time.Minute).Unix(),
			"realm_access": map[string]any{"roles": []string{"analyst"}},
		})
		_, err := v.Verify(context.Background(), tok)
		assert.ErrorIs(t, err, ErrExpiredToken)
	})

	t.Run("wrong audience", func(t *testing.T) {
		tok := fi.SignToken(t, map[string]any{
			"sub":          "alice",
			"azp":          "other-client",
			"aud":          []string{"account"},
			"exp":          exp,
			"realm_access": map[string]any{"roles": []string{"analyst"}},
		})
		_, err := v.Verify(context.Background(), tok)
		assert.ErrorIs(t, err, ErrWrongAudience)
	})

	t.Run("no required role", func(t *testing.T) {
		tok := fi.SignToken(t, map[string]any{
			"sub":          "stranger",
			"azp":          testClientID,
			"exp":          exp,
			"realm_access": map[string]any{"roles": []string{"some-other-role"}},
		})
		_, err := v.Verify(context.Background(), tok)
		assert.ErrorIs(t, err, ErrNoRoles)
	})

	t.Run("ok via group membership", func(t *testing.T) {
		tok := fi.SignToken(t, map[string]any{
			"sub":    "dave",
			"azp":    testClientID,
			"exp":    exp,
			"groups": []string{"/acme-admin", "/analyst", "/mcp-users"},
		})
		c, err := v.Verify(context.Background(), tok)
		require.NoError(t, err)
		assert.Contains(t, c.Groups, "analyst", "leading slash must be stripped")
	})

	t.Run("wrong issuer rejected by signature/iss", func(t *testing.T) {
		tok := fi.SignToken(t, map[string]any{
			"iss":          "https://evil.example.com",
			"sub":          "evil",
			"azp":          testClientID,
			"exp":          exp,
			"realm_access": map[string]any{"roles": []string{"analyst"}},
		})
		_, err := v.Verify(context.Background(), tok)
		assert.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("garbage rejected", func(t *testing.T) {
		_, err := v.Verify(context.Background(), "not.a.jwt")
		assert.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("empty rejected", func(t *testing.T) {
		_, err := v.Verify(context.Background(), "")
		assert.ErrorIs(t, err, ErrInvalidToken)
	})
}

// With Audience configured the resource URI is the only thing that opens the
// door (RFC 8707): a token minted for the same client but another resource
// must not pass, which is exactly what the azp fallback would let through.
func TestVerify_Audience(t *testing.T) {
	fi := authtest.NewIssuer(t, testClientID)
	const resource = "https://mcp.example.com/mcp"
	v, err := NewVerifier(context.Background(), OIDCConfig{
		Issuer:   fi.URL,
		ClientID: testClientID,
		Audience: resource,
	})
	require.NoError(t, err)

	exp := time.Now().Add(time.Hour).Unix()

	t.Run("token for this resource passes", func(t *testing.T) {
		tok := fi.SignToken(t, map[string]any{
			"sub": "alice",
			"aud": []string{resource},
			"azp": testClientID,
			"exp": exp,
		})
		_, err := v.Verify(context.Background(), tok)
		assert.NoError(t, err)
	})

	t.Run("token for another resource is rejected", func(t *testing.T) {
		tok := fi.SignToken(t, map[string]any{
			"sub": "alice",
			"aud": []string{"https://other.example.com/mcp"},
			"azp": testClientID,
			"exp": exp,
		})
		_, err := v.Verify(context.Background(), tok)
		assert.ErrorIs(t, err, ErrWrongAudience)
	})

	t.Run("azp alone no longer suffices", func(t *testing.T) {
		tok := fi.SignToken(t, map[string]any{
			"sub": "alice",
			"azp": testClientID,
			"exp": exp,
		})
		_, err := v.Verify(context.Background(), tok)
		assert.ErrorIs(t, err, ErrWrongAudience)
	})
}

func TestVerify_NoRequiredRoles(t *testing.T) {
	fi := authtest.NewIssuer(t, testClientID)
	v, err := NewVerifier(context.Background(), OIDCConfig{
		Issuer:   fi.URL,
		ClientID: testClientID,
		// RequiredRoles unset → any token with valid signature + audience passes.
	})
	require.NoError(t, err)
	tok := fi.SignToken(t, map[string]any{
		"sub": "x",
		"azp": testClientID,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	_, err = v.Verify(context.Background(), tok)
	assert.NoError(t, err)
}

// The claim that carries the groups is the IdP's choice, not ours: one says
// "groups", another says "memberOf". A GroupsClaim the verifier ignored would
// be a setting the config promises and the code breaks.
func TestVerify_GroupsClaim(t *testing.T) {
	fi := authtest.NewIssuer(t, testClientID)
	v, err := NewVerifier(context.Background(), OIDCConfig{
		Issuer:      fi.URL,
		ClientID:    testClientID,
		GroupsClaim: "memberOf",
	})
	require.NoError(t, err)
	exp := time.Now().Add(time.Hour).Unix()

	t.Run("groups come from the named claim, not from the default one", func(t *testing.T) {
		tok := fi.SignToken(t, map[string]any{
			"sub":      "erin",
			"azp":      testClientID,
			"exp":      exp,
			"memberOf": []string{"/mcp-users"},
			"groups":   []string{"/not-this-one"},
		})
		c, err := v.Verify(context.Background(), tok)
		require.NoError(t, err)
		assert.Equal(t, []string{"mcp-users"}, c.Groups)
	})

	t.Run("a single string is one group", func(t *testing.T) {
		tok := fi.SignToken(t, map[string]any{
			"sub": "erin", "azp": testClientID, "exp": exp, "memberOf": "mcp-users",
		})
		c, err := v.Verify(context.Background(), tok)
		require.NoError(t, err)
		assert.Equal(t, []string{"mcp-users"}, c.Groups)
	})

	t.Run("an absent claim is no groups, not an error", func(t *testing.T) {
		tok := fi.SignToken(t, map[string]any{"sub": "erin", "azp": testClientID, "exp": exp})
		c, err := v.Verify(context.Background(), tok)
		require.NoError(t, err)
		assert.Empty(t, c.Groups)
	})

	t.Run("a claim of another shape is a token this verifier cannot read", func(t *testing.T) {
		tok := fi.SignToken(t, map[string]any{
			"sub": "erin", "azp": testClientID, "exp": exp, "memberOf": 42,
		})
		_, err := v.Verify(context.Background(), tok)
		assert.ErrorIs(t, err, ErrInvalidToken)
	})
}

func TestNewVerifier_Config(t *testing.T) {
	t.Parallel()
	_, err := NewVerifier(t.Context(), OIDCConfig{ClientID: testClientID})
	require.ErrorContains(t, err, "empty issuer")

	_, err = NewVerifier(t.Context(), OIDCConfig{Issuer: "https://idp.example.com"})
	require.ErrorContains(t, err, "empty client id")

	// Discovery is what pins the issuer, so an issuer nobody answers for is a
	// startup failure rather than a verifier that rejects every token.
	_, err = NewVerifier(t.Context(), OIDCConfig{Issuer: "https://127.0.0.1:1/idp", ClientID: testClientID})
	require.ErrorContains(t, err, "discover issuer")
}

func TestHasAny(t *testing.T) {
	t.Parallel()
	assert.True(t, hasAny([]string{"a", "b"}, []string{"b", "c"}))
	assert.False(t, hasAny([]string{"a", "b"}, []string{"c"}))
	assert.False(t, hasAny(nil, []string{"a"}))
	assert.False(t, hasAny([]string{"a"}, nil), "requiring nothing is not the same as matching anything")
}
