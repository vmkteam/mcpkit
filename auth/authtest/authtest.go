// Package authtest is a fake OIDC issuer to sign tokens with: the discovery
// document and the JWKS go-oidc needs, backed by a key generated per test.
//
// It is a separate package so that go-jose, which only the fixture needs, stays
// out of the dependency graph of a service that imports auth.
//
// Production code has no use for it; tests run against the real verifier,
// because a mock of go-oidc would test the mock.
package authtest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

const keyID = "test-kid-1"

// One key for the whole test binary. Generating RSA-2048 per issuer is the
// slowest thing in a package whose tests are otherwise instant, and the key is
// a fixture — no test learns anything from it being fresh.
var (
	testKeyOnce sync.Once
	testKey     *rsa.PrivateKey
	errTestKey  error
)

func sharedKey() (*rsa.PrivateKey, error) {
	testKeyOnce.Do(func() {
		testKey, errTestKey = rsa.GenerateKey(rand.Reader, 2048)
	})
	return testKey, errTestKey
}

// Issuer is a running fake IdP.
type Issuer struct {
	// URL is the issuer: what goes into auth.OIDCConfig.Issuer and into `iss`.
	URL string
	// ClientID is what the tokens are minted for, kept here so a test can build
	// the wrong-audience case against the same fixture.
	ClientID string
	signer   jose.Signer
}

// NewIssuer starts the server and stops it when the test ends.
func NewIssuer(t testing.TB, clientID string) *Issuer {
	t.Helper()
	priv, err := sharedKey()
	require.NoError(t, err)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", keyID),
	)
	require.NoError(t, err)

	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &priv.PublicKey, KeyID: keyID, Algorithm: "RS256", Use: "sig"},
	}}

	iss := &Issuer{ClientID: clientID, signer: signer}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                iss.URL,
			"authorization_endpoint":                iss.URL + "/auth",
			"token_endpoint":                        iss.URL + "/token",
			"jwks_uri":                              iss.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	iss.URL = srv.URL
	return iss
}

// SignToken serialises claims to a compact JWS — the shape of an IdP access
// token. `iss` is filled in unless the test set it to something else on
// purpose.
func (i *Issuer) SignToken(t testing.TB, claims map[string]any) string {
	t.Helper()
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = i.URL
	}
	body, err := json.Marshal(claims)
	require.NoError(t, err)
	jws, err := i.signer.Sign(body)
	require.NoError(t, err)
	out, err := jws.CompactSerialize()
	require.NoError(t, err)
	return out
}
