package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

func hashOf(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func TestAuthenticate(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	expired := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	store := NewStore([]Key{
		{UserID: "alice", KeyHash: hashOf("alice-token"), Groups: []string{"mcp-users"}},
		{UserID: "bob", KeyHash: hashOf("bob-token"), ExpiresAt: future},
		{UserID: "stale", KeyHash: hashOf("stale-token"), ExpiresAt: expired},
		{UserID: "prefixed", KeyHash: HashPrefix + strings.ToUpper(hashOf("prefixed-token"))},
	})

	t.Run("valid token", func(t *testing.T) {
		t.Parallel()
		p, err := store.Authenticate("alice-token", now)
		require.NoError(t, err)
		assert.Equal(t, "alice", p.UserID)
	})

	// Authorization is keyed by group, so a key that carries none authenticates
	// and then fails every call — the groups have to travel with the principal.
	t.Run("groups reach the principal", func(t *testing.T) {
		t.Parallel()
		p, err := store.Authenticate("alice-token", now)
		require.NoError(t, err)
		assert.Equal(t, []string{"mcp-users"}, p.Groups)
	})

	// Configs in the wild spell the digest both ways, and in both cases.
	t.Run("sha256: prefix and upper case are accepted", func(t *testing.T) {
		t.Parallel()
		p, err := store.Authenticate("prefixed-token", now)
		require.NoError(t, err)
		assert.Equal(t, "prefixed", p.UserID)
	})

	t.Run("missing token", func(t *testing.T) {
		t.Parallel()
		_, err := store.Authenticate("", now)
		assert.ErrorIs(t, err, ErrMissingToken)
	})

	t.Run("invalid token", func(t *testing.T) {
		t.Parallel()
		_, err := store.Authenticate("nope", now)
		assert.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("expired token", func(t *testing.T) {
		t.Parallel()
		_, err := store.Authenticate("stale-token", now)
		assert.ErrorIs(t, err, ErrExpiredToken)
	})

	t.Run("non-expired token", func(t *testing.T) {
		t.Parallel()
		_, err := store.Authenticate("bob-token", now)
		assert.NoError(t, err)
	})
}

// A key with no groups is a 403 on every call and a server that reads as
// broken. Keys() is how a service says so at startup instead.
func TestStoreKeys(t *testing.T) {
	t.Parallel()
	store := NewStore([]Key{
		{UserID: "alice", KeyHash: HashPrefix + hashOf("alice-token"), Groups: []string{"mcp-users"}},
		{UserID: "groupless", KeyHash: hashOf("groupless-token")},
	})

	keys := store.Keys()
	require.Len(t, keys, 2)
	assert.Equal(t, hashOf("alice-token"), keys[0].KeyHash, "the normalized hash, not the config spelling")

	var groupless []string
	for _, k := range keys {
		if len(k.Groups) == 0 {
			groupless = append(groupless, k.UserID)
		}
	}
	assert.Equal(t, []string{"groupless"}, groupless)

	keys[0].UserID = "mallory"
	assert.Equal(t, "alice", store.Keys()[0].UserID, "Keys must hand out a copy")
}

func TestMiddleware(t *testing.T) {
	t.Parallel()
	store := NewStore([]Key{
		{UserID: "alice", KeyHash: hashOf("good-token")},
	})

	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := PrincipalFromContext(r.Context())
		if !ok {
			http.Error(w, "no principal", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(p.UserID))
	})

	mw := store.Middleware(probe, embedlog.Logger{})

	t.Run("Authorization Bearer accepted", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(""))
		req.Header.Set("Authorization", "Bearer good-token")
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
		body, _ := io.ReadAll(rec.Body)
		assert.Equal(t, "alice", string(body))
	})

	t.Run("X-API-Key accepted", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(""))
		req.Header.Set("X-Api-Key", "good-token")
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("missing token rejected", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(""))
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, `Bearer realm="`+DefaultRealm+`"`, rec.Header().Get("WWW-Authenticate"))
	})

	t.Run("wrong token rejected", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(""))
		req.Header.Set("Authorization", "Bearer wrong")
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	// The realm is what a human sees in the browser prompt, so a service names
	// itself there instead of inheriting the library's default.
	t.Run("realm comes from the options", func(t *testing.T) {
		t.Parallel()
		named := NewStoreWithOptions([]Key{{UserID: "alice", KeyHash: hashOf("good-token")}},
			StoreOptions{Realm: "example-mcp"})
		rec := httptest.NewRecorder()
		named.Middleware(probe, embedlog.Logger{}).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", nil))
		assert.Equal(t, `Bearer realm="example-mcp"`, rec.Header().Get("WWW-Authenticate"))
	})

	t.Run("empty store bypasses", func(t *testing.T) {
		t.Parallel()
		bypass := NewStore(nil).Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}), embedlog.Logger{})
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(""))
		rec := httptest.NewRecorder()
		bypass.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "bypass should succeed")
	})
}

func TestBearerFromRequest(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{"bearer", map[string]string{"Authorization": "Bearer tok"}, "tok"},
		{"bearer is case-insensitive", map[string]string{"Authorization": "bearer tok"}, "tok"},
		{"api key header", map[string]string{"X-Api-Key": "tok"}, "tok"},
		{"another scheme is not a token", map[string]string{"Authorization": "Basic dXNlcjpwYXNz"}, ""},
		{"nothing at all", nil, ""},
		{"bearer wins over the api key", map[string]string{"Authorization": "Bearer tok", "X-Api-Key": "other"}, "tok"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			assert.Equal(t, tc.want, BearerFromRequest(req))
		})
	}
}

// The principal travels by value: a handler that got a pointer could rewrite
// who the caller is after the middleware decided.
func TestPrincipalFromContext(t *testing.T) {
	t.Parallel()
	_, ok := PrincipalFromContext(t.Context())
	assert.False(t, ok, "an unauthenticated context carries no principal")

	ctx := NewContext(t.Context(), Principal{UserID: "alice", Groups: []string{"mcp-users"}})
	p, ok := PrincipalFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, "alice", p.UserID)
}
