// Package auth answers one question about an MCP request: who is asking.
//
// Two backends, one answer. An api-key store matches a token against sha256
// hashes from the service config; an OIDC verifier checks a JWT against the
// issuer's JWKS. Both put the same Principal in the request context, and what
// that principal is allowed to do is the service's business — the library does
// not know what a role means here.
//
// Both backends are plain net/http middleware, and the service picks the order
// in which they apply: that choice depends on config fields the library never
// sees.
package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/vmkteam/embedlog"
)

// Key is one entry in the keystore — config-shaped.
type Key struct {
	UserID string
	// KeyHash is the sha256 of the plaintext token as hex, with or without a
	// "sha256:" prefix — both spellings appear in configs in the wild.
	KeyHash string
	// Groups are the IdP groups this key stands for. Services key authorization
	// by group, so a key without groups authenticates and then fails every call
	// with 403 — which reads as a broken server, not as a misconfigured key.
	// Store.Keys lets a service check for that at startup.
	Groups    []string
	ExpiresAt time.Time
}

// Principal is an authenticated caller. Filled by the api-key Store or by the
// OIDC middleware — fields specific to one backend are empty under the other.
//
// It is stored in the context by value: a middleware that hands out a pointer
// invites the handler to edit who the caller is after the fact.
type Principal struct {
	UserID string
	Email  string
	Roles  []string
	Groups []string
}

type principalCtxKey struct{}

// Errors returned by Authenticate and by Verify. "Invalid" and "expired" are
// shared by the api-key and the JWT path on purpose: the caller gets the same
// 401 either way, and two vocabularies for one outcome only make the
// middleware harder to read.
var (
	ErrMissingToken = errors.New("auth: missing token")
	ErrInvalidToken = errors.New("auth: invalid token")
	ErrExpiredToken = errors.New("auth: expired token")
)

// HashPrefix is the optional prefix a config may carry in front of the hex
// digest. It documents the algorithm for a human and is dropped here.
const HashPrefix = "sha256:"

// DefaultRealm is the WWW-Authenticate realm when StoreOptions says nothing.
const DefaultRealm = "mcp"

// StoreOptions tunes the keystore. The zero value is the production default.
type StoreOptions struct {
	// Realm goes into WWW-Authenticate on a 401. Empty takes DefaultRealm.
	Realm string
}

// Store holds the keystore. An empty store disables api-key auth: that is the
// dev mode, and whether a production server may run in it is the service's
// call, not this package's.
type Store struct {
	keys  []Key
	realm string
}

// NewStore builds a keystore from config keys with default options.
func NewStore(keys []Key) *Store {
	return NewStoreWithOptions(keys, StoreOptions{})
}

// NewStoreWithOptions is NewStore with the knobs. Hashes are normalized here —
// lower-case hex, prefix dropped — so both config spellings match one token.
func NewStoreWithOptions(keys []Key, opts StoreOptions) *Store {
	out := make([]Key, len(keys))
	for i, k := range keys {
		k.KeyHash = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(k.KeyHash)), HashPrefix)
		out[i] = k
	}
	if opts.Realm == "" {
		opts.Realm = DefaultRealm
	}
	return &Store{keys: out, realm: opts.Realm}
}

// PrincipalFromContext returns the authenticated principal, if any.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalCtxKey{}).(Principal)
	return p, ok
}

// NewContext attaches p to ctx; used by external auth backends.
func NewContext(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalCtxKey{}, p)
}

// BearerFromRequest extracts a token from Authorization (Bearer) or X-Api-Key.
func BearerFromRequest(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		const prefix = "Bearer "
		if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
			return strings.TrimSpace(h[len(prefix):])
		}
	}
	return strings.TrimSpace(r.Header.Get("X-Api-Key"))
}

// Empty reports whether the keystore has zero entries.
func (s *Store) Empty() bool { return len(s.keys) == 0 }

// Keys returns the configured keys. A service checks them at startup — a key
// without groups is a 403 on every call, and the server looks broken rather
// than misconfigured.
func (s *Store) Keys() []Key {
	return append([]Key(nil), s.keys...)
}

// Authenticate validates a plaintext token against the keystore.
func (s *Store) Authenticate(token string, now time.Time) (Principal, error) {
	if token == "" {
		return Principal{}, ErrMissingToken
	}
	sum := sha256.Sum256([]byte(token))
	hexed := hex.EncodeToString(sum[:])
	for _, k := range s.keys {
		if subtle.ConstantTimeCompare([]byte(hexed), []byte(k.KeyHash)) != 1 {
			continue
		}
		if !k.ExpiresAt.IsZero() && now.After(k.ExpiresAt) {
			return Principal{}, ErrExpiredToken
		}
		return Principal{
			UserID: k.UserID,
			Groups: append([]string(nil), k.Groups...),
		}, nil
	}
	return Principal{}, ErrInvalidToken
}

// publicAuthError is what a failed caller is told: the outcome, without the
// package name and without anything the keystore knows.
func publicAuthError(err error) string {
	switch {
	case errors.Is(err, ErrMissingToken):
		return "missing token"
	case errors.Is(err, ErrExpiredToken):
		return "token expired"
	default:
		return "invalid token"
	}
}

// Middleware enforces api-key auth on the wrapped handler. An empty keystore
// is a no-op. The zero embedlog.Logger is a working no-op too.
//
// Only failed auth is logged — success is implicit in access logs and in the
// app_http_* metrics, and per-request structured logging burns allocations on
// the hot path.
func (s *Store) Middleware(next http.Handler, logger embedlog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.Empty() {
			next.ServeHTTP(w, r)
			return
		}
		token := BearerFromRequest(r)
		p, err := s.Authenticate(token, time.Now())
		if err != nil {
			logger.Error(r.Context(), "mcp auth failed", "remote", r.RemoteAddr, "err", err.Error())
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+s.realm+`"`)
			// The "auth: " prefix names this package to a reader of the log and
			// says nothing to a caller, so what goes over the wire is the plain
			// outcome. Expired is told apart from invalid on purpose: a client
			// holding a key that has run out can do something about it.
			http.Error(w, publicAuthError(err), http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(NewContext(r.Context(), p)))
	})
}
