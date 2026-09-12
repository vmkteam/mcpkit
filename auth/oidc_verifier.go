package auth

// JWT verification against an OIDC issuer: discovery plus JWKS, stateless, no
// per-request round-trip to the IdP. Nothing here is vendor-specific.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	goidc "github.com/coreos/go-oidc/v3/oidc"
)

// Errors specific to JWT verification. The shared ones — invalid, expired —
// live in auth.go beside the api-key path.
var (
	ErrWrongAudience = errors.New("oidc: wrong audience")
	ErrNoRoles       = errors.New("oidc: no required roles in token")
)

// DefaultGroupsClaim is the claim name most IdPs put the groups under.
const DefaultGroupsClaim = "groups"

// DefaultDiscoveryTimeout bounds discovery and the JWKS refreshes when
// OIDCConfig carries no client of its own. http.DefaultClient has no timeout,
// and an IdP that accepts the connection and then says nothing would otherwise
// hold the boot open with no way to tell.
const DefaultDiscoveryTimeout = 10 * time.Second

// OIDCConfig drives Verifier.
//
// Audience is the canonical resource URI of this server (RFC 8707) and, when
// set, the only thing `aud` is checked against — that is what MCP clients send
// as `resource`. It must equal the server's public base URI byte for byte.
//
// With an empty Audience the check falls back to ClientID matched against `aud`
// (any element) or `azp`: IdP access tokens routinely carry the client id in
// azp only. The fallback keeps a stand working before audience mapping is
// configured on the IdP side.
type OIDCConfig struct {
	Issuer        string
	ClientID      string
	Audience      string
	RequiredRoles []string
	// GroupsClaim names the claim that carries the IdP groups. Empty means
	// DefaultGroupsClaim. A setting that is accepted by the config and ignored
	// by the code is worse than no setting at all, because someone relies on
	// it — so this one is read on every token.
	GroupsClaim string
	// ResourceMetadataURL is advertised in WWW-Authenticate on a 401 (RFC 9728
	// §5.1). It is what makes an MCP client discover the authorization server
	// instead of giving up.
	ResourceMetadataURL string
	// HTTPClient fetches discovery and JWKS. Nil takes a client with
	// DefaultDiscoveryTimeout rather than http.DefaultClient, which has no
	// timeout at all and would let a hanging IdP hang the boot forever. Pass
	// your own in production anyway: this is the one request that decides
	// whether anybody can log in, and it belongs in your client metrics.
	HTTPClient *http.Client
	Now        func() time.Time
}

// Claims is what the verifier reads out of a token.
type Claims struct {
	Subject  string
	Email    string
	Username string
	Roles    []string
	Groups   []string
}

// Verifier validates bearer tokens against one issuer.
type Verifier struct {
	cfg      OIDCConfig
	verifier *goidc.IDTokenVerifier
}

// NewVerifier runs OIDC discovery against cfg.Issuer and returns a verifier
// bound to it. It talks to the IdP once, here — every Verify after that is
// local.
func NewVerifier(ctx context.Context, cfg OIDCConfig) (*Verifier, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("oidc: empty issuer")
	}
	if cfg.ClientID == "" {
		return nil, errors.New("oidc: empty client id")
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = DefaultGroupsClaim
	}
	// Discovery and the JWKS refreshes that follow go through the caller's
	// client: with a timeout, and counted wherever that client is counted.
	//
	// Discovery also pins `iss`: the verifier below rejects any token whose
	// issuer differs from the discovered one. RFC 9207 iss checks on the
	// authorization *response* belong to the client, not here.
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: DefaultDiscoveryTimeout}
	}
	ctx = goidc.ClientContext(ctx, hc)
	provider, err := goidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discover issuer: %w", err)
	}
	// SkipClientIDCheck: aud is checked by hand below — against Audience
	// (RFC 8707) when configured, against ClientID/azp otherwise. go-oidc's
	// built-in check knows neither shape.
	v := provider.Verifier(&goidc.Config{SkipClientIDCheck: true, Now: cfg.Now})
	// Publish the verify counter with every series at zero from the moment a
	// verifier exists, not from the first request that fails.
	registerMetrics()
	return &Verifier{cfg: cfg, verifier: v}, nil
}

// Verify checks the signature, the issuer, the audience and the required roles
// of a raw bearer token.
func (v *Verifier) Verify(ctx context.Context, raw string) (Claims, error) {
	if raw == "" {
		return Claims{}, ErrInvalidToken
	}
	idt, err := v.verifier.Verify(ctx, raw)
	if err != nil {
		var expErr *goidc.TokenExpiredError
		if errors.As(err, &expErr) {
			return Claims{}, fmt.Errorf("%w: %w", ErrExpiredToken, err)
		}
		return Claims{}, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	// One pass over the payload, not two. The groups claim is named by config
	// and cannot be a struct field, so the whole set is decoded once and the
	// known claims are read out of it — decoding the token again into a typed
	// struct was a second full unmarshal on every request.
	var all map[string]json.RawMessage
	if cerr := idt.Claims(&all); cerr != nil {
		return Claims{}, fmt.Errorf("%w: parse claims: %w", ErrInvalidToken, cerr)
	}

	if aerr := v.checkAudience(idt.Audience, claimString(all, "azp")); aerr != nil {
		return Claims{}, aerr
	}

	roles := realmRoles(all)
	roles = append(roles, resourceRoles(all, v.cfg.ClientID)...)

	groups, err := v.groups(all)
	if err != nil {
		return Claims{}, err
	}

	// RequiredRoles is checked against roles ∪ groups: access is modelled with
	// IdP groups by one service and with realm roles by another, and one
	// RequiredRoles list works for both styles.
	if len(v.cfg.RequiredRoles) > 0 && !hasAny(roles, v.cfg.RequiredRoles) && !hasAny(groups, v.cfg.RequiredRoles) {
		return Claims{}, fmt.Errorf("%w: token roles=%v groups=%v", ErrNoRoles, roles, groups)
	}

	return Claims{
		Subject:  claimString(all, "sub"),
		Email:    claimString(all, "email"),
		Username: claimString(all, "preferred_username"),
		Roles:    roles,
		Groups:   groups,
	}, nil
}

// claimString reads a string claim, treating a claim of another shape as an
// absent one: a token is not rejected over a field this server does not key
// anything on.
func claimString(all map[string]json.RawMessage, name string) string {
	raw, ok := all[name]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

// rolesClaim is the shape both Keycloak-style role containers share.
type rolesClaim struct {
	Roles []string `json:"roles"`
}

func realmRoles(all map[string]json.RawMessage) []string {
	raw, ok := all["realm_access"]
	if !ok {
		return nil
	}
	var rc rolesClaim
	if err := json.Unmarshal(raw, &rc); err != nil {
		return nil
	}
	return rc.Roles
}

func resourceRoles(all map[string]json.RawMessage, clientID string) []string {
	raw, ok := all["resource_access"]
	if !ok {
		return nil
	}
	var byClient map[string]rolesClaim
	if err := json.Unmarshal(raw, &byClient); err != nil {
		return nil
	}
	return byClient[clientID].Roles
}

// checkAudience keeps a token minted for another resource from opening this
// one: with Audience set we require it in `aud` and ignore azp entirely, so a
// token issued to the same client for a different resource is rejected.
func (v *Verifier) checkAudience(aud []string, azp string) error {
	if v.cfg.Audience != "" {
		if !slices.Contains(aud, v.cfg.Audience) {
			return fmt.Errorf("%w: want %q, aud=%v", ErrWrongAudience, v.cfg.Audience, aud)
		}
		return nil
	}
	if azp != v.cfg.ClientID && !slices.Contains(aud, v.cfg.ClientID) {
		return fmt.Errorf("%w: aud=%v azp=%q", ErrWrongAudience, aud, azp)
	}
	return nil
}

// groups reads the configured claim. The claim's name is the IdP's choice, so
// it is looked up by name rather than through a fixed struct field; a list of
// strings is the usual shape, a single string is accepted for the IdP that
// hands out one group that way, anything else is a token this verifier cannot
// read. A leading "/" — the path form some IdPs use — is dropped.
func (v *Verifier) groups(all map[string]json.RawMessage) ([]string, error) {
	raw, ok := all[v.cfg.GroupsClaim]
	if !ok {
		return []string{}, nil
	}

	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		var single string
		if err := json.Unmarshal(raw, &single); err != nil {
			return nil, fmt.Errorf("%w: claim %q is neither a list nor a string", ErrInvalidToken, v.cfg.GroupsClaim)
		}
		list = []string{single}
	}

	groups := make([]string, 0, len(list))
	for _, g := range list {
		groups = append(groups, strings.TrimPrefix(g, "/"))
	}
	return groups, nil
}

// hasAny reports whether any element of want is in got.
func hasAny(got, want []string) bool {
	for _, w := range want {
		if slices.Contains(got, w) {
			return true
		}
	}
	return false
}
