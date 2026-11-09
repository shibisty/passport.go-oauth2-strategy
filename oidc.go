package oauth2

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// OIDC verifies the id_token of an OpenID Connect provider (Google, Apple,
// Microsoft, Keycloak...). With it, Callback requires an id_token signed by
// a key of JWKSURL (RS256 or ES256), checks iss, aud (and azp), exp, iat and
// the nonce AuthCodeURL sent, and takes the profile from the token's claims
// when Config.UserInfoURL is empty.
type OIDC struct {
	Issuer  string        // exact iss, e.g. https://accounts.google.com
	JWKSURL string        // the provider's signing keys
	Leeway  time.Duration // clock skew for exp and iat (default 1 minute)

	mu      sync.Mutex
	keys    map[string]crypto.PublicKey
	fetched time.Time
}

var (
	// ErrIDToken: the id_token is missing or does not verify.
	ErrIDToken = errors.New("oauth2: invalid id_token")
)

// Discovery is what an OpenID provider publishes at
// <issuer>/.well-known/openid-configuration.
type Discovery struct {
	Issuer      string `json:"issuer"`
	AuthURL     string `json:"authorization_endpoint"`
	TokenURL    string `json:"token_endpoint"`
	UserInfoURL string `json:"userinfo_endpoint"`
	JWKSURL     string `json:"jwks_uri"`
}

// Discover reads the provider configuration of issuer; its issuer must be
// the one asked for.
func Discover(ctx context.Context, client *http.Client, issuer string) (*Discovery, error) {
	if client == nil {
		client = &http.Client{Timeout: DefaultTimeout}
	}
	s := &Strategy{name: "discovery", cfg: Config{HTTPClient: client}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	var d Discovery
	if err := s.do(req, "discovery", &d); err != nil {
		return nil, err
	}
	if d.Issuer != issuer {
		return nil, fmt.Errorf("oauth2: discovery of %s returned issuer %q", issuer, d.Issuer)
	}
	return &d, nil
}

// Configure fills the endpoints of cfg from the discovery document and
// turns on OIDC and PKCE.
func (d *Discovery) Configure(cfg *Config) {
	cfg.AuthURL, cfg.TokenURL, cfg.UserInfoURL = d.AuthURL, d.TokenURL, d.UserInfoURL
	cfg.OIDC = &OIDC{Issuer: d.Issuer, JWKSURL: d.JWKSURL}
	cfg.PKCE = true
}

// derive makes the PKCE verifier and the OIDC nonce of a login from its
// state: HMAC-SHA256 with the strategy's key, so they need no storage and
// cannot be computed from the state (which travels in URLs) without the key.
func (s *Strategy) derive(purpose, state string) string {
	m := hmac.New(sha256.New, s.cfg.StateKey)
	m.Write([]byte(purpose + "\x00" + state))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// verifyIDToken checks an id_token and returns its claims.
func (s *Strategy) verifyIDToken(ctx context.Context, token, state string) (map[string]any, error) {
	o := s.cfg.OIDC
	if token == "" {
		return nil, fmt.Errorf("%w: the token response has none", ErrIDToken)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(token) > 16<<10 {
		return nil, fmt.Errorf("%w: malformed", ErrIDToken)
	}
	var h struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &h); err != nil {
		return nil, fmt.Errorf("%w: header: %v", ErrIDToken, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: signature encoding", ErrIDToken)
	}
	key, err := o.key(ctx, s, h.Kid)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch k := key.(type) {
	case *rsa.PublicKey:
		if h.Alg != "RS256" || rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig) != nil {
			return nil, fmt.Errorf("%w: signature (%s)", ErrIDToken, h.Alg)
		}
	case *ecdsa.PublicKey:
		if h.Alg != "ES256" || len(sig) != 64 ||
			!ecdsa.Verify(k, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return nil, fmt.Errorf("%w: signature (%s)", ErrIDToken, h.Alg)
		}
	}
	var c map[string]any
	if err := decodeSegment(parts[1], &c); err != nil {
		return nil, fmt.Errorf("%w: claims: %v", ErrIDToken, err)
	}
	leeway := o.Leeway
	if leeway == 0 {
		leeway = time.Minute
	}
	now := time.Now()
	switch {
	case String(c, "iss") != o.Issuer:
		return nil, fmt.Errorf("%w: issuer %q", ErrIDToken, String(c, "iss"))
	case !audience(c, s.cfg.ClientID):
		return nil, fmt.Errorf("%w: audience", ErrIDToken)
	case String(c, "sub") == "":
		return nil, fmt.Errorf("%w: no sub", ErrIDToken)
	case !now.Add(-leeway).Before(unix(c, "exp")):
		return nil, fmt.Errorf("%w: expired", ErrIDToken)
	case unix(c, "iat").IsZero() || unix(c, "iat").After(now.Add(leeway)):
		return nil, fmt.Errorf("%w: iat", ErrIDToken)
	case !hmac.Equal([]byte(String(c, "nonce")), []byte(s.derive("nonce", state))):
		return nil, fmt.Errorf("%w: nonce", ErrIDToken)
	}
	return c, nil
}

func decodeSegment(seg string, dest any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dest)
}

// audience: aud is the client or a list with it; with several audiences
// azp must be the client (OIDC Core 3.1.3.7).
func audience(c map[string]any, client string) bool {
	switch aud := c["aud"].(type) {
	case string:
		return aud == client
	case []any:
		found := false
		for _, a := range aud {
			if a == client {
				found = true
			}
		}
		return found && (len(aud) == 1 || String(c, "azp") == client)
	}
	return false
}

func unix(c map[string]any, k string) time.Time {
	if f, ok := c[k].(float64); ok && f > 0 {
		return time.Unix(int64(f), 0)
	}
	return time.Time{}
}

// key returns the signing key kid, fetching JWKSURL when it is unknown (at
// most once a minute, so a stream of bad kids cannot hammer the provider).
func (o *OIDC) key(ctx context.Context, s *Strategy, kid string) (crypto.PublicKey, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if k, ok := o.keys[kid]; ok {
		return k, nil
	}
	if time.Since(o.fetched) < time.Minute && o.keys != nil {
		return nil, fmt.Errorf("%w: unknown key %q", ErrIDToken, kid)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.JWKSURL, nil)
	if err != nil {
		return nil, err
	}
	var set struct {
		Keys []struct {
			Kty, Kid, Use, N, E, Crv, X, Y string
		} `json:"keys"`
	}
	if err := s.do(req, "jwks", &set); err != nil {
		return nil, err
	}
	o.keys, o.fetched = map[string]crypto.PublicKey{}, time.Now()
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		switch k.Kty {
		case "RSA":
			n, err1 := base64.RawURLEncoding.DecodeString(k.N)
			e, err2 := base64.RawURLEncoding.DecodeString(k.E)
			if err1 != nil || err2 != nil || len(e) > 4 || len(n) < 256 {
				continue // malformed, or shorter than 2048 bits
			}
			o.keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		case "EC":
			x, err1 := base64.RawURLEncoding.DecodeString(k.X)
			y, err2 := base64.RawURLEncoding.DecodeString(k.Y)
			if err1 != nil || err2 != nil || k.Crv != "P-256" {
				continue
			}
			pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
			if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
				continue
			}
			o.keys[k.Kid] = pub
		}
	}
	if k, ok := o.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("%w: unknown key %q", ErrIDToken, kid)
}
