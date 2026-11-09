// Package oauth2test provides a fake httptest-based OAuth2 provider for testing
// strategies (passport-google, passport-facebook, your own).
//
//	p := oauth2test.NewProvider(t, map[string]any{"sub": "42", "email": "a@x"})
//	cfg.TokenURL, cfg.UserInfoURL = p.TokenURL(), p.UserInfoURL()
//	identity, err := strategy.Callback(ctx, map[string]string{"code": p.Code})
package oauth2test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// Provider is a fake provider. It accepts only Code, ClientID and
// ClientSecret, issues AccessToken and serves Profile for it.
type Provider struct {
	Code         string
	ClientID     string
	ClientSecret string
	AccessToken  string
	Profile      map[string]any

	// TokenStatus/UserInfoStatus set the response status (200 by default), for testing errors.
	TokenStatus    int
	UserInfoStatus int
	// TokenBody/UserInfoBody set a raw response body instead of normal JSON.
	TokenBody    string
	UserInfoBody string

	// Challenge and Nonce are what the login URL sent (Authorize records
	// them): with a Challenge the token endpoint requires a matching
	// code_verifier (PKCE S256); with OIDC on, the id_token carries Nonce.
	Challenge string
	Nonce     string
	// CheckSecret replaces the comparison with ClientSecret (for secrets
	// made per request, like Apple's JWT).
	CheckSecret func(secret string) bool
	// IDTokenClaims are added to (or override) the id_token's claims.
	IDTokenClaims map[string]any

	mu       sync.Mutex
	requests []*http.Request
	server   *httptest.Server
	oidc     bool
	rsaKey   *rsa.PrivateKey
	ecKey    *ecdsa.PrivateKey
}

// NewProvider starts the provider; it stops when the test ends.
func NewProvider(t testing.TB, profile map[string]any) *Provider {
	p := &Provider{
		Code: "test-code", ClientID: "client-id", ClientSecret: "client-secret",
		AccessToken: "test-access-token", Profile: profile,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", p.token)
	mux.HandleFunc("/userinfo", p.userinfo)
	mux.HandleFunc("/jwks", p.jwks)
	mux.HandleFunc("/.well-known/openid-configuration", p.discovery)
	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

// EnableOIDC makes the token endpoint return an id_token signed with a fresh
// RSA key (RS256), or an ECDSA P-256 key (ES256) when es256, published at
// JWKSURL; Issuer is the server URL.
func (p *Provider) EnableOIDC(es256 bool) {
	p.oidc = true
	if es256 {
		p.ecKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		p.rsaKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	}
}

// Issuer and JWKSURL are the OIDC settings of the provider.
func (p *Provider) Issuer() string  { return p.server.URL }
func (p *Provider) JWKSURL() string { return p.server.URL + "/jwks" }

// Authorize records the code_challenge and nonce of a login URL, as a real
// provider remembers them for the code it issues.
func (p *Provider) Authorize(authURL string) {
	u, _ := url.Parse(authURL)
	p.Challenge = u.Query().Get("code_challenge")
	p.Nonce = u.Query().Get("nonce")
}

// AuthURL, TokenURL, UserInfoURL return the endpoints for oauth2.Config.
func (p *Provider) AuthURL() string     { return p.server.URL + "/authorize" }
func (p *Provider) TokenURL() string    { return p.server.URL + "/token" }
func (p *Provider) UserInfoURL() string { return p.server.URL + "/userinfo" }

// Requests returns the received requests (for assertions).
func (p *Provider) Requests() []*http.Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*http.Request(nil), p.requests...)
}

func (p *Provider) record(r *http.Request) {
	p.mu.Lock()
	p.requests = append(p.requests, r)
	p.mu.Unlock()
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	p.record(r)
	if p.TokenStatus != 0 {
		w.WriteHeader(p.TokenStatus)
	}
	if p.TokenBody != "" {
		w.Write([]byte(p.TokenBody))
		return
	}
	if err := r.ParseForm(); err != nil || r.Method != http.MethodPost ||
		r.PostForm.Get("grant_type") != "authorization_code" ||
		r.PostForm.Get("code") != p.Code ||
		r.PostForm.Get("client_id") != p.ClientID ||
		!p.secretOK(r.PostForm.Get("client_secret")) ||
		p.Challenge != "" && s256(r.PostForm.Get("code_verifier")) != p.Challenge {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		return
	}
	resp := map[string]any{"access_token": p.AccessToken, "token_type": "Bearer", "expires_in": 3600}
	if p.oidc {
		resp["id_token"] = p.IDToken()
	}
	json.NewEncoder(w).Encode(resp)
}

func (p *Provider) userinfo(w http.ResponseWriter, r *http.Request) {
	p.record(r)
	if p.UserInfoStatus != 0 {
		w.WriteHeader(p.UserInfoStatus)
	}
	if p.UserInfoBody != "" {
		w.Write([]byte(p.UserInfoBody))
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+p.AccessToken {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	json.NewEncoder(w).Encode(p.Profile)
}

func s256(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// IDToken signs the id_token the token endpoint returns: iss, aud, sub and
// the Profile, nonce, iat, exp (an hour), then IDTokenClaims.
func (p *Provider) IDToken() string {
	now := time.Now().Unix()
	claims := map[string]any{"iss": p.Issuer(), "aud": p.ClientID, "iat": now, "exp": now + 3600, "nonce": p.Nonce}
	for k, v := range p.Profile {
		claims[k] = v
	}
	for k, v := range p.IDTokenClaims {
		if v == nil {
			delete(claims, k)
		} else {
			claims[k] = v
		}
	}
	alg := "RS256"
	if p.ecKey != nil {
		alg = "ES256"
	}
	h, _ := json.Marshal(map[string]string{"alg": alg, "kid": "k1", "typ": "JWT"})
	c, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	digest := sha256.Sum256([]byte(in))
	var sig []byte
	if p.ecKey != nil {
		r, s, _ := ecdsa.Sign(rand.Reader, p.ecKey, digest[:])
		sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	} else {
		sig, _ = rsa.SignPKCS1v15(rand.Reader, p.rsaKey, crypto.SHA256, digest[:])
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (p *Provider) jwks(w http.ResponseWriter, r *http.Request) {
	p.record(r)
	b := base64.RawURLEncoding.EncodeToString
	var key map[string]string
	switch {
	case p.ecKey != nil:
		key = map[string]string{"kty": "EC", "kid": "k1", "use": "sig", "crv": "P-256",
			"x": b(p.ecKey.X.FillBytes(make([]byte, 32))), "y": b(p.ecKey.Y.FillBytes(make([]byte, 32)))}
	case p.rsaKey != nil:
		key = map[string]string{"kty": "RSA", "kid": "k1", "use": "sig",
			"n": b(p.rsaKey.N.Bytes()), "e": b(big.NewInt(int64(p.rsaKey.E)).Bytes())}
	}
	keys := []map[string]string{}
	if key != nil {
		keys = append(keys, key)
	}
	json.NewEncoder(w).Encode(map[string]any{"keys": keys})
}

func (p *Provider) discovery(w http.ResponseWriter, r *http.Request) {
	p.record(r)
	json.NewEncoder(w).Encode(map[string]string{
		"issuer": p.Issuer(), "authorization_endpoint": p.AuthURL(), "token_endpoint": p.TokenURL(),
		"userinfo_endpoint": p.UserInfoURL(), "jwks_uri": p.JWKSURL(),
	})
}

func (p *Provider) secretOK(secret string) bool {
	if p.CheckSecret != nil {
		return p.CheckSecret(secret)
	}
	return secret == p.ClientSecret
}
