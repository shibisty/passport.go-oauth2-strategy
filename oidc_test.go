package oauth2_test

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"passport"
	"passport-oauth2"
	"passport-oauth2/oauth2test"
)

func oidcMapper(p map[string]any) (*passport.Identity, error) {
	return &passport.Identity{ProviderUserID: oauth2.String(p, "sub"), Email: oauth2.String(p, "email"), EmailVerified: oauth2.Bool(p, "email_verified")}, nil
}

func oidcStrategy(t *testing.T, p *oauth2test.Provider, userinfo bool) *oauth2.Strategy {
	d, err := oauth2.Discover(ctx, nil, p.Issuer())
	if err != nil {
		t.Fatal(err)
	}
	cfg := oauth2.Config{ClientID: p.ClientID, ClientSecret: p.ClientSecret, RedirectURL: "https://app/cb", StateKey: []byte(strings.Repeat("k", 32))}
	d.Configure(&cfg)
	if !userinfo {
		cfg.UserInfoURL = ""
	}
	return oauth2.New("acme", cfg, oidcMapper)
}

func login(t *testing.T, s *oauth2.Strategy, p *oauth2test.Provider, state string) (*passport.Identity, error) {
	t.Helper()
	p.Authorize(s.AuthCodeURL(state))
	return s.Callback(ctx, map[string]string{"code": p.Code, "state": state})
}

func TestOIDC(t *testing.T) {
	for _, es256 := range []bool{false, true} {
		p := oauth2test.NewProvider(t, map[string]any{"sub": "u1", "email": "a@x", "email_verified": true})
		p.EnableOIDC(es256)
		s := oidcStrategy(t, p, false)
		u, _ := url.Parse(s.AuthCodeURL("st"))
		if u.Query().Get("code_challenge_method") != "S256" || u.Query().Get("nonce") == "" || u.Query().Get("code_challenge") == "" {
			t.Fatalf("login URL: %s", u)
		}
		id, err := login(t, s, p, "st")
		if err != nil || id.ProviderUserID != "u1" || !id.EmailVerified || id.Provider != "acme" {
			t.Fatalf("es256=%v: %+v %v", es256, id, err)
		}
		for _, r := range p.Requests() {
			if r.URL.Path == "/userinfo" {
				t.Fatal("userinfo fetched though the id_token has the profile")
			}
		}
	}
}

func TestOIDCWithUserinfo(t *testing.T) {
	p := oauth2test.NewProvider(t, map[string]any{"sub": "u1", "email": "a@x"})
	p.EnableOIDC(false)
	s := oidcStrategy(t, p, true)
	if id, err := login(t, s, p, "st"); err != nil || id.Email != "a@x" {
		t.Fatalf("%+v %v", id, err)
	}
	p.IDTokenClaims = map[string]any{"sub": "someone-else"}
	if _, err := login(t, s, p, "st"); !errors.Is(err, oauth2.ErrIDToken) {
		t.Fatalf("userinfo of another user: %v", err)
	}
}

func TestOIDCRejects(t *testing.T) {
	p := oauth2test.NewProvider(t, map[string]any{"sub": "u1"})
	p.EnableOIDC(false)
	s := oidcStrategy(t, p, false)
	now := time.Now().Unix()
	for name, claims := range map[string]map[string]any{
		"issuer":          {"iss": "https://evil"},
		"audience":        {"aud": "other-client"},
		"aud list no azp": {"aud": []string{"client-id", "other"}},
		"no sub":          {"sub": nil},
		"expired":         {"exp": now - 3600},
		"iat in future":   {"iat": now + 3600},
		"no iat":          {"iat": nil},
		"nonce":           {"nonce": "replayed"},
	} {
		p.IDTokenClaims = claims
		if _, err := login(t, s, p, "st"); !errors.Is(err, oauth2.ErrIDToken) {
			t.Errorf("%s: %v", name, err)
		}
	}
	p.IDTokenClaims = map[string]any{"aud": []string{"client-id", "other"}, "azp": "client-id"}
	if _, err := login(t, s, p, "st"); err != nil {
		t.Fatalf("aud list with azp: %v", err)
	}
	p.IDTokenClaims = nil

	// A token signed by another key with the same kid.
	other := oauth2test.NewProvider(t, map[string]any{"sub": "u1"})
	other.EnableOIDC(false)
	other.ClientID = p.ClientID
	other.Nonce = ""
	forged := other.IDToken()
	p.TokenBody = `{"access_token":"x","id_token":"` + forged + `"}`
	if _, err := login(t, s, p, "st"); !errors.Is(err, oauth2.ErrIDToken) {
		t.Fatalf("foreign signature: %v", err)
	}
	for name, body := range map[string]string{
		"no id_token": `{"access_token":"x"}`,
		"malformed":   `{"access_token":"x","id_token":"a.b"}`,
		"bad header":  `{"access_token":"x","id_token":"!!.b.c"}`,
		"bad sig":     `{"access_token":"x","id_token":"` + strings.Split(forged, ".")[0] + "." + strings.Split(forged, ".")[1] + `.!!"}`,
		"alg none":    `{"access_token":"x","id_token":"eyJhbGciOiJub25lIiwia2lkIjoiazEifQ.e30.c2ln"}`,
		"unknown kid": `{"access_token":"x","id_token":"eyJhbGciOiJSUzI1NiIsImtpZCI6Im5vcGUifQ.e30.c2ln"}`,
	} {
		p.TokenBody = body
		if _, err := login(t, s, p, "st"); !errors.Is(err, oauth2.ErrIDToken) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestPKCE(t *testing.T) {
	p := oauth2test.NewProvider(t, map[string]any{"id": "7"})
	s := oauth2.New("acme", oauth2.Config{
		ClientID: p.ClientID, ClientSecret: p.ClientSecret, RedirectURL: "https://app/cb",
		AuthURL: p.AuthURL(), TokenURL: p.TokenURL(), UserInfoURL: p.UserInfoURL(), PKCE: true,
	}, mapper)
	if id, err := login(t, s, p, "state-1"); err != nil || id.ProviderUserID != "7" {
		t.Fatalf("PKCE login: %+v %v", id, err)
	}
	// The code arrives with another state: the verifier does not match.
	p.Authorize(s.AuthCodeURL("state-1"))
	if _, err := s.Callback(ctx, map[string]string{"code": p.Code, "state": "state-2"}); err == nil {
		t.Fatal("PKCE with the wrong state")
	}
	// Another instance with the same StateKey derives the same verifier.
	key := []byte(strings.Repeat("s", 32))
	cfg := s.Config()
	cfg.StateKey = key
	a, b := oauth2.New("acme", cfg, mapper), oauth2.New("acme", cfg, mapper)
	p.Authorize(a.AuthCodeURL("x"))
	if _, err := b.Callback(ctx, map[string]string{"code": p.Code, "state": "x"}); err != nil {
		t.Fatalf("shared StateKey: %v", err)
	}
}

func TestDiscoverErrors(t *testing.T) {
	p := oauth2test.NewProvider(t, nil)
	if _, err := oauth2.Discover(ctx, nil, p.Issuer()+"/other"); err == nil {
		t.Fatal("discovery of a missing issuer")
	}
	if _, err := oauth2.Discover(ctx, nil, "://bad"); err == nil {
		t.Fatal("bad issuer URL")
	}
}
