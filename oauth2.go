// Package oauth2 implements a generic login strategy for the OAuth2 Authorization
// Code flow, using only the standard library. gtr package: passport-oauth2.
//
// Providers differ in endpoints and profile fields, so a strategy for a
// specific provider is just a Config plus a profile-mapping function:
//
//	github := oauth2.New("github", oauth2.Config{
//		ClientID: id, ClientSecret: secret, RedirectURL: "https://app/auth/github/callback",
//		AuthURL:     "https://github.com/login/oauth/authorize",
//		TokenURL:    "https://github.com/login/oauth/access_token",
//		UserInfoURL: "https://api.github.com/user",
//		Scopes:      []string{"read:user", "user:email"},
//	}, func(p map[string]any) (*passport.Identity, error) {
//		return &passport.Identity{ProviderUserID: oauth2.String(p, "id"), Name: oauth2.String(p, "name")}, nil
//	})
//
// This is how passport-google and passport-facebook are built.
package oauth2

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"passport"
)

const (
	// DefaultTimeout is the timeout for provider requests when HTTPClient is not set.
	DefaultTimeout = 15 * time.Second
	maxBody        = 1 << 20 // a provider response larger than 1 MB is an error
	maxErrBody     = 512     // how much of the response body to include in the error message
)

var (
	// ErrMissingCode means the callback has no code parameter.
	ErrMissingCode = errors.New("oauth2: callback has no code parameter")
	// ErrAccessDenied means the user declined or the provider returned an error in the callback.
	ErrAccessDenied = errors.New("oauth2: provider denied login")
	// ErrNoUserID means the profile has no user identifier.
	ErrNoUserID = errors.New("oauth2: provider profile has no user id")
)

// Config holds the provider parameters.
type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string

	AuthURL     string
	TokenURL    string
	UserInfoURL string
	Scopes      []string

	// AuthParams are extra login URL parameters (e.g. prompt=select_account).
	AuthParams url.Values
	// HTTPClient is used for provider requests; defaults to one with DefaultTimeout.
	HTTPClient *http.Client

	// PKCE adds code_challenge (S256) to the login URL and code_verifier to
	// the code exchange (RFC 7636): a stolen code is useless without it.
	PKCE bool
	// OIDC verifies the provider's id_token (see OIDC); nil skips it.
	OIDC *OIDC
	// ClientSecretFunc makes the client secret for each code exchange when it
	// is not a fixed string (Apple: a JWT signed with the team's key); it
	// overrides ClientSecret.
	ClientSecretFunc func() (string, error)
	// Enrich adds to the profile before it is mapped, with the access token
	// (GitHub: the verified email from /user/emails).
	Enrich func(ctx context.Context, s *Strategy, tok *Token, profile map[string]any) error

	// StateKey derives the PKCE verifier and the OIDC nonce from the state,
	// so nothing has to be stored between the redirect and the callback.
	// Give every instance of the application the same key (32+ random
	// bytes); nil is a random key per process (one instance only).
	StateKey []byte
}

// Token is the token endpoint response.
type Token struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token,omitempty"`
}

// ProfileMapper converts a provider profile into an Identity. The strategy fills in
// Provider and Raw itself; an empty ProviderUserID is an ErrNoUserID error.
type ProfileMapper func(profile map[string]any) (*passport.Identity, error)

// Strategy implements passport.RedirectStrategy.
type Strategy struct {
	name   string
	cfg    Config
	mapper ProfileMapper
}

// New creates a strategy named name (also used as Identity.Provider).
func New(name string, cfg Config, mapper ProfileMapper) *Strategy {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: DefaultTimeout}
	}
	if len(cfg.StateKey) == 0 && (cfg.PKCE || cfg.OIDC != nil) {
		cfg.StateKey = make([]byte, 32)
		if _, err := rand.Read(cfg.StateKey); err != nil {
			panic("oauth2: no random source: " + err.Error())
		}
	}
	return &Strategy{name: name, cfg: cfg, mapper: mapper}
}

// Name returns the strategy name.
func (s *Strategy) Name() string { return s.name }

// Config returns a copy of the settings.
func (s *Strategy) Config() Config { return s.cfg }

// AuthCodeURL builds the provider login URL.
func (s *Strategy) AuthCodeURL(state string) string {
	v := url.Values{}
	for k, vals := range s.cfg.AuthParams {
		v[k] = append([]string(nil), vals...)
	}
	v.Set("client_id", s.cfg.ClientID)
	v.Set("redirect_uri", s.cfg.RedirectURL)
	v.Set("response_type", "code")
	v.Set("state", state)
	if len(s.cfg.Scopes) > 0 {
		v.Set("scope", strings.Join(s.cfg.Scopes, " "))
	}
	if s.cfg.PKCE {
		v.Set("code_challenge", challenge(s.derive("pkce", state)))
		v.Set("code_challenge_method", "S256")
	}
	if s.cfg.OIDC != nil {
		v.Set("nonce", s.derive("nonce", state))
	}
	sep := "?"
	if strings.Contains(s.cfg.AuthURL, "?") {
		sep = "&"
	}
	return s.cfg.AuthURL + sep + v.Encode()
}

// Callback exchanges the code for a token, fetches the profile and maps it.
// Check state before calling it (httpauth.CheckState).
func (s *Strategy) Callback(ctx context.Context, params map[string]string) (*passport.Identity, error) {
	if e := params["error"]; e != "" {
		return nil, fmt.Errorf("%w: %s %s", ErrAccessDenied, e, params["error_description"])
	}
	code := params["code"]
	if code == "" {
		return nil, ErrMissingCode
	}
	state := params["state"]
	tok, err := s.exchange(ctx, code, state)
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if s.cfg.OIDC != nil {
		if claims, err = s.verifyIDToken(ctx, tok.IDToken, state); err != nil {
			return nil, fmt.Errorf("oauth2 %s: %w", s.name, err)
		}
	}
	profile := claims
	if s.cfg.UserInfoURL != "" || claims == nil {
		if profile, err = s.FetchUserInfo(ctx, tok.AccessToken); err != nil {
			return nil, err
		}
		// OIDC Core 5.3.2: the userinfo must be about the id_token's user.
		if claims != nil && String(profile, "sub") != String(claims, "sub") {
			return nil, fmt.Errorf("oauth2 %s: %w: userinfo sub differs from the id_token's", s.name, ErrIDToken)
		}
	}
	if s.cfg.Enrich != nil {
		if profile == nil {
			profile = map[string]any{}
		}
		if err := s.cfg.Enrich(ctx, s, tok, profile); err != nil {
			return nil, fmt.Errorf("oauth2 %s: %w", s.name, err)
		}
	}
	id, err := s.mapper(profile)
	if err != nil {
		return nil, fmt.Errorf("oauth2 %s: profile: %w", s.name, err)
	}
	if id == nil || id.ProviderUserID == "" {
		return nil, fmt.Errorf("oauth2 %s: %w", s.name, ErrNoUserID)
	}
	id.Provider = s.name
	id.Raw = profile
	return id, nil
}

// Exchange exchanges an authorization code for a token. With PKCE use
// Callback (it knows the state the verifier comes from).
func (s *Strategy) Exchange(ctx context.Context, code string) (*Token, error) {
	return s.exchange(ctx, code, "")
}

func (s *Strategy) exchange(ctx context.Context, code, state string) (*Token, error) {
	form := url.Values{}
	if s.cfg.PKCE {
		form.Set("code_verifier", s.derive("pkce", state))
	}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", s.cfg.RedirectURL)
	form.Set("client_id", s.cfg.ClientID)
	secret := s.cfg.ClientSecret
	if s.cfg.ClientSecretFunc != nil {
		var err error
		if secret, err = s.cfg.ClientSecretFunc(); err != nil {
			return nil, fmt.Errorf("oauth2 %s: client secret: %w", s.name, err)
		}
	}
	form.Set("client_secret", secret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	var tok Token
	if err := s.do(req, "token", &tok); err != nil {
		return nil, err
	}
	if tok.AccessToken == "" {
		return nil, fmt.Errorf("oauth2 %s: token endpoint did not return access_token", s.name)
	}
	return &tok, nil
}

// GetJSON fetches url with the access token into dest (for Enrich).
func (s *Strategy) GetJSON(ctx context.Context, accessToken, url string, dest any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	return s.do(req, "request", dest)
}

// FetchUserInfo fetches the profile using the access token.
func (s *Strategy) FetchUserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	var profile map[string]any
	if err := s.do(req, "userinfo", &profile); err != nil {
		return nil, err
	}
	return profile, nil
}

func (s *Strategy) do(req *http.Request, what string, dest any) error {
	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("oauth2 %s: %s: %w", s.name, what, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return fmt.Errorf("oauth2 %s: %s: %w", s.name, what, err)
	}
	if len(body) > maxBody {
		return fmt.Errorf("oauth2 %s: %s: response larger than %d bytes", s.name, what, maxBody)
	}
	if resp.StatusCode >= 300 {
		snippet := body
		if len(snippet) > maxErrBody {
			snippet = snippet[:maxErrBody]
		}
		return fmt.Errorf("oauth2 %s: %s returned %d: %s", s.name, what, resp.StatusCode, snippet)
	}
	if err := json.Unmarshal(body, dest); err != nil {
		return fmt.Errorf("oauth2 %s: %s: not JSON: %w", s.name, what, err)
	}
	return nil
}

// String extracts a string from the profile; a numeric id is also converted to a string
// (GitHub returns id as a number).
func String(profile map[string]any, key string) string {
	switch v := profile[key].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case json.Number:
		return v.String()
	default:
		return ""
	}
}

// Bool extracts a boolean value; the strings "true"/"false" are understood too
// (some providers return email_verified as a string).
func Bool(profile map[string]any, key string) bool {
	switch v := profile[key].(type) {
	case bool:
		return v
	case string:
		b, _ := strconv.ParseBool(v)
		return b
	default:
		return false
	}
}

var _ passport.RedirectStrategy = (*Strategy)(nil)
