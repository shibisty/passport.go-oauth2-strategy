package oauth2_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"passport"
	"passport-oauth2"
	"passport-oauth2/oauth2test"
)

var ctx = context.Background()

func mapper(p map[string]any) (*passport.Identity, error) {
	return &passport.Identity{ProviderUserID: oauth2.String(p, "id"), Email: oauth2.String(p, "email"), EmailVerified: oauth2.Bool(p, "verified")}, nil
}

func newStrategy(p *oauth2test.Provider) *oauth2.Strategy {
	return oauth2.New("acme", oauth2.Config{
		ClientID: p.ClientID, ClientSecret: p.ClientSecret, RedirectURL: "https://app/cb",
		AuthURL: p.AuthURL(), TokenURL: p.TokenURL(), UserInfoURL: p.UserInfoURL(),
		Scopes: []string{"openid", "email"},
	}, mapper)
}

func TestAuthCodeURL(t *testing.T) {
	s := oauth2.New("acme", oauth2.Config{
		ClientID: "cid", RedirectURL: "https://app/cb?x=1", AuthURL: "https://p/auth?tenant=t1",
		Scopes: []string{"a", "b"}, AuthParams: url.Values{"prompt": {"select_account"}, "state": {"overridden"}},
	}, mapper)
	u, err := url.Parse(s.AuthCodeURL("st&ate"))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	for k, want := range map[string]string{
		"tenant": "t1", "client_id": "cid", "redirect_uri": "https://app/cb?x=1", "response_type": "code",
		"state": "st&ate", "scope": "a b", "prompt": "select_account",
	} {
		if got := q.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if s.Name() != "acme" || s.Config().HTTPClient.Timeout != oauth2.DefaultTimeout {
		t.Error("Name/default HTTP client timeout")
	}
	// Without scopes the parameter is not added; without "?" in AuthURL the separator is "?".
	s2 := oauth2.New("x", oauth2.Config{AuthURL: "https://p/auth"}, mapper)
	if got := s2.AuthCodeURL("s"); !strings.HasPrefix(got, "https://p/auth?") || strings.Contains(got, "scope=") {
		t.Errorf("AuthCodeURL = %s", got)
	}
}

func TestCallbackSuccess(t *testing.T) {
	p := oauth2test.NewProvider(t, map[string]any{"id": float64(1234567), "email": "a@x", "verified": "true"})
	id, err := newStrategy(p).Callback(ctx, map[string]string{"code": p.Code, "state": "s"})
	if err != nil {
		t.Fatal(err)
	}
	if id.Provider != "acme" || id.ProviderUserID != "1234567" || id.Email != "a@x" || !id.EmailVerified || id.Raw["email"] != "a@x" {
		t.Fatalf("identity = %+v", *id)
	}
	reqs := p.Requests()
	if len(reqs) != 2 || reqs[0].URL.Path != "/token" || reqs[1].URL.Path != "/userinfo" {
		t.Fatalf("requests: %v", reqs)
	}
}

func TestCallbackErrors(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(p *oauth2test.Provider)
		params map[string]string
		mapper oauth2.ProfileMapper
		want   string
		is     error
	}{
		{name: "provider error param", params: map[string]string{"error": "access_denied"}, is: oauth2.ErrAccessDenied},
		{name: "no code", params: map[string]string{}, is: oauth2.ErrMissingCode},
		{name: "wrong code", params: map[string]string{"code": "bad"}, want: "token returned 400"},
		{name: "token 500 long body", setup: func(p *oauth2test.Provider) {
			p.TokenStatus, p.TokenBody = 500, strings.Repeat("x", 5000)
		}, want: "token returned 500"},
		{name: "token not json", setup: func(p *oauth2test.Provider) { p.TokenBody = "<html>" }, want: "not JSON"},
		{name: "no access token", setup: func(p *oauth2test.Provider) { p.TokenBody = `{"token_type":"Bearer"}` }, want: "access_token"},
		{name: "token too big", setup: func(p *oauth2test.Provider) {
			p.TokenBody = `{"x":"` + strings.Repeat("a", 1<<20+10) + `"}`
		}, want: "larger than"},
		{name: "userinfo 401", setup: func(p *oauth2test.Provider) { p.AccessToken = "other" }, want: "userinfo returned 401"},
		{name: "userinfo not json", setup: func(p *oauth2test.Provider) { p.UserInfoBody = "nope" }, want: "not JSON"},
		{name: "no user id", setup: func(p *oauth2test.Provider) { p.Profile = map[string]any{"email": "a@x"} }, is: oauth2.ErrNoUserID},
		{name: "mapper error", mapper: func(map[string]any) (*passport.Identity, error) { return nil, errors.New("bad profile") }, want: "bad profile"},
		{name: "mapper nil", mapper: func(map[string]any) (*passport.Identity, error) { return nil, nil }, is: oauth2.ErrNoUserID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := oauth2test.NewProvider(t, map[string]any{"id": "1"})
			s := newStrategy(p)
			if tc.setup != nil {
				// The provider's AccessToken changes after issuance — to test 401.
				if tc.name == "userinfo 401" {
					tok, err := s.Exchange(ctx, p.Code)
					if err != nil {
						t.Fatal(err)
					}
					tc.setup(p)
					_, err = s.FetchUserInfo(ctx, tok.AccessToken)
					if err == nil || !strings.Contains(err.Error(), tc.want) {
						t.Fatalf("got %v, want %q", err, tc.want)
					}
					return
				}
				tc.setup(p)
			}
			if tc.mapper != nil {
				cfg := s.Config()
				s = oauth2.New("acme", cfg, tc.mapper)
			}
			params := tc.params
			if params == nil {
				params = map[string]string{"code": p.Code}
			}
			_, err := s.Callback(ctx, params)
			if err == nil {
				t.Fatal("want error")
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("got %v, want %v", err, tc.is)
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if len(err.Error()) > 1000 {
				t.Fatalf("error text must be truncated, got %d bytes", len(err.Error()))
			}
		})
	}
}

func TestNetworkErrorsAndTimeout(t *testing.T) {
	s := oauth2.New("acme", oauth2.Config{TokenURL: "http://127.0.0.1:1/token", UserInfoURL: "http://127.0.0.1:1/u"}, mapper)
	if _, err := s.Exchange(ctx, "c"); err == nil {
		t.Error("connection refused should be an error")
	}
	if _, err := s.FetchUserInfo(ctx, "t"); err == nil {
		t.Error("connection refused should be an error")
	}
	bad := oauth2.New("acme", oauth2.Config{TokenURL: "::bad", UserInfoURL: "::bad"}, mapper)
	if _, err := bad.Exchange(ctx, "c"); err == nil {
		t.Error("bad URL should be an error")
	}
	if _, err := bad.FetchUserInfo(ctx, "t"); err == nil {
		t.Error("bad URL should be an error")
	}

	// A provider slower than the client's timeout. (A 1 ns timeout is not
	// reliable: on Windows a loopback request can finish before it fires.)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer slow.Close()
	timed := oauth2.New("acme", oauth2.Config{TokenURL: slow.URL, HTTPClient: &http.Client{Timeout: 50 * time.Millisecond}}, mapper)
	if _, err := timed.Exchange(ctx, "c"); err == nil {
		t.Error("timeout should be an error")
	}
}

func TestHelpers(t *testing.T) {
	p := map[string]any{"s": "x", "f": float64(42), "n": json.Number("7"), "b": true, "bs": "true", "bad": []int{}}
	for k, want := range map[string]string{"s": "x", "f": "42", "n": "7", "bad": "", "missing": ""} {
		if got := oauth2.String(p, k); got != want {
			t.Errorf("String(%s) = %q", k, got)
		}
	}
	if !oauth2.Bool(p, "b") || !oauth2.Bool(p, "bs") || oauth2.Bool(p, "s") || oauth2.Bool(p, "missing") {
		t.Error("Bool")
	}
}
