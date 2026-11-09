# passport-oauth2

A generic OAuth2 strategy (Authorization Code flow) for
[passport](https://github.com/shibisty/passport.go). Standard library only.
`passport-google` and `passport-facebook` are built on it; any other provider is
just a `Config` and a profile-mapping function:

## Installation

```bash
gtr add github:shibisty/passport.go github:shibisty/passport.go-oauth2-strategy
```

`passport` is a peer dependency (`^0.1`): the application adds it, and every strategy
plugs into the same `Authenticator`.

## Usage

Import as `oauth2 "passport-oauth2"` (Go package `oauth2`), next to `"passport"`.

```go
github := oauth2.New("github", oauth2.Config{
	ClientID: id, ClientSecret: secret,
	RedirectURL: "https://app.example/auth/github/callback",
	AuthURL:     "https://github.com/login/oauth/authorize",
	TokenURL:    "https://github.com/login/oauth/access_token",
	UserInfoURL: "https://api.github.com/user",
	Scopes:      []string{"read:user", "user:email"},
}, func(p map[string]any) (*passport.Identity, error) {
	return &passport.Identity{ProviderUserID: oauth2.String(p, "id"), Name: oauth2.String(p, "name")}, nil
})
a.Use(github)
```

Login in handlers (with CSRF protection from `passport/httpauth`):

```go
// GET /auth/github
state, _ := httpauth.NewState(w)
url, _ := a.RedirectURL("github", state)
http.Redirect(w, r, url, http.StatusFound)

// GET /auth/github/callback
if err := httpauth.CheckState(w, r); err != nil { /* 400 */ }
q := r.URL.Query()
identity, err := a.Callback(ctx, "github", map[string]string{"code": q.Get("code"), "state": q.Get("state"), "error": q.Get("error")})
```

Pass `state` to `Callback`: PKCE and OIDC derive their values from it.

### PKCE and OpenID Connect

```go
d, err := oauth2.Discover(ctx, nil, "https://accounts.google.com") // .well-known/openid-configuration
cfg := oauth2.Config{ClientID: id, ClientSecret: secret, RedirectURL: cb,
	Scopes: []string{"openid", "email", "profile"}, StateKey: []byte(os.Getenv("OAUTH_STATE_KEY"))}
d.Configure(&cfg) // endpoints, OIDC and PKCE
cfg.UserInfoURL = "" // the profile comes from the verified id_token
s := oauth2.New("google", cfg, mapper)
```

- `PKCE: true` adds `code_challenge` (S256) to the login URL and `code_verifier` to the
  exchange (RFC 7636), so an intercepted code cannot be redeemed.
- `OIDC: &oauth2.OIDC{Issuer, JWKSURL}` requires an `id_token` signed with a key of the
  provider's JWKS (RS256 ≥ 2048 bits, or ES256), with the exact `iss`, the client in `aud`
  (and `azp` when there are several), `exp`, `iat` and the `nonce` of the login. Keys are
  cached and fetched again for an unknown `kid`, at most once a minute. With a
  `UserInfoURL` the profile is fetched too, and its `sub` must match the token's.
- The verifier and the nonce are derived from the state with `StateKey` (HMAC-SHA256), so
  nothing is stored between the redirect and the callback, and they cannot be computed
  from the state alone. Give every instance the same 32-byte key; without one each
  process makes its own (fine for one instance).
- Errors: `ErrIDToken` for any id_token problem.

- Provider request timeout is 15 s (`DefaultTimeout`) unless you set your own `HTTPClient`.
- A response larger than 1 MB is an error; the error message includes at most 512 bytes of the response body.
- Errors: `ErrAccessDenied` (the user declined), `ErrMissingCode`, `ErrNoUserID`.
- `oauth2.String` understands numeric ids (GitHub); `oauth2.Bool` understands `"true"` as a string.

## Testing strategies: `oauth2test`

A fake provider built on `httptest`:

```go
p := oauth2test.NewProvider(t, map[string]any{"id": "42", "email": "a@x"})
// p.EnableOIDC(false) signs id_tokens (RS256; true: ES256) and serves JWKS and discovery;
// p.Authorize(s.AuthCodeURL(state)) records the PKCE challenge and nonce of a login.
s := oauth2.New("acme", oauth2.Config{
	ClientID: p.ClientID, ClientSecret: p.ClientSecret,
	AuthURL: p.AuthURL(), TokenURL: p.TokenURL(), UserInfoURL: p.UserInfoURL(),
}, mapper)
identity, err := s.Callback(ctx, map[string]string{"code": p.Code})
```

`TokenStatus`, `TokenBody`, `UserInfoStatus`, `UserInfoBody` override responses for
testing errors; `Requests()` returns the received requests.

## Tests

In a checkout, run `gtr install` once, then `gtr run test`.

## License

MIT
