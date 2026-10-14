An OpenID Connect provider that acts as a brige to
[XEP-0070](https://xmpp.org/extensions/xep-0070.html).

Runs as a component for now, but making it run as a client instead would be easy.

## XMPP server (Prosody example)

In `prosody.cfg.lua`:

```lua
Component "oidc.example.com"
    component_secret = "mysecretcomponentpassword"
```

## Build & run

```sh
go build .
./xmpp-oidc
```

First run creates an RSA signing key at `JWKS_KEY` (default `jwks.key`)
and an empty SQLite database at `DB` (default `xmpp-oidc.sqlite`) for client registrations.

## Environment variables

| Variable                | Default                | Purpose |
|-------------------------|------------------------|---------|
| `ISSUER`                | `http://localhost:8080` | Public base URL of the provider. Discovery is served at `$ISSUER/.well-known/openid-configuration` |
| `LISTEN`                | `:8080`                | HTTP bind address |
| `JWKS_KEY`              | `jwks.key`             | Path of the RSA key that signs ID tokens. Created if absent. |
| `XMPP_SERVER`           | `localhost:5347`       | `host:port` of the XMPP server component interface |
| `XMPP_DOMAIN`           | (**required**)         | Domain of the component |
| `XMPP_COMPONENT_SECRET` | (**required**)         | Component secret |
| `DB`                    | `xmpp-oidc.sqlite`     | DB for registered clients |
| `TRUSTED_PROXIES`       | `127.0.0.0/8,::1/128`  | Comma-separated CIDRs whose `X-Forwarded-For` is trusted when picking the client IP for the `/register` rate limit. |

## Registering a client (for testing)

RFC 7591 JSON body:

```sh
curl http://localhost:8080/register \
  -H 'Content-Type: application/json' \
  -d '{
    "client_name": "test app",
    "application_type": "web",
    "redirect_uris": ["http://localhost:1234/callback"],
    "grant_types": ["authorization_code"],
    "response_types": ["code"],
    "subject_type": "public",
    "id_token_signed_response_alg": "RS256",
    "scopes": ["openid"]
  }'
```

The response contains the `client_id` used in the authorization request.
