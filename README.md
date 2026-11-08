# social-oauth

[![crates.io](https://img.shields.io/crates/v/social-oauth.svg)](https://crates.io/crates/social-oauth)
[![docs.rs](https://docs.rs/social-oauth/badge.svg)](https://docs.rs/social-oauth)
[![CI](https://github.com/gocfun/social-oauth/actions/workflows/ci.yml/badge.svg)](https://github.com/gocfun/social-oauth/actions/workflows/ci.yml)
[![license](https://img.shields.io/crates/l/social-oauth.svg)](https://github.com/gocfun/social-oauth/blob/main/LICENSE)

Google and Facebook OAuth for Rust backends. Create an authorization URL, exchange
the callback code and receive a normalized profile. Bring your own account model,
state store and application sessions.

[Repository](https://github.com/gocfun/social-oauth) · Rust 1.91+

## Installation

```toml
[dependencies]
social-oauth = "0.1"
```

Enable TOML configuration when needed:

```toml
social-oauth = { version = "0.1", features = ["config-toml"] }
```

Alternatively, install from Git:

```toml
social-oauth = { git = "https://github.com/gocfun/social-oauth", features = ["config-toml"] }
```

Default features are empty. The library has no database or web-framework dependency.
Call its async methods from a Tokio-based application, such as an Axum server.

## Quick start

Create a client once and reuse it in your request handlers:

```rust,no_run
use social_oauth::OAuthClient;

fn google_client() -> Result<OAuthClient, Box<dyn std::error::Error>> {
    Ok(OAuthClient::google(
        std::env::var("GOOGLE_CLIENT_ID")?,
        std::env::var("GOOGLE_CLIENT_SECRET")?,
        "https://example.com/oauth/google/callback",
    )?)
}
```

For Facebook, use `OAuthClient::facebook(client_id, client_secret, redirect_url,
graph_version)` with a Graph version enabled for your Meta app. Register the exact
backend callback URI in the provider console. Keep the client secret server-side.

### Start authorization

Call `client.authorize()`. It returns:

| Value | Use |
| --- | --- |
| `authorization.url` | Redirect the browser to this URL |
| `authorization.pending` | Save privately in the initiating browser's server-side session |

Give pending state a short expiry and consume it atomically once on callback,
including when the provider denies authorization. It supports Serde serialization;
never reconstruct it from client input or expose its serialized form to the browser.

### Handle the callback

After retrieving and consuming the trusted pending record, pass it with the
provider's callback code and state:

```rust,no_run
use social_oauth::{Error, Identity, OAuthClient, PendingAuthorization};

async fn finish_login(
    client: &OAuthClient,
    consumed_pending: PendingAuthorization,
    code: &str,
    returned_state: &str,
) -> Result<Identity, Error> {
    client.complete(consumed_pending, code, returned_state).await
}
```

`complete` checks the client and state, exchanges the code and fetches identity.
Handle provider denial before calling it. Then resolve the identity and create your
own application session. Use provider + subject within the configured provider app
as the identity key; matching email alone is not permission to link accounts.

The crate validates state equality, while your application supplies browser binding,
expiry and one-use storage. Rust ownership alone cannot prevent replay of stored
copies. Avoid logging authorization URLs, callback codes or pending state.

## Provider profiles

| Behavior | Google | Facebook Full (default) | Facebook IdOnly |
| --- | --- | --- | --- |
| Identity key | Google `sub` | App-scoped Facebook `id` | App-scoped Facebook `id` |
| Requested scope | `openid email profile` | `public_profile email` | No explicit extra scope |
| Profile | Names, email, avatar if available | Names, email, avatar if available | ID only |
| Default PKCE | S256 | Disabled | Disabled |

`Identity` contains `provider`, `subject`, `name`, `first_name`, `middle_name`,
`last_name`, `email`, `email_verified` and `avatar_url`. Optional fields can be absent
without failing login. Facebook Full covers the basic login profile, not every
Facebook account field. Its email is not marked verified; `verified_email()` only
returns an email when the provider explicitly marks it verified.

To request only the Facebook ID, set the mode before authorization:

```rust,no_run
use social_oauth::{FacebookProfileMode, OAuthClient};

fn id_only(client: OAuthClient) -> OAuthClient {
    client.with_facebook_profile_mode(FacebookProfileMode::IdOnly)
}
```

IdOnly requests `fields=id` and returns no optional profile data. The setting has
no effect on Google. Facebook subjects are scoped to the Facebook app.

## Optional TOML configuration

Enable `config-toml` in the dependency, then explicitly load a file. This snippet
requires that feature:

```rust,ignore
use social_oauth::{config::SocialOAuthConfig, OAuthClient, Provider};

fn facebook_client() -> Result<OAuthClient, Box<dyn std::error::Error>> {
    let config = SocialOAuthConfig::from_file("config_social.toml")?;
    Ok(config.client(Provider::Facebook)?)
}
```

Enabling the feature or importing a type reads no file. `from_file` reads only the
path you provide; `from_toml` accepts text already read by your application. There
is no automatic file search, environment lookup or environment substitution.

Configure either provider or both. Each section uses the same fields:

```toml
[facebook]
client_id = "<facebook-app-id>"
client_secret = "<facebook-app-secret>"
redirect_url = "https://example.com/oauth/facebook/callback"
auth_url = "https://www.facebook.com/v25.0/dialog/oauth"
token_url = "https://graph.facebook.com/v25.0/oauth/access_token"
profile_url = "https://graph.facebook.com/v25.0/me"
client_authentication = "request_body"
facebook_profile_mode = "full"
```

Choose a Graph version enabled for your app. The first five fields are required;
the remaining options are:

| Option | Default | Alternative |
| --- | --- | --- |
| `profile_url` | Google UserInfo or Facebook's unversioned `/me` | Your explicit profile endpoint/version |
| `client_authentication` | `request_body` | `basic` |
| `facebook_profile_mode` | `full` | `id_only`; ignored for Google |

See the [configuration template](https://github.com/gocfun/social-oauth/blob/main/config_social.example.toml)
for both providers. Unknown provider options are rejected. Unrelated top-level
sections are ignored; requesting an unconfigured provider returns
`ConfigError::ProviderMissing`. Keep credential files out of version control.

## Existing OAuth flows

Use `with_endpoints` for custom/versioned provider URLs and
`with_client_authentication` to select token endpoint authentication.
`authorize_with_state(state, pkce)` preserves application-generated state, including
prefixes, and lets you choose `PkceMode::S256` or `Disabled`.

After your application validates and consumes its state, use
`identity_from_code(code, verifier)` or the separate `exchange_code` and
`fetch_identity` methods. These lower-level methods do not validate state. With
S256, save `pending.pkce_verifier()` privately and supply it during exchange.
See the [API reference](https://docs.rs/social-oauth) for the complete contract.

Identity is fetched directly from provider UserInfo/Graph using a code-exchanged
token. This is a confidential backend OAuth code client; it does not validate ID
tokens or accept externally supplied provider access tokens. Provider tokens remain
opaque and are not persisted. HTTP redirects are disabled, requests time out after
15 seconds and profile bodies are limited to 64 KiB. HTTPS callbacks are required,
except HTTP loopback during development.

## Example application

The [Axum example](https://github.com/gocfun/social-oauth/tree/main/examples/axum)
shows TOML loading, a browser-bound one-use state store, authorization and callback
handlers. It reads the selected provider's callback path and local port from config.
Follow the [demo instructions](https://github.com/gocfun/social-oauth/blob/main/DEVELOPMENT.md#run-the-demo)
to run it from a source checkout.

## Contributing

See [CONTRIBUTING.md](https://github.com/gocfun/social-oauth/blob/main/CONTRIBUTING.md)
for contribution guidelines and [DEVELOPMENT.md](https://github.com/gocfun/social-oauth/blob/main/DEVELOPMENT.md)
for source layout, tests, local examples and the maintainer release process.
