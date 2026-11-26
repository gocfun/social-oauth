# social-oauth

[![Version 0.1.2](https://img.shields.io/badge/version-0.1.2-blue.svg)](https://crates.io/crates/social-oauth/0.1.2)
[![docs.rs for 0.1.2](https://img.shields.io/docsrs/social-oauth/0.1.2)](https://docs.rs/social-oauth/0.1.2/social_oauth/)
[![CI](https://github.com/gocfun/social-oauth/actions/workflows/ci.yml/badge.svg)](https://github.com/gocfun/social-oauth/actions/workflows/ci.yml)
[![license](https://img.shields.io/crates/l/social-oauth.svg)](https://github.com/gocfun/social-oauth/blob/main/LICENSE)

Google, Facebook, Discord and Apple OAuth for Rust backends. Create an authorization URL, exchange
the callback code and receive a normalized profile. Bring your own account model,
state store and application sessions.

[Repository](https://github.com/gocfun/social-oauth) · Rust 1.91+

## Installation

```toml
[dependencies]
social-oauth = "0.1.2"
```

Alternatively, install from Git:

```toml
social-oauth = { git = "https://github.com/gocfun/social-oauth" }
```

TOML configuration is built in. Call the library's async methods from a
Tokio-based application, such as an Axum server.

## Quick start

Copy `config_social.example.toml` to `config_social.toml` and fill in the
credentials for the provider you want to use. Register the exact backend
`redirect_url` in the provider console. Load the file once at startup and reuse
the client in your request handlers.

```rust,no_run
fn oauth_client() -> Result<social_oauth::OAuthClient, social_oauth::config::ConfigError> {
    use social_oauth::{config::SocialOAuthConfig, Provider};

    let config = SocialOAuthConfig::from_file("config_social.toml")?;
    config.client(Provider::Discord)
}
```

Select `Provider::Google`, `Provider::Facebook` or `Provider::Apple` to load the
corresponding TOML section. Keep the file on the server and out of version control.

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

If multiple providers share a callback, use the provider recorded in pending
state and check that a Discord response contains `iss=https://discord.com` before
exchanging the code. See [Discord OAuth2](https://docs.discord.com/developers/topics/oauth2#issuer-identification).

## Provider profiles

| Behavior | Google | Facebook Full (default) | Facebook IdOnly | Discord |
| --- | --- | --- | --- | --- |
| Identity key | Google `sub` | App-scoped Facebook `id` | App-scoped Facebook `id` | Discord user `id` |
| Requested scope | `openid email profile` | `public_profile email` | No explicit extra scope | `identify email` |
| Profile | Names, email, avatar if available | Names, email, avatar if available | ID only | Display name or username, email, avatar if available |
| Default PKCE | S256 | Disabled | Disabled | S256 |

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

## TOML configuration

`from_file` reads OAuth settings from the exact path you provide. If your
application already reads the TOML file, pass its contents to `from_toml`.

Configure the providers you need. Each section uses the same fields:

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

Choose a Graph version enabled for your app when configuring Facebook. Each
provider section requires the first five fields and supports the following options.

| Option | Default | Alternative |
| --- | --- | --- |
| `profile_url` | Google UserInfo, Facebook's unversioned `/me`, or Discord's v10 `/users/@me` | Your explicit profile endpoint/version |
| `client_authentication` | `request_body` | `basic` |
| `facebook_profile_mode` | `full` | `id_only` for Facebook |

See the [configuration template](https://github.com/gocfun/social-oauth/blob/main/config_social.example.toml)
for all four providers. Unknown provider options are rejected. Unrelated top-level
sections are ignored; requesting an unconfigured provider returns
`ConfigError::ProviderMissing`. Keep credential files out of version control.

### Sign in with Apple

Use the optional `[apple]` section with the five required fields. Use your
Services ID as `client_id`, a signed Apple client-secret JWT as `client_secret`,
and the registered backend HTTPS callback as `redirect_url`. Rotate the JWT before
expiry. Apple authenticates the client in the token request body.

Mount a POST callback for Apple's `form_post` response. Store the complete
`PendingAuthorization` so the server retains both state and nonce. If you use a
browser cookie to identify the pending record, configure it to reach the callback
on a cross-site form POST. Call `complete` after checking browser ownership and
atomically consuming the record. The library exchanges the code server-side and
verifies the ID token against Apple's keys before returning its `sub`.

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

Google, Facebook and Discord fetch identity from their profile endpoints after
code exchange. Apple verifies a code-exchanged ID token. Provider tokens stay
opaque and the library does not persist them. HTTP redirects are disabled,
requests time out after 15 seconds and profile and JWKS bodies are limited to
64 KiB. The Apple callback requires HTTPS with a domain and callback path. The
other flows also support HTTP loopback for local development.

## Example application

The [Axum example](https://github.com/gocfun/social-oauth/tree/main/examples/axum)
shows TOML loading, a browser-bound one-use state store, authorization and callback
handlers. It reads the selected provider's callback path and local port from config.
Run the Discord demo after filling in the `[discord]` section.

```sh
cargo run --example axum -- config_social.toml discord
```

Follow the [demo instructions](https://github.com/gocfun/social-oauth/blob/main/DEVELOPMENT.md#run-the-demo)
to configure the callback and select a provider.

## Contributing

See the [changelog](https://github.com/gocfun/social-oauth/blob/main/CHANGELOG.md) for release changes.

See [CONTRIBUTING.md](https://github.com/gocfun/social-oauth/blob/main/CONTRIBUTING.md)
for contribution guidelines and [DEVELOPMENT.md](https://github.com/gocfun/social-oauth/blob/main/DEVELOPMENT.md)
for source layout, tests, local examples and the maintainer release process.

To request support for another social login provider, contact me at
[windy@gocfun.vn](mailto:windy@gocfun.vn).
