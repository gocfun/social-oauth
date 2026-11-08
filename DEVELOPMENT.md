# Development guide

This guide is for contributors and maintainers. For installation and application
integration, see [README.md](README.md).

## Set up a checkout

```sh
git clone https://github.com/gocfun/social-oauth.git
cd social-oauth
rustup show
```

The repository pins Rust 1.91.0 with rustfmt and Clippy through
`rust-toolchain.toml`. The library supports Rust 1.91 or newer.
Default features stay empty; TOML loading is tested separately with `config-toml`.
No database or production provider credentials are required for automated tests.

## Run the demo

The Axum example reads the same `config_social.toml` schema as the library's
optional loader. Run these commands from this repository:

```sh
cp -n config_social.example.toml config_social.toml
chmod 600 config_social.toml
```

Fill in the credentials and callback URL for the provider you want to test. Choose
a Facebook Graph API version enabled for your Meta app. Register that exact
`redirect_url` in the provider console, then start one provider:

```sh
cargo run --example axum --features config-toml -- config_social.toml google
# Or stop that process and run Facebook:
cargo run --example axum --features config-toml -- config_social.toml facebook
```

With the supplied template, open `http://localhost:3000` and select **Start OAuth**.
The callback is `http://localhost:3000/oauth/callback`. The example returns identity
JSON; it does not create an account or issue an application session.

| Argument | Meaning |
| --- | --- |
| `config_social.toml` | Explicit config file path; any filename/path is accepted |
| `google` / `facebook` | Section to use; the other section is optional |
| Optional third argument | Listen address, e.g. `127.0.0.1:9001` |

The callback route comes from the selected section's `redirect_url` path. For an
HTTP loopback callback, the default listen port also comes from that URL. Thus
`http://localhost:8083/auth/oauth/facebook/callback` mounts that path on port 8083,
without editing the example. The paths `/` and `/login` are reserved by the demo.
Use the same hostname to open the app as the one in `redirect_url`, so the browser
session cookie reaches the callback.

For an HTTPS callback behind a tunnel/reverse proxy, choose the internal listen
address explicitly if needed:

```sh
cargo run --example axum --features config-toml -- config_social.toml facebook 127.0.0.1:3000
```

The demo serves HTTP internally and defaults to loopback port 3000 for HTTPS
callbacks. Start the flow through the configured public HTTPS origin; the example
adds `Secure` to its cookie when the callback scheme is HTTPS. Your proxy/tunnel
must forward the callback path to this listener.

The example is a single-process demo. It uses a separate HttpOnly, SameSite=Lax
browser cookie and a bounded in-memory state map with a five-minute TTL. Pending
state is consumed before provider requests. Starting again in the same browser
replaces its previous attempt. Deployment needs a suitable shared one-use store
and rate limits. Avoid logging callback query strings or authorization URLs.

## Source layout

```text
src/
  lib.rs                   Public re-exports and optional config module
  provider.rs              Provider, endpoints and option enums
  state.rs                 Authorization and private pending state
  identity.rs              Normalized identity and profile parsing
  error.rs                 Redacted OAuth errors
  client/
    mod.rs                 Client construction and settings
    authorization.rs       Authorization URL, PKCE and state validation
    exchange.rs            Code exchange, opaque token and identity HTTP lookup
    tests.rs               Client/state/profile regressions and HTTP mocks
  config/
    mod.rs                 Opt-in TOML loader and client factory
    tests.rs               Config and template regression tests
examples/axum/
  main.rs                  Explicit CLI/config loading and router setup
  settings.rs              Configured callback path, port and cookie policy
  handlers.rs              Browser-bound login/callback flow
  tests.rs                 State safety and config/router regression tests
```

Public imports stay under `social_oauth::{OAuthClient, Identity, ...}`;
TOML types stay under `social_oauth::config`. Library defaults remain independent
of the example's `config-toml` requirement.

## Validation

```sh
cargo fmt --all -- --check
cargo check --all-targets --no-default-features --locked
cargo test --no-default-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
cargo test --example axum --features config-toml --locked
RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --all-features --locked
cargo package --all-features --locked
```

Tests use local HTTP mocks, not real provider credentials. Live consent/callback
verification needs your own provider app. Review package metadata before publishing.

## Release on crates.io

Maintainers publish from a clean, committed checkout after the validation commands
above pass. The initial release is `0.1.0`.

1. Check crate-name availability and publishing rights on crates.io. A GitHub
   repository name does not reserve a crate name.
2. Review version, license and repository/documentation URLs. Keep the README
   installation snippets aligned with the version being released.
3. Inspect package contents and verify both optional-feature and default builds:

   ```sh
   cargo package --list --locked
   cargo package --all-features --locked
   cargo publish --dry-run --all-features --locked
   ```

4. Publish using the maintainer's configured registry authentication:

   ```sh
   cargo publish --locked
   ```

5. Verify the version on crates.io, the docs.rs build (including `config-toml`) and
   the installation snippets. Tag the matching source revision after publication.

Publishing is a maintainer action. Commands in this document are instructions;
the documentation update itself does not publish or push anything.

Local `config_social.toml`, `config_social.local.toml`, `.env` files and macOS
`.DS_Store` metadata are excluded from packages. Inspect the file list before each
release; use the placeholder-only `config_social.example.toml` in the repository.

## References

- [oauth2-rs](https://docs.rs/oauth2/5.0.0/oauth2/)
- [Google UserInfo](https://developers.google.com/identity/openid-connect/openid-connect)
- [Facebook login](https://developers.facebook.com/docs/facebook-login/guides/advanced/manual-flow/)
