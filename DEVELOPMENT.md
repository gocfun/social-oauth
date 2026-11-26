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
No database or production provider credentials are required for automated tests.

## Run the demo

The Axum example uses the library's TOML loader. Run these commands from this
repository.

```sh
cp -n config_social.example.toml config_social.toml
chmod 600 config_social.toml
```

Fill in the credentials and callback URL for the provider you want to test. Choose
a Facebook Graph API version enabled for your Meta app. Register that exact
`redirect_url` in the provider console, then start one provider:

```sh
cargo run --example axum -- config_social.toml google
# Stop the running demo before starting another provider.
cargo run --example axum -- config_social.toml facebook
cargo run --example axum -- config_social.toml discord
```

With the supplied template, open `http://localhost:3000` and select **Start OAuth**.
The callback is `http://localhost:3000/oauth/callback`. The example returns identity
JSON; it does not create an account or issue an application session.

| Argument | Meaning |
| --- | --- |
| `config_social.toml` | Explicit config file path; any filename/path is accepted |
| `google` / `facebook` / `discord` / `apple` | Provider section to use |
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
cargo run --example axum -- config_social.toml facebook 127.0.0.1:3000
```

The demo serves HTTP internally and defaults to loopback port 3000 for HTTPS
callbacks. Start the flow through the configured public HTTPS origin; the example
adds `Secure` to its cookie when the callback scheme is HTTPS. Your proxy/tunnel
must forward the callback path to this listener.

For Apple, run the demo with `apple` behind the registered public HTTPS origin.
The demo receives Apple's form POST and sets its HttpOnly cookie with
`Secure; SameSite=None` so it reaches the callback. Other providers use
`SameSite=Lax`.

The example is a single-process demo. It uses a browser cookie and a bounded
in-memory state map with a five-minute TTL. Pending
state is consumed before provider requests. Starting again in the same browser
replaces its previous attempt. Deployment needs a suitable shared one-use store
and rate limits. Avoid logging callback query strings or authorization URLs.

## Source layout

```text
src/
  lib.rs                   Public re-exports and config module
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
    mod.rs                 TOML loader and client factory
    tests.rs               Config and template regression tests
examples/axum/
  main.rs                  Explicit CLI/config loading and router setup
  settings.rs              Configured callback path, port and cookie policy
  handlers.rs              Browser-bound login/callback flow
  tests.rs                 State safety and config/router regression tests
```

Import client and identity types from `social_oauth` and TOML configuration
types from `social_oauth::config`.

## Validation

```sh
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo test --example axum --locked
RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --locked
cargo package --locked
```

Tests use local HTTP mocks, not real provider credentials. Live consent/callback
verification needs your own provider app. Review package metadata before publishing.

## Release on crates.io

The GitHub Actions workflow publishes the version identified by a matching
`v<version>` tag once its checks pass.

1. In the crate settings on crates.io, configure a GitHub Trusted Publisher
   with owner `gocfun`, repository `social-oauth`, and workflow `ci.yml`.
   [Trusted Publishing setup](https://crates.io/docs/trusted-publishing)
2. Update `Cargo.toml`, `Cargo.lock`, the README version, and [CHANGELOG.md](CHANGELOG.md).
   Run the validation commands and inspect the package contents.
   ```sh
   cargo package --list --locked
   ```
3. Commit the release, then push the commit and the matching tag. For version
   `0.1.2`, run the following from `main`.
   ```sh
   git tag -a v0.1.2 -m "social-oauth 0.1.2"
   git push --atomic origin main refs/tags/v0.1.2
   ```
4. Check the tag's GitHub Actions run, the version on crates.io, and the docs.rs build.

Local `config_social.toml`, `config_social.local.toml`, `.env` files and macOS
`.DS_Store` metadata are excluded from packages. Inspect the file list before each
release; use the placeholder-only `config_social.example.toml` in the repository.

## References

- [oauth2-rs](https://docs.rs/oauth2/5.0.0/oauth2/)
- [Google UserInfo](https://developers.google.com/identity/openid-connect/openid-connect)
- [Facebook login](https://developers.facebook.com/docs/facebook-login/guides/advanced/manual-flow/)
