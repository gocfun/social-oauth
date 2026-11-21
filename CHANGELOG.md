# Changelog

## [0.1.1]

### Added

- Discord OAuth for confidential clients, with authorization code exchange,
  S256 PKCE, and profile lookup using the Discord user ID.
- A `[discord]` TOML section and Discord support in the Axum demo.

### Changed

- TOML configuration is built in. Remove `features = ["config-toml"]` from
  dependency declarations and remove `--features config-toml` from Cargo commands.
- GitHub Actions publishes tagged releases to crates.io after CI passes.

### Fixed

- Discord authorization URLs with an existing `response_type` query parameter
  now send `response_type=code` exactly once.

## [0.1.0]

- Initial release with Google and Facebook OAuth, optional TOML configuration,
  and an Axum example.

[0.1.1]: https://github.com/gocfun/social-oauth/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/gocfun/social-oauth/tree/v0.1.0
