# Contributing

Thanks for contributing to social-oauth. Start with [DEVELOPMENT.md](DEVELOPMENT.md)
for checkout setup, source layout, the runnable Axum example and validation commands.

## Changes and pull requests

- Describe the concrete behavior you are fixing or adding. Keep the change focused.
- Preserve the public imports and keep the core independent of database, account
  models and web frameworks. Optional integrations should remain opt-in features.
- Preserve state/PKCE validation and redaction of credentials, codes and tokens.
- Add a regression test for changed behavior. Test both default and relevant
  optional features; use local HTTP mocks rather than real credentials.
- Update user-facing instructions in README when installation or usage changes.
  Keep architecture, validation and release details in DEVELOPMENT.md.
- Report which checks ran and any remaining limitations in the pull request.

Use [GitHub issues](https://github.com/gocfun/social-oauth/issues) for reproducible
bugs or proposed features. Include relevant versions and a minimal reproduction
with credentials and personal information removed.

## Releases

Crates.io publishing is handled by maintainers. Follow the release section in
DEVELOPMENT.md; do not include registry credentials or local OAuth config in commits.
