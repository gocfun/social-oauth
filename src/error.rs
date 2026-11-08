/// Errors intentionally omit provider bodies, authorization codes and token values.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Missing credentials, invalid redirect URI, or invalid Facebook API version.
    #[error("invalid OAuth configuration: {0}")]
    Configuration(&'static str),
    /// Caller-supplied state was empty.
    #[error("OAuth state must be non-empty")]
    InvalidState,
    /// HTTP client construction failed.
    #[error("failed to construct the OAuth HTTP client")]
    HttpClient,
    /// State did not match the browser session's pending authorization.
    #[error("OAuth state mismatch")]
    StateMismatch,
    /// Pending authorization belongs to another provider, client, or redirect URI.
    #[error("pending authorization belongs to another OAuth client")]
    ClientMismatch,
    /// The callback did not contain an authorization code.
    #[error("authorization code is empty")]
    MissingCode,
    /// The provider rejected the code exchange or returned an invalid token response.
    #[error("OAuth token exchange failed")]
    TokenExchange,
    /// UserInfo/Graph transport failed.
    #[error("provider profile request failed")]
    ProfileRequest,
    /// UserInfo/Graph returned a non-success status. Response bodies are not retained.
    #[error("provider profile returned HTTP {0}")]
    ProfileStatus(u16),
    /// UserInfo/Graph returned a malformed, oversized or incomplete identity.
    #[error("invalid provider profile")]
    InvalidProfile,
}
