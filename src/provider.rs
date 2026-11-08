use serde::{Deserialize, Serialize};

/// Supported identity providers. Facebook subjects are scoped to the Facebook app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    /// Google: subject is the `sub` field from UserInfo.
    Google,
    /// Facebook: subject is the app-scoped `id` field from Graph API.
    Facebook,
}

/// Provider URLs supplied by trusted application configuration, never callback input.
/// This lets existing applications retain their own endpoint/version configuration.
#[derive(Clone)]
pub struct Endpoints {
    /// Browser authorization endpoint.
    pub authorization_url: String,
    /// Server-side authorization code exchange endpoint.
    pub token_url: String,
    /// Google UserInfo or Facebook Graph `/me` endpoint.
    pub profile_url: String,
}

/// How a confidential client authenticates at the token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthentication {
    /// Send client credentials in the token request body (the default).
    RequestBody,
    /// Send client credentials using HTTP Basic authentication.
    Basic,
}

/// PKCE behavior for an authorization request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkceMode {
    /// Generate an S256 challenge; save the verifier for code exchange.
    S256,
    /// Do not send PKCE parameters. Intended for existing confidential-server flows.
    Disabled,
}

/// Facebook profile data requested during authorization and identity lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FacebookProfileMode {
    /// Request public profile and email; fetch ID, names, email and picture.
    /// Optional fields may be absent when unavailable or permission is not granted.
    #[default]
    Full,
    /// Request and return only the app-scoped ID, without requesting email permission.
    IdOnly,
}
