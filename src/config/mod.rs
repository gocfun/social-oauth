//! Explicit `config_social.toml` loading behind the optional `config-toml` feature.
//!
//! No file or environment variable is read unless your application calls
//! [`crate::config::SocialOAuthConfig::from_file`]. Use the loader at startup, not per request.

use crate::{ClientAuthentication, Endpoints, FacebookProfileMode, OAuthClient, Provider};
use serde::Deserialize;
use std::{fmt, path::Path};

/// Optional Google/Facebook sections. Unknown sections (e.g. existing `discord`
/// config) are ignored; only supported providers can be used to build clients.
#[derive(Debug, Clone, Deserialize)]
pub struct SocialOAuthConfig {
    /// Google client configuration, if configured.
    pub google: Option<OAuthClientConfig>,
    /// Facebook client configuration, if configured.
    pub facebook: Option<OAuthClientConfig>,
}

/// Configuration for one confidential server-side OAuth client.
/// Debug output intentionally omits all values, including credentials and URLs.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthClientConfig {
    /// Provider application/client ID.
    pub client_id: String,
    /// Provider client secret. Keep the file private and out of version control.
    pub client_secret: String,
    /// Backend callback URI registered with the provider.
    pub redirect_url: String,
    /// Browser authorization endpoint, including the desired version if applicable.
    pub auth_url: String,
    /// Authorization code exchange endpoint.
    pub token_url: String,
    /// Optional profile endpoint. Defaults to Google's standard UserInfo endpoint
    /// or Facebook's unversioned `/me`; set explicitly to pin a Graph API version.
    pub profile_url: Option<String>,
    /// Token client authentication (`request_body` by default, or `basic`).
    #[serde(default = "default_client_authentication")]
    pub client_authentication: ClientAuthentication,
    /// Facebook data/permission mode (`full` by default, or `id_only`). Ignored for Google.
    #[serde(default)]
    pub facebook_profile_mode: FacebookProfileMode,
}

impl fmt::Debug for OAuthClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthClientConfig").finish_non_exhaustive()
    }
}

fn default_client_authentication() -> ClientAuthentication {
    ClientAuthentication::RequestBody
}

/// Configuration errors omit file contents and parser input to avoid exposing secrets.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The selected file could not be read as UTF-8.
    #[error("could not read OAuth configuration file")]
    ReadFile,
    /// Invalid TOML, missing required fields or invalid option values.
    #[error("invalid OAuth TOML configuration")]
    InvalidToml,
    /// The selected provider section was absent.
    #[error("OAuth provider is not configured: {0:?}")]
    ProviderMissing(Provider),
    /// Client construction rejected the configuration. Inner errors are redacted.
    #[error(transparent)]
    Client(#[from] crate::Error),
}

impl SocialOAuthConfig {
    /// Parses TOML already read by your application; performs no filesystem access.
    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        toml::from_str(input).map_err(|_| ConfigError::InvalidToml)
    }

    /// Reads ONLY the explicitly supplied path. No default filename, environment
    /// lookup or automatic file discovery is performed. Call once during startup.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|_| ConfigError::ReadFile)?;
        Self::from_toml(&contents)
    }

    /// Builds one selected provider client. Does not require the other provider.
    pub fn client(&self, provider: Provider) -> Result<OAuthClient, ConfigError> {
        let config = match provider {
            Provider::Google => self.google.as_ref(),
            Provider::Facebook => self.facebook.as_ref(),
        }
        .ok_or(ConfigError::ProviderMissing(provider))?;
        Ok(config.build(provider)?)
    }
}

impl OAuthClientConfig {
    /// Builds a client from an individual section, preserving the configured URLs.
    /// This performs no file access and does not change application state/session logic.
    pub fn build(&self, provider: Provider) -> Result<OAuthClient, crate::Error> {
        let default_profile = match provider {
            Provider::Google => "https://openidconnect.googleapis.com/v1/userinfo",
            Provider::Facebook => "https://graph.facebook.com/me",
        };
        Ok(OAuthClient::with_endpoints(
            provider,
            self.client_id.clone(),
            self.client_secret.clone(),
            self.redirect_url.clone(),
            Endpoints {
                authorization_url: self.auth_url.clone(),
                token_url: self.token_url.clone(),
                profile_url: self
                    .profile_url
                    .as_deref()
                    .unwrap_or(default_profile)
                    .to_string(),
            },
        )?
        .with_client_authentication(self.client_authentication)
        .with_facebook_profile_mode(self.facebook_profile_mode))
    }
}

#[cfg(test)]
mod tests;
