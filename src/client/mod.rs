mod authorization;
mod exchange;

pub use exchange::ProviderToken;

use crate::{ClientAuthentication, Endpoints, Error, FacebookProfileMode, Provider};
use oauth2::{
    basic::BasicClient, AuthType, AuthUrl, ClientId, ClientSecret, EndpointNotSet, EndpointSet,
    RedirectUrl, TokenUrl,
};
use std::{fmt, time::Duration};
use url::Url;

type ConfiguredClient =
    BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

/// Confidential server-side OAuth client. Debug output does not expose credentials.
///
/// The built-in HTTP client uses Rustls, a 15-second timeout and disables redirects.
/// Construct one client per provider/app and reuse it across requests.
#[derive(Clone)]
pub struct OAuthClient {
    provider: Provider,
    facebook_profile_mode: FacebookProfileMode,
    client_id: String,
    redirect_uri: String,
    oauth: ConfiguredClient,
    http: reqwest::Client,
    profile_url: Url,
}

impl fmt::Debug for OAuthClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthClient")
            .field("provider", &self.provider)
            .field("facebook_profile_mode", &self.facebook_profile_mode)
            .finish_non_exhaustive()
    }
}

impl OAuthClient {
    /// Builds a client using endpoints from trusted application configuration.
    /// No config file format, environment variables, Graph version, or storage
    /// implementation is imposed. Redirect URI validation matches the standard
    /// constructors. Provider profile mapping/scopes remain Google/Facebook-specific.
    pub fn with_endpoints(
        provider: Provider,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
        endpoints: Endpoints,
    ) -> Result<Self, Error> {
        Self::new(
            provider,
            client_id.into(),
            client_secret.into(),
            redirect_uri.into(),
            &endpoints.authorization_url,
            &endpoints.token_url,
            &endpoints.profile_url,
        )
    }

    /// Selects token endpoint client authentication without exposing oauth2 types.
    pub fn with_client_authentication(mut self, authentication: ClientAuthentication) -> Self {
        self.oauth = self.oauth.set_auth_type(match authentication {
            ClientAuthentication::RequestBody => AuthType::RequestBody,
            ClientAuthentication::Basic => AuthType::BasicAuth,
        });
        self
    }

    /// Selects Facebook profile data and permissions. Defaults to Full for both
    /// the standard constructor and custom endpoints. Has no effect on Google.
    /// Configure before authorization so requested permissions match the lookup.
    pub fn with_facebook_profile_mode(mut self, mode: FacebookProfileMode) -> Self {
        self.facebook_profile_mode = mode;
        self
    }

    /// Builds a confidential Google client using Google's standard endpoints.
    /// Requests `openid email profile` with an S256 PKCE challenge.
    pub fn google(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<Self, Error> {
        Self::new(
            Provider::Google,
            client_id.into(),
            client_secret.into(),
            redirect_uri.into(),
            "https://accounts.google.com/o/oauth2/v2/auth",
            "https://oauth2.googleapis.com/token",
            "https://openidconnect.googleapis.com/v1/userinfo",
        )
    }

    /// Builds a confidential Facebook client for an explicit Graph API version
    /// such as `v25.0`. Select a supported version in your Meta app configuration.
    /// Defaults to Full profile (`public_profile email`), without PKCE. Use
    /// [`Self::with_facebook_profile_mode`] with IdOnly to request only the ID.
    pub fn facebook(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
        graph_version: &str,
    ) -> Result<Self, Error> {
        let valid = graph_version
            .strip_prefix('v')
            .and_then(|version| version.split_once('.'))
            .is_some_and(|(major, minor)| {
                !major.is_empty()
                    && !minor.is_empty()
                    && major.bytes().all(|c| c.is_ascii_digit())
                    && minor.bytes().all(|c| c.is_ascii_digit())
            });
        if !valid {
            return Err(Error::Configuration("expected a Graph version like v25.0"));
        }
        Self::new(
            Provider::Facebook,
            client_id.into(),
            client_secret.into(),
            redirect_uri.into(),
            &format!("https://www.facebook.com/{graph_version}/dialog/oauth"),
            &format!("https://graph.facebook.com/{graph_version}/oauth/access_token"),
            &format!("https://graph.facebook.com/{graph_version}/me"),
        )
    }

    fn new(
        provider: Provider,
        client_id: String,
        client_secret: String,
        redirect_uri: String,
        auth_url: &str,
        token_url: &str,
        profile_url: &str,
    ) -> Result<Self, Error> {
        if client_id.trim().is_empty() || client_secret.trim().is_empty() {
            return Err(Error::Configuration(
                "client ID and secret must be non-empty",
            ));
        }
        let redirect =
            Url::parse(&redirect_uri).map_err(|_| Error::Configuration("invalid redirect URI"))?;
        let loopback = matches!(
            redirect.host_str(),
            Some("localhost" | "127.0.0.1" | "[::1]")
        );
        if !(redirect.scheme() == "https" || (redirect.scheme() == "http" && loopback))
            || redirect.host_str().is_none()
            || !redirect.username().is_empty()
            || redirect.password().is_some()
            || redirect.fragment().is_some()
        {
            return Err(Error::Configuration(
                "redirect URI must be HTTPS (HTTP only for loopback), without credentials or fragment",
            ));
        }
        let oauth = BasicClient::new(ClientId::new(client_id.clone()))
            .set_client_secret(ClientSecret::new(client_secret))
            .set_auth_uri(
                AuthUrl::new(auth_url.into())
                    .map_err(|_| Error::Configuration("invalid authorization URL"))?,
            )
            .set_token_uri(
                TokenUrl::new(token_url.into())
                    .map_err(|_| Error::Configuration("invalid token URL"))?,
            )
            .set_redirect_uri(
                RedirectUrl::new(redirect_uri.clone())
                    .map_err(|_| Error::Configuration("invalid redirect URI"))?,
            )
            .set_auth_type(AuthType::RequestBody);
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|_| Error::HttpClient)?;
        Ok(Self {
            provider,
            facebook_profile_mode: FacebookProfileMode::default(),
            client_id,
            redirect_uri,
            oauth,
            http,
            profile_url: Url::parse(profile_url)
                .map_err(|_| Error::Configuration("invalid profile URL"))?,
        })
    }

    #[cfg(all(test, feature = "config-toml"))]
    pub(crate) fn profile_url(&self) -> &Url {
        &self.profile_url
    }

    #[cfg(all(test, feature = "config-toml"))]
    pub(crate) fn facebook_profile_mode(&self) -> FacebookProfileMode {
        self.facebook_profile_mode
    }
}

#[cfg(test)]
mod tests;
