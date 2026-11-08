use social_oauth::{
    config::{ConfigError, SocialOAuthConfig},
    OAuthClient, Provider,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use url::Url;

pub(super) struct ExampleSettings {
    pub oauth: OAuthClient,
    pub callback_path: String,
    pub listen: SocketAddr,
    pub secure_cookie: bool,
}

impl ExampleSettings {
    pub(super) fn from_config(
        config: &SocialOAuthConfig,
        provider: Provider,
        listen: Option<SocketAddr>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let section = match provider {
            Provider::Google => config.google.as_ref(),
            Provider::Facebook => config.facebook.as_ref(),
        }
        .ok_or(ConfigError::ProviderMissing(provider))?;
        let oauth = config.client(provider)?;
        let redirect = Url::parse(&section.redirect_url)?;
        let callback_path = redirect.path().to_string();
        if callback_path == "/" || callback_path == "/login" {
            return Err("example callback path must differ from / and /login".into());
        }
        let secure_cookie = redirect.scheme() == "https";
        let host = redirect.host_str();
        let loopback_http =
            !secure_cookie && matches!(host, Some("localhost" | "127.0.0.1" | "[::1]"));
        let default_listen = if loopback_http {
            let ip = if host == Some("[::1]") {
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            } else {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            };
            SocketAddr::new(ip, redirect.port_or_known_default().unwrap_or(80))
        } else {
            SocketAddr::from((Ipv4Addr::LOCALHOST, 3000))
        };
        Ok(Self {
            oauth,
            callback_path,
            listen: listen.unwrap_or(default_listen),
            secure_cookie,
        })
    }
}
