use super::*;
use crate::PkceMode;

const GOOGLE: &str = r#"
[google]
client_id = "google-client"
client_secret = "private-secret-do-not-log"
redirect_url = "http://localhost:3000/google/callback"
auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
token_url = "https://oauth2.googleapis.com/token"
"#;
const FACEBOOK: &str = r#"
[facebook]
client_id = "facebook-client"
client_secret = "private-facebook-secret"
redirect_url = "http://localhost:3000/facebook/callback"
auth_url = "https://www.facebook.com/v25.0/dialog/oauth"
token_url = "https://graph.facebook.com/v25.0/oauth/access_token"
"#;

#[test]
fn legacy_sections_are_accepted_without_requiring_discord_or_both_providers() {
    let config = SocialOAuthConfig::from_toml(GOOGLE).unwrap();
    assert!(config.facebook.is_none());
    assert!(matches!(
        config.client(Provider::Facebook),
        Err(ConfigError::ProviderMissing(Provider::Facebook))
    ));
    let client = config.client(Provider::Google).unwrap();
    let auth = client
        .authorize_with_state("register.random", PkceMode::Disabled)
        .unwrap();
    let params: std::collections::HashMap<_, _> = auth.url.query_pairs().into_owned().collect();
    assert_eq!(params["client_id"], "google-client");
    assert_eq!(params["state"], "register.random");
    assert_eq!(
        params["redirect_uri"],
        "http://localhost:3000/google/callback"
    );
    assert_eq!(params["scope"], "openid email profile");
    assert_eq!(
        client.profile_url().as_str(),
        "https://openidconnect.googleapis.com/v1/userinfo"
    );
    let with_discord = format!("{GOOGLE}\n[discord]\nclient_secret = 'ignored-legacy-value'\n");
    assert!(SocialOAuthConfig::from_toml(&with_discord).is_ok());
}

#[test]
fn facebook_defaults_full_but_config_can_select_id_only_and_custom_profile_url() {
    let full = SocialOAuthConfig::from_toml(FACEBOOK).unwrap();
    let client = full.client(Provider::Facebook).unwrap();
    let auth = client.authorize();
    assert!(auth
        .url
        .query_pairs()
        .any(|(k, v)| k == "scope" && v == "public_profile email"));
    let input = format!("{FACEBOOK}\nfacebook_profile_mode = 'id_only'\nclient_authentication = 'basic'\nprofile_url = 'https://graph.facebook.com/v25.0/me'\n");
    let config = SocialOAuthConfig::from_toml(&input).unwrap();
    let section = config.facebook.as_ref().unwrap();
    assert_eq!(section.client_authentication, ClientAuthentication::Basic);
    let client = config.client(Provider::Facebook).unwrap();
    assert_eq!(client.facebook_profile_mode(), FacebookProfileMode::IdOnly);
    assert_eq!(
        client.profile_url().as_str(),
        "https://graph.facebook.com/v25.0/me"
    );
    assert!(!client
        .authorize()
        .url
        .query_pairs()
        .any(|(key, _)| key == "scope"));
}

#[test]
fn malformed_configuration_and_debug_do_not_expose_secrets() {
    let config = SocialOAuthConfig::from_toml(GOOGLE).unwrap();
    assert!(!format!("{config:?}").contains("private-secret-do-not-log"));
    for invalid in [
        "[google]\nclient_secret = 'private-secret-do-not-log'",
        "[google\nclient_secret = 'private-secret-do-not-log'",
    ] {
        let error = SocialOAuthConfig::from_toml(invalid).unwrap_err();
        assert!(matches!(error, ConfigError::InvalidToml));
        assert!(!format!("{error:?} {error}").contains("private-secret-do-not-log"));
    }
    let invalid_mode = format!("{FACEBOOK}\nfacebook_profile_mode = 'typo-with-secret'\n");
    assert!(matches!(
        SocialOAuthConfig::from_toml(&invalid_mode),
        Err(ConfigError::InvalidToml)
    ));
    let typo = format!("{FACEBOOK}\nfacebook_profile_mdoe = 'id_only'\n");
    assert!(matches!(
        SocialOAuthConfig::from_toml(&typo),
        Err(ConfigError::InvalidToml)
    ));
}

#[test]
fn reads_only_requested_file_and_returns_redacted_errors() {
    let path = std::env::temp_dir().join(format!(
        "social-oauth-config-{}.toml",
        oauth2::CsrfToken::new_random().secret()
    ));
    std::fs::write(&path, GOOGLE).unwrap();
    let result = SocialOAuthConfig::from_file(&path);
    std::fs::remove_file(&path).unwrap();
    assert!(result.unwrap().google.is_some());
    assert!(matches!(
        SocialOAuthConfig::from_file(&path),
        Err(ConfigError::ReadFile)
    ));
}

#[test]
fn distributed_template_parses_with_both_providers() {
    let config =
        SocialOAuthConfig::from_toml(include_str!("../../config_social.example.toml")).unwrap();
    assert!(config.google.is_some());
    assert_eq!(
        config.facebook.unwrap().facebook_profile_mode,
        FacebookProfileMode::Full
    );
}
