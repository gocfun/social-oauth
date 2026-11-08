use super::handlers::{callback, Callback};
use super::*;
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
};
use std::time::Duration;

fn app() -> Arc<App> {
    Arc::new(App {
        oauth: OAuthClient::google("client", "secret", "http://localhost:3000/oauth/callback")
            .unwrap(),
        secure_cookie: false,
        pending: Mutex::new(HashMap::new()),
    })
}

fn cookie(value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&format!("oauth_demo={value}")).unwrap(),
    );
    headers
}

#[tokio::test]
async fn callback_state_alone_cannot_recover_another_browsers_pending_authorization() {
    let app = app();
    let auth = app.oauth.authorize();
    let state = auth
        .url
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();
    app.pending.lock().unwrap().insert(
        "correct-browser".into(),
        Pending {
            created: Instant::now(),
            authorization: auth.pending,
        },
    );
    let response = callback(
        State(app.clone()),
        cookie("wrong-browser"),
        Query(Callback {
            code: Some("code".into()),
            state: Some(state),
            error: None,
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(app.pending.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn denial_consumes_pending_state_and_clears_browser_cookie() {
    let app = app();
    app.pending.lock().unwrap().insert(
        "browser".into(),
        Pending {
            created: Instant::now(),
            authorization: app.oauth.authorize().pending,
        },
    );
    let response = callback(
        State(app.clone()),
        cookie("browser"),
        Query(Callback {
            code: None,
            state: None,
            error: Some("access_denied".into()),
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(app.pending.lock().unwrap().is_empty());
    assert!(response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .contains("Max-Age=0"));
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
}

#[tokio::test]
async fn expired_pending_state_is_consumed_without_exchange() {
    let app = app();
    app.pending.lock().unwrap().insert(
        "browser".into(),
        Pending {
            created: Instant::now() - Duration::from_secs(301),
            authorization: app.oauth.authorize().pending,
        },
    );
    let response = callback(
        State(app.clone()),
        cookie("browser"),
        Query(Callback {
            code: Some("code".into()),
            state: Some("state".into()),
            error: None,
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(app.pending.lock().unwrap().is_empty());
}

#[test]
fn distributed_config_runs_either_provider_without_separate_environment_credentials() {
    let config =
        SocialOAuthConfig::from_toml(include_str!("../../config_social.example.toml")).unwrap();
    for provider in [Provider::Google, Provider::Facebook] {
        let settings = ExampleSettings::from_config(&config, provider, None).unwrap();
        assert_eq!(settings.callback_path, "/oauth/callback");
        assert_eq!(
            settings.listen,
            "127.0.0.1:3000".parse::<SocketAddr>().unwrap()
        );
        assert!(!settings.secure_cookie);
    }
}

#[test]
fn custom_callback_path_and_port_are_taken_from_the_selected_section() {
    let config = SocialOAuthConfig::from_toml(
        r#"
[facebook]
client_id = "app"
client_secret = "secret"
redirect_url = "http://localhost:8083/auth/oauth/facebook/callback"
auth_url = "https://www.facebook.com/dialog/oauth"
token_url = "https://graph.facebook.com/oauth/access_token"
facebook_profile_mode = "id_only"
client_authentication = "basic"
"#,
    )
    .unwrap();
    let settings = ExampleSettings::from_config(&config, Provider::Facebook, None).unwrap();
    assert_eq!(settings.callback_path, "/auth/oauth/facebook/callback");
    assert_eq!(
        settings.listen,
        "127.0.0.1:8083".parse::<SocketAddr>().unwrap()
    );
    assert!(!settings
        .oauth
        .authorize()
        .url
        .query_pairs()
        .any(|(key, _)| key == "scope"));
    assert!(ExampleSettings::from_config(&config, Provider::Google, None).is_err());
}

#[test]
fn https_callback_uses_secure_cookie_and_explicit_proxy_listen_address() {
    let config = SocialOAuthConfig::from_toml(
        r#"
[google]
client_id = "app"
client_secret = "secret"
redirect_url = "https://example.com/auth/google/callback"
auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
token_url = "https://oauth2.googleapis.com/token"
"#,
    )
    .unwrap();
    let listen = "127.0.0.1:9001".parse::<SocketAddr>().unwrap();
    let settings = ExampleSettings::from_config(&config, Provider::Google, Some(listen)).unwrap();
    assert_eq!(settings.listen, listen);
    assert!(settings.secure_cookie);
    assert_eq!(settings.callback_path, "/auth/google/callback");
}

#[tokio::test]
async fn router_mounts_the_callback_configured_in_toml() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let config = SocialOAuthConfig::from_toml(&format!(
        r#"
[google]
client_id = "app"
client_secret = "secret"
redirect_url = "http://localhost:{}/auth/oauth/google/callback"
auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
token_url = "https://oauth2.googleapis.com/token"
"#,
        address.port()
    ))
    .unwrap();
    let settings = ExampleSettings::from_config(&config, Provider::Google, None).unwrap();
    let path = settings.callback_path.clone();
    let app = Arc::new(App::new(settings));
    let task = tokio::spawn(async move {
        axum::serve(listener, router(app, &path)).await.unwrap();
    });
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let configured = http
        .get(format!("http://{address}/auth/oauth/google/callback"))
        .send()
        .await
        .unwrap();
    let old_default = http
        .get(format!("http://{address}/oauth/callback"))
        .send()
        .await
        .unwrap();
    task.abort();
    assert_eq!(configured.status().as_u16(), 400);
    assert_eq!(old_default.status().as_u16(), 404);
}
