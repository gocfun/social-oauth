use super::exchange::MAX_PROFILE_BYTES;
use super::*;
use crate::{identity::parse_identity, PendingAuthorization, PkceMode};
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use std::sync::{Arc, Mutex};

fn google() -> OAuthClient {
    OAuthClient::google(
        "client",
        "secret-do-not-log",
        "http://localhost:3000/oauth/callback",
    )
    .unwrap()
}

#[test]
fn authorization_has_fresh_state_and_google_pkce() {
    let client = google();
    let first = client.authorize();
    let second = client.authorize();
    let params: std::collections::HashMap<_, _> = first.url.query_pairs().into_owned().collect();
    assert_eq!(params["response_type"], "code");
    assert_eq!(params["scope"], "openid email profile");
    assert_eq!(params["code_challenge_method"], "S256");
    assert_eq!(params["state"], first.pending.state());
    assert_ne!(first.pending.state(), second.pending.state());
    assert_ne!(
        first.pending.pkce_verifier(),
        second.pending.pkce_verifier()
    );
    assert!(!first.url.as_str().contains("secret-do-not-log"));
    assert!(!first
        .url
        .as_str()
        .contains(first.pending.pkce_verifier().unwrap()));
}

#[test]
fn facebook_defaults_to_full_profile_with_explicit_version_and_no_pkce() {
    let client =
        OAuthClient::facebook("app", "secret", "https://example.com/callback", "v25.0").unwrap();
    let auth = client.authorize();
    assert_eq!(auth.url.path(), "/v25.0/dialog/oauth");
    let params: std::collections::HashMap<_, _> = auth.url.query_pairs().into_owned().collect();
    assert_eq!(params["scope"], "public_profile email");
    assert!(!params.contains_key("code_challenge"));
    assert!(auth.pending.pkce_verifier().is_none());
    assert_eq!(client.profile_url.path(), "/v25.0/me");
}

#[test]
fn rejects_bad_configuration_and_does_not_leak_input() {
    for redirect in [
        "http://example.com/cb",
        "file:///tmp/cb",
        "https://user:pass@example.com/cb",
        "https://example.com/cb#fragment",
        "broken-secret-url",
    ] {
        let error = OAuthClient::google("client", "secret", redirect).unwrap_err();
        assert!(matches!(error, Error::Configuration(_)));
        assert!(!format!("{error:?}").contains(redirect));
    }
    for version in ["", "25.0", "v25", "v.0", "v25.0/other", "v25.0?secret=x"] {
        assert!(
            OAuthClient::facebook("client", "secret", "https://example.com/cb", version).is_err()
        );
    }
    assert!(OAuthClient::google(" ", "secret", "https://example.com/cb").is_err());
    assert!(OAuthClient::google("id", "", "https://example.com/cb").is_err());
    assert!(OAuthClient::google("id", "secret", "http://[::1]:3000/cb").is_ok());
}

#[test]
fn debug_redacts_secrets_and_pending_round_trips() {
    let client = google();
    let auth = client.authorize();
    let output = format!("{client:?} {auth:?} {:?}", auth.pending);
    for secret in [
        "secret-do-not-log",
        auth.pending.state(),
        auth.pending.pkce_verifier().unwrap(),
    ] {
        assert!(!output.contains(secret));
    }
    let restored: PendingAuthorization =
        serde_json::from_str(&serde_json::to_string(&auth.pending).unwrap()).unwrap();
    assert_eq!(restored.state(), auth.pending.state());
    assert_eq!(restored.pkce_verifier(), auth.pending.pkce_verifier());
}

#[test]
fn identity_preserves_email_verification_without_application_policy() {
    for (claim, expected) in [
        ("true", Some("a@example.com")),
        ("false", None),
        ("null", None),
    ] {
        let body =
            format!(r#"{{"sub":"google-id","email":"a@example.com","email_verified":{claim}}}"#);
        let identity =
            parse_identity(Provider::Google, body.as_bytes(), FacebookProfileMode::Full).unwrap();
        assert_eq!(identity.subject, "google-id");
        assert_eq!(identity.email.as_deref(), Some("a@example.com"));
        assert_eq!(identity.verified_email(), expected);
    }
    let facebook = parse_identity(
        Provider::Facebook,
        br#"{"id":"app-scoped"}"#,
        FacebookProfileMode::Full,
    )
    .unwrap();
    assert_eq!(facebook.subject, "app-scoped");
    assert!(facebook.email.is_none());
    for body in [
        br#"{"id":""}"#.as_slice(),
        br#"{"email":"x"}"#,
        br#"{"id":123}"#,
        b"not-json",
    ] {
        assert_eq!(
            parse_identity(Provider::Facebook, body, FacebookProfileMode::Full),
            Err(Error::InvalidProfile)
        );
    }
}

#[tokio::test]
async fn rejects_mismatched_state_client_and_empty_code_before_network() {
    let client = google();
    assert_eq!(
        client
            .complete(client.authorize().pending, "code", "wrong")
            .await,
        Err(Error::StateMismatch)
    );
    let auth = client.authorize();
    let state = auth.pending.state().to_owned();
    assert_eq!(
        client.complete(auth.pending, "", &state).await,
        Err(Error::MissingCode)
    );
    for other in [
        OAuthClient::google("other", "secret", "http://localhost:3000/oauth/callback").unwrap(),
        OAuthClient::google("client", "secret", "https://example.com/other").unwrap(),
        OAuthClient::facebook(
            "client",
            "secret",
            "http://localhost:3000/oauth/callback",
            "v25.0",
        )
        .unwrap(),
    ] {
        let auth = client.authorize();
        let state = auth.pending.state().to_owned();
        assert_eq!(
            other.complete(auth.pending, "code", &state).await,
            Err(Error::ClientMismatch)
        );
    }
}

#[derive(Clone)]
struct Mock {
    token_status: StatusCode,
    profile_status: StatusCode,
    profile_body: String,
    forms: Arc<Mutex<Vec<String>>>,
    token_auth: Arc<Mutex<Vec<Option<String>>>>,
    profiles: Arc<Mutex<Vec<(String, String)>>>,
}

impl Mock {
    fn new(body: &str) -> Self {
        Self {
            token_status: StatusCode::OK,
            profile_status: StatusCode::OK,
            profile_body: body.into(),
            forms: Arc::default(),
            token_auth: Arc::default(),
            profiles: Arc::default(),
        }
    }
}

struct Server(tokio::task::JoinHandle<()>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn mock_client(provider: Provider, mock: Mock) -> (OAuthClient, Server) {
    async fn token(
        State(mock): State<Mock>,
        headers: axum::http::HeaderMap,
        body: String,
    ) -> impl IntoResponse {
        mock.forms.lock().unwrap().push(body);
        mock.token_auth.lock().unwrap().push(
            headers
                .get("authorization")
                .map(|value| value.to_str().unwrap().into()),
        );
        (
            mock.token_status,
            Json(serde_json::json!({"access_token":"provider-secret-token","token_type":"Bearer"})),
        )
    }
    async fn profile(
        State(mock): State<Mock>,
        headers: axum::http::HeaderMap,
        uri: axum::http::Uri,
    ) -> impl IntoResponse {
        mock.profiles.lock().unwrap().push((
            headers["authorization"].to_str().unwrap().into(),
            uri.query().unwrap_or_default().into(),
        ));
        (
            mock.profile_status,
            [(axum::http::header::LOCATION, "/redirect-target")],
            mock.profile_body,
        )
    }
    let router = Router::new()
        .route("/token", post(token))
        .route("/me", get(profile))
        .with_state(mock);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let client = OAuthClient::with_endpoints(
        provider,
        "client",
        "client-secret",
        "http://localhost:3000/oauth/callback",
        Endpoints {
            authorization_url: format!("{base}/authorize"),
            token_url: format!("{base}/token"),
            profile_url: format!("{base}/me"),
        },
    )
    .unwrap();
    (client, Server(task))
}

#[test]
fn application_supplied_state_preserves_prefixes_without_requiring_pending_storage() {
    let client = google();
    for state in ["login-random", "register.random", "bind.random"] {
        let auth = client
            .authorize_with_state(state, PkceMode::Disabled)
            .unwrap();
        assert_eq!(auth.pending.state(), state);
        assert_eq!(auth.pending.pkce_verifier(), None);
        assert!(!auth
            .url
            .query_pairs()
            .any(|(key, _)| key == "code_challenge"));
        let params: std::collections::HashMap<_, _> = auth.url.query_pairs().into_owned().collect();
        assert_eq!(params["state"], state);
        assert_eq!(params["scope"], "openid email profile");
    }
    assert!(matches!(
        client.authorize_with_state(" ", PkceMode::Disabled),
        Err(Error::InvalidState)
    ));
}

#[tokio::test]
async fn external_state_flow_can_use_basic_auth_without_pkce_or_pending_format() {
    let mock = Mock::new(
        r#"{"sub":"existing-google-sub","email_verified":false,"email":"user@example.com"}"#,
    );
    let (client, _server) = mock_client(Provider::Google, mock.clone()).await;
    let client = client.with_client_authentication(ClientAuthentication::Basic);
    let authorization = client
        .authorize_with_state("bind.server-generated-random", PkceMode::Disabled)
        .unwrap();
    assert_eq!(
        authorization.pending.state(),
        "bind.server-generated-random"
    );
    // The application has already validated/consumed its existing state record here.
    let identity = client
        .identity_from_code("legacy-code", None)
        .await
        .unwrap();
    assert_eq!(identity.subject, "existing-google-sub");
    assert_eq!(identity.verified_email(), None);
    let forms = mock.forms.lock().unwrap();
    let fields: std::collections::HashMap<_, _> = url::form_urlencoded::parse(forms[0].as_bytes())
        .into_owned()
        .collect();
    assert_eq!(fields["code"], "legacy-code");
    assert!(!fields.contains_key("code_verifier"));
    assert!(!fields.contains_key("client_secret"));
    assert!(mock.token_auth.lock().unwrap()[0]
        .as_ref()
        .unwrap()
        .starts_with("Basic "));
}

#[tokio::test]
async fn separate_exchange_and_fetch_uses_saved_pkce_and_rejects_other_clients() {
    let mock = Mock::new(r#"{"sub":"google-id"}"#);
    let (client, _server) = mock_client(Provider::Google, mock.clone()).await;
    let authorization = client
        .authorize_with_state("register.server-random", PkceMode::S256)
        .unwrap();
    let verifier = authorization.pending.pkce_verifier().unwrap();
    let token = client.exchange_code("code", Some(verifier)).await.unwrap();
    assert!(!format!("{token:?}").contains("provider-secret-token"));
    let other = OAuthClient::google(
        "different-client",
        "secret",
        "http://localhost:3000/oauth/callback",
    )
    .unwrap();
    assert_eq!(
        other.fetch_identity(&token).await,
        Err(Error::ClientMismatch)
    );
    assert!(mock.profiles.lock().unwrap().is_empty());
    assert_eq!(
        client.fetch_identity(&token).await.unwrap().subject,
        "google-id"
    );
    let forms = mock.forms.lock().unwrap();
    let fields: std::collections::HashMap<_, _> = url::form_urlencoded::parse(forms[0].as_bytes())
        .into_owned()
        .collect();
    assert_eq!(fields["code_verifier"], verifier);
}

#[tokio::test]
async fn google_exchange_sends_pkce_and_fetches_identity_with_bearer_token() {
    let mock = Mock::new(
        r#"{"sub":"google-id","email":"a@example.com","email_verified":true,"name":"Alice","picture":"https://example.com/avatar"}"#,
    );
    let (client, _server) = mock_client(Provider::Google, mock.clone()).await;
    let auth = client.authorize();
    let state = auth.pending.state().to_owned();
    let verifier = auth.pending.pkce_verifier().unwrap().to_owned();
    let identity = client
        .complete(auth.pending, "test-code", &state)
        .await
        .unwrap();
    assert_eq!(identity.verified_email(), Some("a@example.com"));
    assert_eq!(identity.name.as_deref(), Some("Alice"));
    let forms = mock.forms.lock().unwrap();
    let fields: std::collections::HashMap<_, _> = url::form_urlencoded::parse(forms[0].as_bytes())
        .into_owned()
        .collect();
    assert_eq!(fields["code"], "test-code");
    assert_eq!(fields["client_secret"], "client-secret");
    assert_eq!(fields["code_verifier"], verifier);
    assert_eq!(
        fields["redirect_uri"],
        "http://localhost:3000/oauth/callback"
    );
    assert_eq!(
        mock.profiles.lock().unwrap()[0].0,
        "Bearer provider-secret-token"
    );
}

#[tokio::test]
async fn facebook_exchange_fetches_only_id_without_email_or_pkce() {
    let mock = Mock::new(r#"{"id":"facebook-id"}"#);
    let (client, _server) = mock_client(Provider::Facebook, mock.clone()).await;
    let client = client.with_facebook_profile_mode(FacebookProfileMode::IdOnly);
    let auth = client.authorize();
    assert!(!auth.url.query_pairs().any(|(key, _)| key == "scope"));
    let state = auth.pending.state().to_owned();
    let identity = client.complete(auth.pending, "code", &state).await.unwrap();
    assert_eq!(identity.subject, "facebook-id");
    assert_eq!(mock.profiles.lock().unwrap()[0].1, "fields=id");
    assert!(!mock.forms.lock().unwrap()[0].contains("code_verifier"));
}

#[tokio::test]
async fn facebook_full_profile_requests_permissions_and_maps_names_email_and_nested_picture() {
    let mock = Mock::new(
        r#"{
        "id":"facebook-id",
        "name":"Alice Marie Doe",
        "first_name":"Alice",
        "middle_name":"Marie",
        "last_name":"Doe",
        "email":"alice@example.com",
        "verified":true,
        "picture":{"data":{"url":"https://example.com/avatar.jpg","is_silhouette":false,"width":50,"height":50}}
    }"#,
    );
    let (client, _server) = mock_client(Provider::Facebook, mock.clone()).await;
    // Custom endpoint clients and application-managed state also default to Full.
    let auth = client
        .authorize_with_state("register.random", PkceMode::Disabled)
        .unwrap();
    let params: std::collections::HashMap<_, _> = auth.url.query_pairs().into_owned().collect();
    assert_eq!(params["scope"], "public_profile email");
    let identity = client.identity_from_code("code", None).await.unwrap();
    assert_eq!(identity.subject, "facebook-id");
    assert_eq!(identity.name.as_deref(), Some("Alice Marie Doe"));
    assert_eq!(identity.first_name.as_deref(), Some("Alice"));
    assert_eq!(identity.middle_name.as_deref(), Some("Marie"));
    assert_eq!(identity.last_name.as_deref(), Some("Doe"));
    assert_eq!(identity.email.as_deref(), Some("alice@example.com"));
    assert_eq!(
        identity.avatar_url.as_deref(),
        Some("https://example.com/avatar.jpg")
    );
    // A profile's verified badge is not an email-verification assertion.
    assert_eq!(identity.email_verified, None);
    assert_eq!(identity.verified_email(), None);
    let profiles = mock.profiles.lock().unwrap();
    let query: std::collections::HashMap<_, _> =
        url::form_urlencoded::parse(profiles[0].1.as_bytes())
            .into_owned()
            .collect();
    assert_eq!(
        query["fields"],
        "id,name,first_name,middle_name,last_name,email,picture"
    );
    assert_eq!(profiles[0].0, "Bearer provider-secret-token");
}

#[tokio::test]
async fn facebook_id_only_does_not_return_unrequested_extra_profile_data() {
    let mock = Mock::new(
        r#"{"id":"facebook-id","name":123,"email":{"unexpected":"object"},"picture":"unexpected"}"#,
    );
    let (client, _server) = mock_client(Provider::Facebook, mock.clone()).await;
    let client = client.with_facebook_profile_mode(FacebookProfileMode::IdOnly);
    let identity = client.identity_from_code("code", None).await.unwrap();
    assert_eq!(mock.profiles.lock().unwrap()[0].1, "fields=id");
    assert_eq!(identity.subject, "facebook-id");
    assert!(identity.name.is_none());
    assert!(identity.first_name.is_none());
    assert!(identity.middle_name.is_none());
    assert!(identity.last_name.is_none());
    assert!(identity.email.is_none());
    assert!(identity.avatar_url.is_none());
}

#[test]
fn facebook_full_profile_tolerates_missing_or_null_optional_fields() {
    for body in [
        r#"{"id":"id"}"#,
        r#"{"id":"id","email":null,"name":null,"first_name":null,"picture":null}"#,
        r#"{"id":"id","picture":{"data":null}}"#,
        r#"{"id":"id","picture":{"data":{}}}"#,
    ] {
        let identity = parse_identity(
            Provider::Facebook,
            body.as_bytes(),
            FacebookProfileMode::Full,
        )
        .unwrap();
        assert_eq!(identity.subject, "id");
        assert!(identity.email.is_none());
        assert!(identity.avatar_url.is_none());
        assert_eq!(identity.verified_email(), None);
    }
    assert_eq!(
        parse_identity(
            Provider::Facebook,
            br#"{"id":"id","picture":"invalid"}"#,
            FacebookProfileMode::Full
        ),
        Err(Error::InvalidProfile)
    );
}

#[test]
fn google_names_are_normalized_and_facebook_mode_does_not_change_google() {
    let client = google().with_facebook_profile_mode(FacebookProfileMode::IdOnly);
    let auth = client.authorize();
    let params: std::collections::HashMap<_, _> = auth.url.query_pairs().into_owned().collect();
    assert_eq!(params["scope"], "openid email profile");
    assert_eq!(params["code_challenge_method"], "S256");
    let identity = parse_identity(
        Provider::Google,
        br#"{"sub":"id","given_name":"Alice","family_name":"Doe"}"#,
        FacebookProfileMode::IdOnly,
    )
    .unwrap();
    assert_eq!(identity.first_name.as_deref(), Some("Alice"));
    assert_eq!(identity.last_name.as_deref(), Some("Doe"));
    assert!(identity.middle_name.is_none());
}

#[tokio::test]
async fn token_failure_does_not_fetch_profile_or_expose_provider_body() {
    let mut mock = Mock::new("unused");
    mock.token_status = StatusCode::BAD_REQUEST;
    let (client, _server) = mock_client(Provider::Google, mock.clone()).await;
    let auth = client.authorize();
    let state = auth.pending.state().to_owned();
    let error = client
        .complete(auth.pending, "code", &state)
        .await
        .unwrap_err();
    assert_eq!(error, Error::TokenExchange);
    assert!(!format!("{error:?} {error}").contains("provider-secret-token"));
    assert!(mock.profiles.lock().unwrap().is_empty());
}

#[tokio::test]
async fn rejects_profile_redirects_invalid_json_and_oversized_bodies() {
    for (status, body, expected) in [
        (
            StatusCode::FOUND,
            "redirect".into(),
            Error::ProfileStatus(302),
        ),
        (
            StatusCode::UNAUTHORIZED,
            "provider-secret".into(),
            Error::ProfileStatus(401),
        ),
        (StatusCode::OK, "not-json".into(), Error::InvalidProfile),
        (
            StatusCode::OK,
            "x".repeat(MAX_PROFILE_BYTES + 1),
            Error::InvalidProfile,
        ),
    ] {
        let mut mock = Mock::new(&body);
        mock.profile_status = status;
        let (client, _server) = mock_client(Provider::Google, mock).await;
        let auth = client.authorize();
        let state = auth.pending.state().to_owned();
        assert_eq!(
            client.complete(auth.pending, "code", &state).await,
            Err(expected)
        );
    }
}
