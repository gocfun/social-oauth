use super::*;
use crate::{PendingAuthorization, PkceMode};
use axum::{
    routing::{get, post},
    Form, Json, Router,
};
use std::collections::HashMap;

const CLIENT_ID: &str = "test-services-id";
const REDIRECT: &str = "https://gocfun.example/auth/oauth/apple/callback";
const NONCE: &str = "expected-nonce";

// Public test vectors signed with a disposable RSA key.
const KEYS: &str = r#"{"keys":[{"kty":"RSA","kid":"fixture","alg":"RS256","use":"sig","n":"3M0wSn7uIjgZHg_JLAm1oDr0qBOXs7ECAqJ7-9bIncJEhsvBFG3q3nd3SovAdvXiQ1NYTaPUR0gylKHHDQJai8XFT0i1zjkmrMjVIEMScJx5mgJxVLyntULnqKMG56Sh7E6aBOyrZrrbhWIPZH4yA86QXlHUSwGV7qCbwmhT71r43lZHLXPL-xbeZb54inPR-X7CPocd4OBPqj0JARfPZS5n9QtaqxXkNwx-22pAIabVJwsw97U2z9bFeyhcTqe-tc9LbtWixvA8r0HNsohS-4r5AehsxI-lqU_Xj82M1OZFerazlg-H-_PUeevuCmGpH_4egsnT9TLj4oOY3NOWDw","e":"AQAB"}]}"#;
const ID_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImZpeHR1cmUifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoidGVzdC1zZXJ2aWNlcy1pZCIsImV4cCI6NDEwMjQ0NDgwMCwic3ViIjoiYXBwbGUtc3ViamVjdCIsIm5vbmNlIjoiZXhwZWN0ZWQtbm9uY2UiLCJlbWFpbCI6InJlbGF5QGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOiJ0cnVlIn0.gxHTRx-2AvtP_KFt5T6zZHfEfNvTQPBiyuLJvMfG4QF7AqYzJLmFH1tcT4fLd-YlWU143BYHtF2GNVU2uuFrAYy9hhMTKTcqal-aGNk67qodaHxXgPWeau9E5gwSfqF04O0xXKEzLYjzGst4FLbU8HgOCijsNHYcLRAcqHNY0nPlxKQAE9rY2kVLn7epr8OnNxDychYOnN-rFLDi3XCZRWEF2teDXgTZMWn9xMTO04usZFPiDd1YRN5Wojll8efNUesCltOaqvWnFpYWwo35C8oYikPh8DwpsPxcM0Dc47xqDuoWUk7VLkPQlml9WCTY3DOrqKG0L5FAxiH5-KpGqQ";
const EXPIRED_ID_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImZpeHR1cmUifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoidGVzdC1zZXJ2aWNlcy1pZCIsImV4cCI6MTU3NzgzNjgwMCwic3ViIjoiYXBwbGUtc3ViamVjdCIsIm5vbmNlIjoiZXhwZWN0ZWQtbm9uY2UiLCJlbWFpbCI6InJlbGF5QGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOiJ0cnVlIn0.mhbExlzwUhv3qtc6BGngVusYNvs3j5aF-lrCQyFzBWuH0TE1AJdu5WHTgSLc47rI7B6Eui0R-44wt3utqOdmzfZSwjujvdAwkCoiScF-1_ruI4UdPwTPRwFXnCxgTLfpjeiYzIxSGtD76zjlDNTH-PuHdR-Dru0JIWqxnaetApCIuYgfGa2VYiEg3f2LIIX-XF0U2aLuhfu03yb_Aih4zyLcBWkukKvyyP9v3xVwCHNNk0Raa6RK1U00oRPxWzVlNV30bQ0tq7A98XSC5EIbYVN8LVolDQabUog63sDpQfqAmVI2SymNnguotx8SVwGkbXxPsLvKAehmZdYEt9cjOQ";
const WRONG_ISSUER_ID_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImZpeHR1cmUifQ.eyJpc3MiOiJodHRwczovL290aGVyLmV4YW1wbGUiLCJhdWQiOiJ0ZXN0LXNlcnZpY2VzLWlkIiwiZXhwIjo0MTAyNDQ0ODAwLCJzdWIiOiJhcHBsZS1zdWJqZWN0Iiwibm9uY2UiOiJleHBlY3RlZC1ub25jZSIsImVtYWlsIjoicmVsYXlAZXhhbXBsZS5jb20iLCJlbWFpbF92ZXJpZmllZCI6InRydWUifQ.AW6-_JfNyuyzynWSMAeIBEj2gGONXJG_c48LjQFTrrnmwAkaWEVxjxPb_j4-l7azEKbAFJIT_YoUycwcB4VsLnBXhFAqgNpIjAJujyyVLsiim2tz8FMXepkPZgmWKDkh2UVw0UG6UUvB7nkLIcgu-uk8l9JCke1c5zI0PuLkfD-jBc9gpVtXJd41HSv5M_e38Gt-Bzhnde5-ARdc253dOogLUpt21er0QvmNr0-ENuLdsscJetrCZjaUoCcKH0B46fGB0xwPn5OEXYEo5xzS8HvGijQotZShKlsTgHKT4we-zxYU2aBt8LjbmmsSyfmAC6TazJfLTwmhvPGDk-crTg";

#[test]
fn browser_authorization_uses_form_post_and_independent_nonce() {
    let client = OAuthClient::apple(CLIENT_ID, "test-secret", REDIRECT).unwrap();
    let authorization = client
        .authorize_with_state("test-state", PkceMode::Disabled)
        .unwrap();
    let params: HashMap<_, _> = authorization.url.query_pairs().collect();
    assert_eq!(params["client_id"], CLIENT_ID);
    assert_eq!(params["redirect_uri"], REDIRECT);
    assert_eq!(params["state"], "test-state");
    assert_eq!(params["response_mode"], "form_post");
    assert_eq!(params["response_type"], "code");
    assert_eq!(params["scope"], "openid");
    assert_eq!(
        Some(params["nonce"].as_ref()),
        authorization.pending.nonce()
    );
    assert_ne!(params["nonce"], params["state"]);
    assert_ne!(
        client.authorize().pending.nonce(),
        authorization.pending.nonce()
    );
    assert!(!params.contains_key("code_challenge"));
    assert!(client
        .authorize_with_state("test-state", PkceMode::S256)
        .is_err());
    assert!(OAuthClient::apple(CLIENT_ID, "test-secret", "https://localhost/callback").is_err());
}

#[test]
fn verifies_apple_signature_and_required_claims() {
    let keys = serde_json::from_str(KEYS).unwrap();
    let identity = verify_identity(ID_TOKEN, "fixture", &keys, CLIENT_ID, NONCE).unwrap();
    assert_eq!(identity.subject, "apple-subject");
    assert_eq!(identity.provider, Provider::Apple);
    assert_eq!(identity.verified_email(), Some("relay@example.com"));

    let (claims_and_header, _) = ID_TOKEN.rsplit_once('.').unwrap();
    let bad_signature = format!("{claims_and_header}.AQAB");
    for (token, kid, audience, nonce) in [
        (bad_signature.as_str(), "fixture", CLIENT_ID, NONCE),
        (EXPIRED_ID_TOKEN, "fixture", CLIENT_ID, NONCE),
        (WRONG_ISSUER_ID_TOKEN, "fixture", CLIENT_ID, NONCE),
        (ID_TOKEN, "missing", CLIENT_ID, NONCE),
        (ID_TOKEN, "fixture", "wrong-audience", NONCE),
        (ID_TOKEN, "fixture", CLIENT_ID, "wrong-nonce"),
    ] {
        assert_eq!(
            verify_identity(token, kid, &keys, audience, nonce),
            Err(Error::InvalidAppleIdentity)
        );
    }
}

#[tokio::test]
async fn apple_complete_exchanges_code_in_body_and_verifies_token_with_jwks() {
    let router = Router::new().route("/keys", get(|| async { KEYS })).route(
        "/token",
        post(
            |headers: axum::http::HeaderMap, Form(form): Form<HashMap<String, String>>| async move {
                assert!(!headers.contains_key("authorization"));
                assert_eq!(form["client_id"], CLIENT_ID);
                assert_eq!(form["client_secret"], "test-secret");
                assert_eq!(form["grant_type"], "authorization_code");
                assert_eq!(form["redirect_uri"], REDIRECT);
                assert_eq!(form["code"], "example-code");
                assert!(!form.contains_key("code_verifier"));
                Json(serde_json::json!({
                    "access_token": "provider-access-token",
                    "token_type": "Bearer",
                    "id_token": ID_TOKEN
                }))
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    let mut client = OAuthClient::apple(CLIENT_ID, "test-secret", REDIRECT).unwrap();
    client.oauth = client
        .oauth
        .set_token_uri(oauth2::TokenUrl::new(format!("{url}/token")).unwrap());
    client.profile_url = Url::parse(&format!("{url}/keys")).unwrap();
    let pending = PendingAuthorization::new(
        Provider::Apple,
        CLIENT_ID.into(),
        REDIRECT.into(),
        "test-state".into(),
        None,
        Some(NONCE.into()),
    );
    let identity = client
        .complete(pending, "example-code", "test-state")
        .await
        .unwrap();
    assert_eq!(identity.subject, "apple-subject");
    assert_eq!(
        client.identity_from_code("example-code", None).await,
        Err(Error::ApplePendingRequired)
    );
    server.abort();
}
