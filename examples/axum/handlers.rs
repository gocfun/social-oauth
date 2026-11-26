use super::{App, Pending};
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Form, Json,
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

pub(super) async fn login(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let authorization = app.oauth.authorize();
    // Separate random browser cookie: do not use callback state alone as the session key.
    let browser = oauth2::CsrfToken::new_random().secret().clone();
    {
        let mut store = app.pending.lock().unwrap();
        store.retain(|_, entry| entry.created.elapsed() < Duration::from_secs(300));
        if let Some(previous) = browser_cookie(&headers) {
            store.remove(previous);
        }
        if store.len() >= 1000 {
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        }
        store.insert(
            browser.clone(),
            Pending {
                created: Instant::now(),
                authorization: authorization.pending,
            },
        );
    }
    let mut response = Redirect::to(authorization.url.as_str()).into_response();
    // HTTP on loopback only. Use Secure cookies and HTTPS in a deployed application.
    response
        .headers_mut()
        .insert(header::SET_COOKIE, cookie_header(&app, &browser, 300));
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[derive(serde::Deserialize)]
pub(super) struct Callback {
    pub(super) code: Option<String>,
    pub(super) state: Option<String>,
    pub(super) error: Option<String>,
}

pub(super) async fn callback(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<Callback>,
) -> Response {
    finish_callback(app, headers, query).await
}

pub(super) async fn apple_callback(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Form(form): Form<Callback>,
) -> Response {
    finish_callback(app, headers, form).await
}

async fn finish_callback(app: Arc<App>, headers: HeaderMap, query: Callback) -> Response {
    // Check Apple state and consume under one lock. A cross-site POST with the
    // browser cookie alone must neither consume pending state nor clear the cookie.
    let pending = {
        let mut store = app.pending.lock().unwrap();
        let browser = browser_cookie(&headers);
        if app.apple
            && !browser
                .and_then(|browser| store.get(browser))
                .is_some_and(|pending| {
                    query.state.as_deref() == Some(pending.authorization.state())
                })
        {
            return (StatusCode::BAD_REQUEST, "Invalid Apple OAuth state").into_response();
        }
        browser.and_then(|browser| store.remove(browser))
    };
    let mut response = match pending {
        Some(pending) if pending.created.elapsed() < Duration::from_secs(300) => {
            if query.error.is_some() {
                (StatusCode::BAD_REQUEST, "Provider authorization was denied").into_response()
            } else if let (Some(code), Some(state)) = (query.code, query.state) {
                match app
                    .oauth
                    .complete(pending.authorization, &code, &state)
                    .await
                {
                    // Demonstrate the identity only. Add your account/session policy here.
                    Ok(identity) => Json(identity).into_response(),
                    Err(_) => (StatusCode::BAD_REQUEST, "OAuth callback failed").into_response(),
                }
            } else {
                (StatusCode::BAD_REQUEST, "Missing code or state").into_response()
            }
        }
        _ => (
            StatusCode::BAD_REQUEST,
            "Missing, expired or consumed browser session",
        )
            .into_response(),
    };
    response
        .headers_mut()
        .insert(header::SET_COOKIE, cookie_header(&app, "", 0));
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

fn browser_cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|cookie| cookie.trim().strip_prefix("oauth_demo="))
}

fn cookie_header(app: &App, browser: &str, max_age: u64) -> HeaderValue {
    let secure = if app.secure_cookie { "; Secure" } else { "" };
    let same_site = if app.apple { "None" } else { "Lax" };
    HeaderValue::from_str(&format!(
        "oauth_demo={browser}; HttpOnly; SameSite={same_site}; Path=/; Max-Age={max_age}{secure}"
    ))
    .unwrap()
}
