//! Local demo: explicit TOML config, one provider, browser-bound state, no database.
mod handlers;
mod settings;

use axum::{response::Html, routing::get, Router};
use handlers::{callback, login};
use settings::ExampleSettings;
use social_oauth::{config::SocialOAuthConfig, OAuthClient, PendingAuthorization, Provider};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Instant,
};

struct Pending {
    created: Instant,
    authorization: PendingAuthorization,
}

struct App {
    oauth: OAuthClient,
    secure_cookie: bool,
    pending: Mutex<HashMap<String, Pending>>,
}

impl App {
    fn new(settings: ExampleSettings) -> Self {
        Self {
            oauth: settings.oauth,
            secure_cookie: settings.secure_cookie,
            pending: Mutex::new(HashMap::new()),
        }
    }
}

const USAGE: &str = "cargo run --example axum --features config-toml -- <config-path> <google|facebook> [listen-address]";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.as_slice() == ["--help"] || args.as_slice() == ["-h"] {
        println!("{USAGE}");
        return Ok(());
    }
    if !(2..=3).contains(&args.len()) {
        return Err(USAGE.into());
    }
    let provider = match args[1].as_str() {
        "google" => Provider::Google,
        "facebook" => Provider::Facebook,
        _ => return Err("provider must be google or facebook".into()),
    };
    let listen = args
        .get(2)
        .map(|value| value.parse::<SocketAddr>())
        .transpose()?;
    // File loading is explicit and occurs once, at application startup.
    let config = SocialOAuthConfig::from_file(&args[0])?;
    let settings = ExampleSettings::from_config(&config, provider, listen)?;
    let callback_path = settings.callback_path.clone();
    let listener = tokio::net::TcpListener::bind(settings.listen).await?;
    if settings.secure_cookie {
        println!(
            "Listening on {} behind your HTTPS callback origin; open that public origin to start",
            listener.local_addr()?
        );
    } else {
        println!(
            "Listening on {}; open the same loopback hostname used in redirect_url to start",
            listener.local_addr()?
        );
    }
    let app = Arc::new(App::new(settings));
    axum::serve(listener, router(app, &callback_path)).await?;
    Ok(())
}

fn router(app: Arc<App>, callback_path: &str) -> Router {
    Router::new()
        .route(
            "/",
            get(|| async { Html("<a href='/login'>Start OAuth</a>") }),
        )
        .route("/login", get(login))
        .route(callback_path, get(callback))
        .with_state(app)
}

#[cfg(test)]
mod tests;
