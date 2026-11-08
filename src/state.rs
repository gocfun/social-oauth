use crate::Provider;
use serde::{Deserialize, Serialize};
use std::fmt;
use url::Url;

/// Authorization URL and the private state that must be saved before redirecting.
/// Debug output deliberately hides both values.
pub struct Authorization {
    /// Send the browser to this URL; do not log it because it contains OAuth state.
    pub url: Url,
    /// Store server-side, bound to the initiating browser session, with a short TTL.
    pub pending: PendingAuthorization,
}

impl fmt::Debug for Authorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authorization").finish_non_exhaustive()
    }
}

/// Private, serializable OAuth state and optional PKCE verifier.
///
/// Store in a trusted server-side session store; serialization exposes secrets.
/// Never send it to the browser as unsigned JSON, log it, or deserialize it from
/// callback parameters. Bind it to the initiating browser, expire it (e.g. 5 minutes),
/// and atomically consume it once, including on denial/failure. Rust ownership alone
/// cannot prevent replay of a previously serialized value.
#[derive(Serialize, Deserialize)]
pub struct PendingAuthorization {
    provider: Provider,
    client_id: String,
    redirect_uri: String,
    state: String,
    pkce_verifier: Option<String>,
}

impl PendingAuthorization {
    pub(crate) fn new(
        provider: Provider,
        client_id: String,
        redirect_uri: String,
        state: String,
        pkce_verifier: Option<String>,
    ) -> Self {
        Self {
            provider,
            client_id,
            redirect_uri,
            state,
            pkce_verifier,
        }
    }

    pub(crate) fn belongs_to(
        &self,
        provider: Provider,
        client_id: &str,
        redirect_uri: &str,
    ) -> bool {
        self.provider == provider
            && self.client_id == client_id
            && self.redirect_uri == redirect_uri
    }

    /// State sent to the provider. Useful for existing session/Redis key formats.
    /// Do not log it, and do not treat possession of this value as browser binding.
    pub fn state(&self) -> &str {
        &self.state
    }

    /// Private PKCE verifier to save in your trusted one-use state store, if enabled.
    pub fn pkce_verifier(&self) -> Option<&str> {
        self.pkce_verifier.as_deref()
    }
}

impl fmt::Debug for PendingAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingAuthorization")
            .field("provider", &self.provider)
            .finish_non_exhaustive()
    }
}
