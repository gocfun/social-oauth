use super::OAuthClient;
use crate::{
    Authorization, Error, FacebookProfileMode, Identity, PendingAuthorization, PkceMode, Provider,
};
use oauth2::{CsrfToken, PkceCodeChallenge, Scope};
use subtle::ConstantTimeEq;

impl OAuthClient {
    /// Creates fresh cryptographically random state and a provider authorization URL.
    /// Store `pending` in the browser's server-side session before redirecting.
    pub fn authorize(&self) -> Authorization {
        let pkce = if self.provider == Provider::Google {
            PkceMode::S256
        } else {
            PkceMode::Disabled
        };
        self.authorize_with_state(CsrfToken::new_random().secret().clone(), pkce)
            .expect("generated OAuth state is non-empty")
    }

    /// Creates an authorization URL with application-supplied state and PKCE policy.
    ///
    /// Supply fresh, unpredictable state for every attempt; prefixes are preserved
    /// verbatim. The caller must store, expire, browser-bind and atomically consume
    /// state before calling the lower-level code exchange APIs. With S256, also
    /// save [`PendingAuthorization::pkce_verifier`] privately. Only enable PKCE
    /// when supported by the configured provider flow.
    pub fn authorize_with_state(
        &self,
        state: impl Into<String>,
        pkce: PkceMode,
    ) -> Result<Authorization, Error> {
        let state = state.into();
        if state.trim().is_empty() {
            return Err(Error::InvalidState);
        }
        let mut request = self.oauth.authorize_url(|| CsrfToken::new(state));
        let mut pkce_verifier = None;
        if self.provider == Provider::Google {
            request = request
                .add_scope(Scope::new("openid".into()))
                .add_scope(Scope::new("email".into()))
                .add_scope(Scope::new("profile".into()));
        } else if self.facebook_profile_mode == FacebookProfileMode::Full {
            request = request
                .add_scope(Scope::new("public_profile".into()))
                .add_scope(Scope::new("email".into()));
        }
        if pkce == PkceMode::S256 {
            let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
            request = request.set_pkce_challenge(challenge);
            pkce_verifier = Some(verifier.secret().clone());
        }
        let (url, state) = request.url();
        Ok(Authorization {
            url,
            pending: PendingAuthorization::new(
                self.provider,
                self.client_id.clone(),
                self.redirect_uri.clone(),
                state.secret().clone(),
                pkce_verifier,
            ),
        })
    }

    /// Validates state, exchanges the code and fetches the provider identity.
    ///
    /// `pending` must come from a trusted, browser-bound store and be atomically
    /// consumed before calling this method. The library compares state but cannot
    /// establish browser binding or enforce expiry/storage replay protection.
    /// No provider access/refresh token is returned or persisted.
    pub async fn complete(
        &self,
        pending: PendingAuthorization,
        code: &str,
        returned_state: &str,
    ) -> Result<Identity, Error> {
        if !pending.belongs_to(self.provider, &self.client_id, &self.redirect_uri) {
            return Err(Error::ClientMismatch);
        }
        if !bool::from(pending.state().as_bytes().ct_eq(returned_state.as_bytes())) {
            return Err(Error::StateMismatch);
        }
        self.identity_from_code(code, pending.pkce_verifier()).await
    }
}
