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
        let pkce = match self.provider {
            Provider::Google | Provider::Discord => PkceMode::S256,
            Provider::Facebook | Provider::Apple => PkceMode::Disabled,
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
        let nonce = if self.provider == Provider::Apple {
            if pkce == PkceMode::S256 {
                return Err(Error::Configuration(
                    "Apple browser flow requires PKCE disabled",
                ));
            }
            let nonce = CsrfToken::new_random().secret().clone();
            request = request
                .add_extra_param("response_mode", "form_post")
                .add_extra_param("nonce", nonce.clone());
            Some(nonce)
        } else {
            None
        };
        let mut pkce_verifier = None;
        let scopes: &[&str] = match self.provider {
            Provider::Google => &["openid", "email", "profile"],
            Provider::Facebook if self.facebook_profile_mode == FacebookProfileMode::Full => {
                &["public_profile", "email"]
            }
            Provider::Facebook => &[],
            Provider::Discord => &["identify", "email"],
            Provider::Apple => &["openid"],
        };
        for &scope in scopes {
            request = request.add_scope(Scope::new(scope.into()));
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
                nonce,
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
        if self.provider == Provider::Apple {
            let nonce = pending.nonce().ok_or(Error::InvalidAppleIdentity)?;
            return self.apple_identity_from_code(code, nonce).await;
        }
        self.identity_from_code(code, pending.pkce_verifier()).await
    }
}
