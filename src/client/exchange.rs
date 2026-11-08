use super::OAuthClient;
use crate::{identity::parse_identity, Error, FacebookProfileMode, Identity, Provider};
use futures_util::StreamExt;
use oauth2::{AuthorizationCode, PkceCodeVerifier, TokenResponse};
use std::fmt;

pub(super) const MAX_PROFILE_BYTES: usize = 64 * 1024;

/// Opaque provider token obtained by exchanging an authorization code.
/// Not serializable; Debug redacts token values. Use with [`OAuthClient::fetch_identity`].
pub struct ProviderToken {
    provider: Provider,
    client_id: String,
    redirect_uri: String,
    access_token: oauth2::AccessToken,
}

impl fmt::Debug for ProviderToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderToken")
            .field("provider", &self.provider)
            .finish_non_exhaustive()
    }
}

impl OAuthClient {
    /// Exchanges a code after the application has validated and consumed its state.
    ///
    /// This method does NOT check OAuth state, expiry or browser binding. Use it
    /// only after your own CSRF/state checks, or use [`Self::complete`] instead.
    /// Pass the saved private verifier for S256, or `None` for a non-PKCE flow.
    pub async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: Option<&str>,
    ) -> Result<ProviderToken, Error> {
        if code.trim().is_empty() {
            return Err(Error::MissingCode);
        }
        let mut exchange = self
            .oauth
            .exchange_code(AuthorizationCode::new(code.into()));
        if let Some(verifier) = pkce_verifier {
            exchange = exchange.set_pkce_verifier(PkceCodeVerifier::new(verifier.into()));
        }
        let token = exchange
            .request_async(&self.http)
            .await
            .map_err(|_| Error::TokenExchange)?;
        Ok(ProviderToken {
            provider: self.provider,
            client_id: self.client_id.clone(),
            redirect_uri: self.redirect_uri.clone(),
            access_token: token.access_token().clone(),
        })
    }

    /// Fetches identity using an opaque token returned by this configured client.
    /// This performs no application account, session or binding operations.
    pub async fn fetch_identity(&self, token: &ProviderToken) -> Result<Identity, Error> {
        if token.provider != self.provider
            || token.client_id != self.client_id
            || token.redirect_uri != self.redirect_uri
        {
            return Err(Error::ClientMismatch);
        }
        let mut request = self
            .http
            .get(self.profile_url.clone())
            .bearer_auth(token.access_token.secret());
        if self.provider == Provider::Facebook {
            let fields = match self.facebook_profile_mode {
                FacebookProfileMode::Full => {
                    "id,name,first_name,middle_name,last_name,email,picture"
                }
                FacebookProfileMode::IdOnly => "id",
            };
            request = request.query(&[("fields", fields)]);
        }
        let response = request.send().await.map_err(|_| Error::ProfileRequest)?;
        if !response.status().is_success() {
            return Err(Error::ProfileStatus(response.status().as_u16()));
        }
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| Error::ProfileRequest)?;
            if chunk.len() > MAX_PROFILE_BYTES.saturating_sub(body.len()) {
                return Err(Error::InvalidProfile);
            }
            body.extend_from_slice(&chunk);
        }
        parse_identity(self.provider, &body, self.facebook_profile_mode)
    }

    /// Convenience method to exchange a code and fetch identity after your own
    /// state validation. Does NOT replace CSRF checks, state consumption or expiry.
    /// No library-specific pending-state format is required by this API.
    pub async fn identity_from_code(
        &self,
        code: &str,
        pkce_verifier: Option<&str>,
    ) -> Result<Identity, Error> {
        let token = self.exchange_code(code, pkce_verifier).await?;
        self.fetch_identity(&token).await
    }
}
