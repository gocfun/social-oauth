use super::{exchange::MAX_PROFILE_BYTES, OAuthClient};
use crate::{Error, Identity, Provider};
use futures_util::StreamExt;
use jsonwebtoken::{
    decode, decode_header,
    jwk::{AlgorithmParameters, JwkSet, KeyAlgorithm, PublicKeyUse},
    Algorithm, DecodingKey, Validation,
};
use oauth2::AuthorizationCode;
use serde::Deserialize;
use subtle::ConstantTimeEq;
use url::Url;

const ISSUER: &str = "https://appleid.apple.com";
const AUTH_URL: &str = "https://appleid.apple.com/auth/authorize";
const TOKEN_URL: &str = "https://appleid.apple.com/auth/token";
const JWKS_URL: &str = "https://appleid.apple.com/auth/keys";

#[derive(Deserialize)]
struct AppleClaims {
    sub: String,
    nonce: String,
    email: Option<String>,
    email_verified: Option<AppleEmailVerified>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AppleEmailVerified {
    Boolean(bool),
    String(String),
}

impl AppleEmailVerified {
    fn into_verified(self) -> bool {
        match self {
            Self::Boolean(verified) => verified,
            Self::String(value) => value == "true",
        }
    }
}

impl OAuthClient {
    /// Builds a confidential browser client for a Sign in with Apple Services ID.
    /// Pass a signed Apple client-secret JWT and the registered HTTPS callback.
    pub fn apple(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<Self, Error> {
        Self::apple_with_endpoints(client_id, client_secret, redirect_uri, AUTH_URL, TOKEN_URL)
    }

    /// Builds an Apple browser client with explicit authorization and token URLs.
    /// These endpoints must be trusted HTTPS URLs. Verification always uses Apple's issuer and keys.
    pub fn apple_with_endpoints(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
        auth_url: impl AsRef<str>,
        token_url: impl AsRef<str>,
    ) -> Result<Self, Error> {
        let auth_url = auth_url.as_ref();
        let token_url = token_url.as_ref();
        for endpoint in [auth_url, token_url] {
            let endpoint = Url::parse(endpoint)
                .map_err(|_| Error::Configuration("invalid Apple endpoint URL"))?;
            if endpoint.scheme() != "https"
                || endpoint.host().is_none()
                || !endpoint.username().is_empty()
                || endpoint.password().is_some()
                || endpoint.query().is_some()
                || endpoint.fragment().is_some()
            {
                return Err(Error::Configuration(
                    "Apple endpoints require HTTPS without credentials, query or fragment",
                ));
            }
        }
        Self::new(
            Provider::Apple,
            client_id.into(),
            client_secret.into(),
            redirect_uri.into(),
            auth_url,
            token_url,
            JWKS_URL,
        )
    }

    pub(super) async fn apple_identity_from_code(
        &self,
        code: &str,
        nonce: &str,
    ) -> Result<Identity, Error> {
        if code.trim().is_empty() {
            return Err(Error::MissingCode);
        }
        let response = self
            .oauth
            .exchange_code(AuthorizationCode::new(code.to_owned()))
            .request_async(&self.http)
            .await
            .map_err(|_| Error::TokenExchange)?;
        let id_token = response
            .extra_fields()
            .id_token
            .as_str()
            .ok_or(Error::InvalidAppleIdentity)?;
        let header = decode_header(id_token).map_err(|_| Error::InvalidAppleIdentity)?;
        let kid = header
            .kid
            .filter(|kid| !kid.is_empty() && header.alg == Algorithm::RS256)
            .ok_or(Error::InvalidAppleIdentity)?;
        let keys = self.fetch_apple_keys().await?;
        verify_identity(id_token, &kid, &keys, &self.client_id, nonce)
    }

    async fn fetch_apple_keys(&self) -> Result<JwkSet, Error> {
        let response = self
            .http
            .get(self.profile_url.clone())
            .send()
            .await
            .map_err(|_| Error::ProfileRequest)?;
        if !response.status().is_success() {
            return Err(Error::ProfileStatus(response.status().as_u16()));
        }
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| Error::ProfileRequest)?;
            if chunk.len() > MAX_PROFILE_BYTES.saturating_sub(body.len()) {
                return Err(Error::InvalidAppleIdentity);
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|_| Error::InvalidAppleIdentity)
    }
}

fn verify_identity(
    id_token: &str,
    kid: &str,
    keys: &JwkSet,
    client_id: &str,
    nonce: &str,
) -> Result<Identity, Error> {
    let jwk = keys.find(kid).ok_or(Error::InvalidAppleIdentity)?;
    if !matches!(jwk.algorithm, AlgorithmParameters::RSA(_))
        || jwk.common.key_algorithm != Some(KeyAlgorithm::RS256)
        || jwk.common.public_key_use != Some(PublicKeyUse::Signature)
    {
        return Err(Error::InvalidAppleIdentity);
    }
    let key = DecodingKey::from_jwk(jwk).map_err(|_| Error::InvalidAppleIdentity)?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[client_id]);
    validation.set_required_spec_claims(&["iss", "aud", "exp", "sub"]);
    validation.leeway = 0;
    let claims = decode::<AppleClaims>(id_token, &key, &validation)
        .map_err(|_| Error::InvalidAppleIdentity)?
        .claims;
    if claims.sub.trim().is_empty()
        || nonce.is_empty()
        || !bool::from(claims.nonce.as_bytes().ct_eq(nonce.as_bytes()))
    {
        return Err(Error::InvalidAppleIdentity);
    }
    Ok(Identity {
        provider: Provider::Apple,
        subject: claims.sub,
        email: claims.email,
        email_verified: claims.email_verified.map(AppleEmailVerified::into_verified),
        name: None,
        first_name: None,
        middle_name: None,
        last_name: None,
        avatar_url: None,
    })
}

#[cfg(test)]
mod tests;
