use crate::{Error, FacebookProfileMode, Provider};
use serde::{Deserialize, Serialize};

/// Identity fetched directly from the provider after a successful code exchange.
///
/// Use `(provider, subject)` within the configured provider app as the identity key.
/// This value is not an application session or a validated OpenID Connect ID token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    /// Provider that returned this identity.
    pub provider: Provider,
    /// Stable provider identifier; never substitute email as the identity key.
    pub subject: String,
    /// Email when supplied. Facebook IdOnly mode does not request email.
    pub email: Option<String>,
    /// Provider's email verification claim, or `None` if unavailable.
    pub email_verified: Option<bool>,
    /// Display name when supplied.
    pub name: Option<String>,
    /// First/given name when supplied by the provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    /// Middle name when supplied by Facebook.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
    /// Last/family name when supplied by the provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    /// Avatar URL when supplied. Treat it as untrusted external content.
    pub avatar_url: Option<String>,
}

impl Identity {
    /// Returns the email only when the provider explicitly marks it verified.
    /// Account linking and email ownership policy remain the application's decision.
    pub fn verified_email(&self) -> Option<&str> {
        (self.email_verified == Some(true))
            .then_some(self.email.as_deref())
            .flatten()
    }
}

#[derive(Deserialize)]
struct GoogleProfile {
    sub: String,
    email: Option<String>,
    email_verified: Option<bool>,
    name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    picture: Option<String>,
}

#[derive(Default, Deserialize)]
struct FacebookProfile {
    id: String,
    name: Option<String>,
    first_name: Option<String>,
    middle_name: Option<String>,
    last_name: Option<String>,
    email: Option<String>,
    picture: Option<FacebookPicture>,
}

#[derive(Deserialize)]
struct FacebookIdProfile {
    id: String,
}

#[derive(Deserialize)]
struct FacebookPicture {
    data: Option<FacebookPictureData>,
}

#[derive(Deserialize)]
struct FacebookPictureData {
    url: Option<String>,
}

pub(crate) fn parse_identity(
    provider: Provider,
    body: &[u8],
    facebook_mode: FacebookProfileMode,
) -> Result<Identity, Error> {
    let identity = match provider {
        Provider::Google => {
            let profile: GoogleProfile =
                serde_json::from_slice(body).map_err(|_| Error::InvalidProfile)?;
            Identity {
                provider,
                subject: profile.sub,
                email: profile.email,
                email_verified: profile.email_verified,
                name: profile.name,
                first_name: profile.given_name,
                middle_name: None,
                last_name: profile.family_name,
                avatar_url: profile.picture,
            }
        }
        Provider::Facebook => {
            let profile: FacebookProfile = match facebook_mode {
                FacebookProfileMode::Full => {
                    serde_json::from_slice(body).map_err(|_| Error::InvalidProfile)?
                }
                FacebookProfileMode::IdOnly => {
                    // Ignore even unexpected or malformed extra profile fields in IdOnly mode.
                    let id: FacebookIdProfile =
                        serde_json::from_slice(body).map_err(|_| Error::InvalidProfile)?;
                    FacebookProfile {
                        id: id.id,
                        ..FacebookProfile::default()
                    }
                }
            };
            Identity {
                provider,
                subject: profile.id,
                email: profile.email,
                email_verified: None,
                name: profile.name,
                first_name: profile.first_name,
                middle_name: profile.middle_name,
                last_name: profile.last_name,
                avatar_url: profile
                    .picture
                    .and_then(|picture| picture.data)
                    .and_then(|data| data.url),
            }
        }
    };
    if identity.subject.trim().is_empty() {
        return Err(Error::InvalidProfile);
    }
    Ok(identity)
}
