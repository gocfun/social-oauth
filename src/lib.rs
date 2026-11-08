#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod client;
mod error;
mod identity;
mod provider;
mod state;

/// Explicit TOML configuration loading, available with the `config-toml` feature.
#[cfg(feature = "config-toml")]
pub mod config;

pub use client::{OAuthClient, ProviderToken};
pub use error::Error;
pub use identity::Identity;
pub use provider::{ClientAuthentication, Endpoints, FacebookProfileMode, PkceMode, Provider};
pub use state::{Authorization, PendingAuthorization};
