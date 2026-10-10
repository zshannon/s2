//! Client-key authentication and Biscuit authorization for S2.
//! Permission evaluation has no database dependency.
mod biscuit;
mod collection;
mod keys;
mod policy;
pub use biscuit::*;
pub use collection::*;
pub use keys::*;

pub type Result<T> = std::result::Result<T, AuthError>;
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid PKI key")]
    Key,
    #[error("invalid PKI grant")]
    InvalidGrant,
    #[error("untrusted grant issuer")]
    UntrustedIssuer,
    #[error("invalid client-signed delegation")]
    Delegation,
    #[error("grant audience does not match endpoint")]
    Audience,
    #[error("operation is outside the grant")]
    PermissionDenied,
    #[error("listing work limit exceeded")]
    ListWorkLimit,
    #[error("invalid HTTP message signature")]
    Signature,
    #[error("Biscuit verification failed: {0}")]
    Biscuit(#[from] biscuit_auth::error::Token),
}

mod signatures;
pub use s2_common::access::Operation;
pub use signatures::*;
