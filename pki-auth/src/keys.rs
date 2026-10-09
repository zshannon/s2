use biscuit_auth::{KeyPair, PrivateKey, PublicKey, builder::Algorithm};
use p256::ecdsa::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::{AuthError, Result};

#[derive(Clone)]
pub struct ClientKey(pub(crate) SigningKey);

impl std::fmt::Debug for ClientKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientKey")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}
impl ClientKey {
    pub fn generate() -> Self {
        Self(SigningKey::random(&mut OsRng))
    }
    pub fn from_base58(value: &str) -> Result<Self> {
        let bytes = bs58::decode(value).into_vec().map_err(|_| AuthError::Key)?;
        Ok(Self(
            SigningKey::from_slice(&bytes).map_err(|_| AuthError::Key)?,
        ))
    }
    /// Export only for explicit credential storage. Debug never exposes this value.
    pub fn to_base58(&self) -> String {
        bs58::encode(self.0.to_bytes()).into_string()
    }
    pub fn public_key(&self) -> ClientPublicKey {
        ClientPublicKey(
            bs58::encode(self.0.verifying_key().to_encoded_point(true).as_bytes()).into_string(),
        )
    }
    pub(crate) fn biscuit_private(&self) -> Result<PrivateKey> {
        PrivateKey::from_bytes(self.0.to_bytes().as_slice(), Algorithm::Secp256r1)
            .map_err(|_| AuthError::Key)
    }
    pub(crate) fn biscuit_keypair(&self) -> Result<KeyPair> {
        Ok(KeyPair::from(&self.biscuit_private()?))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClientPublicKey(pub(crate) String);
impl ClientPublicKey {
    pub fn from_base58(value: &str) -> Result<Self> {
        let key = Self(value.to_owned());
        key.verifying_key()?;
        Ok(key)
    }
    pub fn to_base58(&self) -> &str {
        &self.0
    }
    pub(crate) fn verifying_key(&self) -> Result<VerifyingKey> {
        VerifyingKey::from_sec1_bytes(
            &bs58::decode(&self.0)
                .into_vec()
                .map_err(|_| AuthError::Key)?,
        )
        .map_err(|_| AuthError::Key)
    }
    pub(crate) fn biscuit_public(&self) -> Result<PublicKey> {
        PublicKey::from_bytes(
            self.verifying_key()?.to_encoded_point(true).as_bytes(),
            Algorithm::Secp256r1,
        )
        .map_err(|_| AuthError::Key)
    }
}

#[derive(Clone, Debug)]
pub struct TrustedIssuers(pub(crate) Vec<ClientPublicKey>);
impl TrustedIssuers {
    pub fn new(keys: Vec<ClientPublicKey>) -> Self {
        Self(keys)
    }
}
