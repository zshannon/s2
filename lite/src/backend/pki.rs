//! PKI deny-only state. Permission decisions live in s2-pki-auth.
use s2_common::access::Operation;
use s2_pki_auth::VerifiedRequest;
use slatedb::IsolationLevel;

use super::{Backend, error::StorageError, store::db_txn_commit_durable};
impl Backend {
    pub(crate) fn with_pki(mut self, identity: Option<VerifiedRequest>) -> Self {
        self.pki = identity;
        self
    }
    pub(super) fn authorize(
        &self,
        op: Operation,
        basin: Option<&str>,
        stream: Option<&str>,
    ) -> Result<(), StorageError> {
        if let Some(identity) = &self.pki {
            identity
                .authorize(
                    op,
                    basin,
                    stream,
                    time::OffsetDateTime::now_utc().unix_timestamp(),
                )
                .map_err(|_| StorageError::PermissionDenied)?;
        }
        Ok(())
    }
    pub(super) fn authorize_provision_stream(
        &self,
        basin: &str,
        stream: &str,
        ensure: bool,
    ) -> Result<(), StorageError> {
        if let Some(identity) = &self.pki {
            identity
                .authorize_provision_stream(
                    basin,
                    stream,
                    ensure,
                    time::OffsetDateTime::now_utc().unix_timestamp(),
                )
                .map_err(|_| StorageError::PermissionDenied)?;
        }
        Ok(())
    }
    pub(super) fn authorize_collection(
        &self,
        operation: Operation,
        basin: Option<&str>,
    ) -> Result<(), StorageError> {
        if let Some(identity) = &self.pki {
            identity
                .authorize_collection(
                    operation,
                    basin,
                    time::OffsetDateTime::now_utc().unix_timestamp(),
                )
                .map_err(|_| StorageError::PermissionDenied)?;
        }
        Ok(())
    }
    pub async fn pki_not_revoked(&self, ids: &[Vec<u8>]) -> Result<bool, StorageError> {
        not_revoked(&self.db, ids).await
    }
    pub async fn pki_revoke(&self, id: &[u8]) -> Result<(), StorageError> {
        let mut key = vec![0xf1];
        key.extend(id);
        let txn = self.db.begin(IsolationLevel::SerializableSnapshot).await?;
        txn.put(key, b"revoked")?;
        db_txn_commit_durable(txn).await?;
        Ok(())
    }
    // Prefixes 0xf0 (nonce), 0xf1 (revocation), 0xf2 (nonce expiry index) are reserved for PKI
    // state.
    async fn pki_cleanup_nonces(&self) -> Result<(), StorageError> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let mut it = self.db.scan(vec![0xf2]..vec![0xf3]).await?;
        let mut expired = Vec::new();
        while expired.len() < 128 {
            let Some(entry) = it.next().await? else { break };
            let timestamp = entry
                .key
                .get(1..9)
                .and_then(|bytes| bytes.try_into().ok())
                .map(i64::from_be_bytes)
                .ok_or_else(|| {
                    StorageError::InvariantViolation("Invalid PKI nonce expiry index".into())
                })?;
            if timestamp > now {
                break;
            }
            expired.push((entry.key, entry.value));
        }
        if !expired.is_empty() {
            let txn = self.db.begin(IsolationLevel::SerializableSnapshot).await?;
            for (index, key) in expired {
                txn.delete(index)?;
                txn.delete(key)?;
            }
            super::store::db_txn_commit_durable(txn).await?;
        }
        Ok(())
    }
    pub(crate) async fn pki_accept_nonce(
        &self,
        identity: &VerifiedRequest,
    ) -> Result<bool, StorageError> {
        self.pki_cleanup_nonces().await?;
        let mut key = vec![0xf0];
        key.extend(
            format!(
                "{}:{}",
                identity.capability().client_public_key().to_base58(),
                identity.nonce()
            )
            .as_bytes(),
        );
        let txn = self.db.begin(IsolationLevel::SerializableSnapshot).await?;
        if txn.get(&key).await?.is_some() {
            return Ok(false);
        }
        let mut index = vec![0xf2];
        index.extend(identity.proof_expires_at().to_be_bytes());
        index.extend(&key);
        txn.put(index, key.as_slice())?;
        txn.put(key, identity.proof_expires_at().to_be_bytes())?;
        match db_txn_commit_durable(txn).await {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == slatedb::ErrorKind::Transaction => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
}

pub(super) async fn not_revoked(db: &slatedb::Db, ids: &[Vec<u8>]) -> Result<bool, StorageError> {
    for id in ids {
        let mut key = vec![0xf1];
        key.extend(id);
        if db.get(key).await?.is_some() {
            return Ok(false);
        }
    }
    Ok(true)
}
