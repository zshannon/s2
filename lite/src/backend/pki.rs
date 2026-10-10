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
            expired.push((entry.key, entry.value, timestamp));
        }
        if !expired.is_empty() {
            let txn = self.db.begin(IsolationLevel::SerializableSnapshot).await?;
            for (index, key, timestamp) in expired {
                // The scan may predate a replacement value. Read the value in
                // this serializable transaction, so both earlier replacements
                // and writes racing this read cannot be deleted by stale work.
                if txn
                    .get(&key)
                    .await?
                    .is_some_and(|value| value.as_ref() == timestamp.to_be_bytes())
                {
                    txn.delete(&key)?;
                }
                txn.delete(index)?;
            }
            match super::store::db_txn_commit_durable(txn).await {
                Ok(_) => {}
                // Cleanup is optional; a concurrent write keeps state for the
                // next cleanup instead of making nonce admission unavailable.
                Err(error) if error.kind() == slatedb::ErrorKind::Transaction => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
    pub(crate) async fn pki_accept_nonce(
        &self,
        identity: &VerifiedRequest,
    ) -> Result<bool, StorageError> {
        self.pki_accept_nonce_with_clock(identity, || {
            time::OffsetDateTime::now_utc().unix_timestamp()
        })
        .await
    }
    async fn pki_accept_nonce_with_clock(
        &self,
        identity: &VerifiedRequest,
        now: impl Fn() -> i64 + Send + Sync,
    ) -> Result<bool, StorageError> {
        if identity.validate_admission(now()).is_err() {
            return Ok(false);
        }
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
            // A proof that expired during the durable commit never reaches a
            // handler, even if cleanup subsequently makes its nonce reusable.
            Ok(_) => Ok(identity.validate_admission(now()).is_ok()),
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

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use bytesize::ByteSize;
    use http::{HeaderMap, Method};
    use s2_pki_auth::*;
    use slatedb::{Db, config::Settings, object_store::memory::InMemory};

    use super::*;

    async fn backend() -> Backend {
        let db = Db::builder(
            format!("pki-races-{}", uuid::Uuid::new_v4()),
            Arc::new(InMemory::new()),
        )
        .with_settings(Settings {
            flush_interval: Some(Duration::from_millis(5)),
            ..Default::default()
        })
        .build()
        .await
        .unwrap();
        Backend::new(db, ByteSize::mib(10))
    }
    fn identity(created: i64, verified_at: i64) -> VerifiedRequest {
        let issuer = ClientKey::generate();
        let holder = ClientKey::generate();
        let grant = issue_grant(
            &issuer,
            &holder.public_key(),
            "http://localhost",
            &GrantScope::new(
                ResourceScope::Any,
                ResourceScope::Any,
                vec![Operation::Read],
            ),
            2_000_000_000,
        )
        .unwrap();
        let credentials = PkiCredentials::new(holder, grant).unwrap();
        let uri = "http://localhost/v1/streams/events/records"
            .parse()
            .unwrap();
        let mut headers = HeaderMap::new();
        sign_request(
            &credentials,
            &Method::GET,
            &uri,
            &mut headers,
            RequestBody::Unary(b""),
            created,
        )
        .unwrap();
        verify_request(
            &TrustedIssuers::new(vec![issuer.public_key()]),
            "http://localhost",
            &Method::GET,
            &uri,
            &headers,
            RequestBody::Unary(b""),
            verified_at,
        )
        .unwrap()
    }
    #[tokio::test]
    async fn pending_proofs_cannot_be_admitted_after_expiry() {
        let backend = backend().await;
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let identity = identity(now, now);
        let expiry = identity.proof_expires_at();
        assert!(identity.lease_expires_at() > expiry);
        for _ in 0..2 {
            assert!(
                !backend
                    .pki_accept_nonce_with_clock(&identity, || expiry)
                    .await
                    .unwrap(),
                "pending verified proofs must not reopen expired replay state"
            );
        }
        backend.close().await.unwrap();
    }
    #[tokio::test]
    async fn stale_expiry_indexes_cannot_delete_a_renewed_nonce() {
        let backend = backend().await;
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let key = b"\xf0renewed-nonce".to_vec();
        let mut index = vec![0xf2];
        index.extend((now - 1).to_be_bytes());
        index.extend(&key);
        let expired_key = b"\xf0expired-nonce".to_vec();
        let mut expired_index = vec![0xf2];
        expired_index.extend((now - 2).to_be_bytes());
        expired_index.extend(&expired_key);
        // This is the state seen by a stale cleanup after another request has
        // replaced the expired nonce with a newer admitted value.
        let txn = backend
            .db
            .begin(IsolationLevel::SerializableSnapshot)
            .await
            .unwrap();
        txn.put(&index, &key).unwrap();
        txn.put(&key, (now + 60).to_be_bytes()).unwrap();
        txn.put(&expired_index, &expired_key).unwrap();
        txn.put(&expired_key, (now - 2).to_be_bytes()).unwrap();
        db_txn_commit_durable(txn).await.unwrap();
        backend.pki_cleanup_nonces().await.unwrap();
        assert_eq!(
            backend.db.get(&key).await.unwrap().as_deref(),
            Some((now + 60).to_be_bytes().as_slice()),
            "cleanup must preserve the newer nonce value"
        );
        assert!(backend.db.get(&index).await.unwrap().is_none());
        assert!(backend.db.get(&expired_index).await.unwrap().is_none());
        assert!(backend.db.get(&expired_key).await.unwrap().is_none());
        backend.close().await.unwrap();
    }
    #[tokio::test]
    async fn proof_expiring_during_durable_nonce_admission_is_rejected() {
        use std::sync::atomic::{AtomicI64, Ordering};
        let backend = backend().await;
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let identity = identity(now, now);
        let clock = AtomicI64::new(identity.proof_expires_at() - 1);
        assert!(
            !backend
                .pki_accept_nonce_with_clock(&identity, || clock.fetch_add(1, Ordering::SeqCst))
                .await
                .unwrap(),
            "proof freshness must be checked after awaited durable admission"
        );
        // An admitted session has its own longer lease; proof freshness must
        // not be imposed on its subsequent native operation checks.
        identity
            .authorize(
                Operation::Read,
                Some("logs"),
                Some("events"),
                identity.proof_expires_at() + 1,
            )
            .unwrap();
        backend.close().await.unwrap();
    }
    #[tokio::test]
    async fn fresh_nonce_admission_is_once_only() {
        let backend = backend().await;
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let identity = identity(now, now);
        let clock = || identity.proof_expires_at() - 1;
        assert!(
            backend
                .pki_accept_nonce_with_clock(&identity, clock)
                .await
                .unwrap()
        );
        assert!(
            !backend
                .pki_accept_nonce_with_clock(&identity, clock)
                .await
                .unwrap()
        );
        backend.close().await.unwrap();
    }
}
