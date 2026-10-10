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

/// Intersect storage selection with verified literal scope, retaining per-row
/// native authorization. Invalid resource prefixes cannot match stored names.
pub(super) fn intersect_list_range(
    range: std::ops::Range<bytes::Bytes>,
    scope: &s2_pki_auth::ResourceScope,
    prefix_range: impl FnOnce(&str) -> Option<std::ops::Range<bytes::Bytes>>,
) -> std::ops::Range<bytes::Bytes> {
    use s2_pki_auth::ResourceScope;
    let value = match scope {
        ResourceScope::Any => return range,
        ResourceScope::None => return range.start.clone()..range.start,
        ResourceScope::Exact(value) | ResourceScope::Prefix(value) => value,
    };
    let Some(mut scoped) = prefix_range(value) else {
        return range.start.clone()..range.start;
    };
    if matches!(scope, ResourceScope::Exact(_)) {
        // Names contain no NUL. This exclusive end contains only the exact key,
        // never extension names that happen to share the same prefix.
        let mut end = scoped.start.to_vec();
        end.push(0);
        scoped.end = end.into();
    }
    std::cmp::max(range.start, scoped.start)..std::cmp::min(range.end, scoped.end)
}

#[cfg(test)]
mod tests;
