use super::Backend;
use crate::auth::revocation::{self, RevocationError};

impl Backend {
    /// Check if any of the given revocation IDs are revoked.
    pub async fn is_token_revoked(
        &self,
        revocation_ids: &[Vec<u8>],
    ) -> Result<bool, RevocationError> {
        revocation::is_revoked(&self.db, revocation_ids).await
    }

    /// Revoke a token by storing its revocation ID.
    pub async fn revoke_token(&self, revocation_id: &[u8]) -> Result<(), RevocationError> {
        revocation::revoke(&self.db, revocation_id).await
    }

    /// List all revoked token IDs (hex-encoded).
    pub async fn list_revocations(&self) -> Result<Vec<String>, RevocationError> {
        revocation::list_revocations(&self.db).await
    }
}
