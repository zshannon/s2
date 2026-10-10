//! Bounded native authorization for one collection scan.
use crate::{AuthError, Operation, ResourceScope, Result, VerifiedRequest};

pub const MAX_COLLECTION_CANDIDATES: usize = 4096;

/// One budget per list request, including denied rows and pagination lookahead.
/// Hosts must intersect scans with `resource_scope`, stop on errors and discard
/// partial output; never expose a raw scanned-key cursor or derive `has_more`
/// from denied candidates. Broad custom policies are rejected at preflight.
pub struct CollectionAuthorizer<'a> {
    request: &'a VerifiedRequest,
    operation: Operation,
    basin: Option<&'a str>,
    remaining_candidates: usize,
    remaining_work: usize,
}
impl VerifiedRequest {
    pub fn collection_authorizer<'a>(
        &'a self,
        operation: Operation,
        basin: Option<&'a str>,
        now: i64,
    ) -> Result<CollectionAuthorizer<'a>> {
        if now < 0 {
            return Err(AuthError::PermissionDenied);
        }
        self.authorize_collection(operation, basin, now)?;
        Ok(CollectionAuthorizer {
            request: self,
            operation,
            basin,
            remaining_candidates: MAX_COLLECTION_CANDIDATES,
            // Preserve a maximum-sized fully authorized page plus lookahead,
            // even for the most expensive admitted profile. Cheap profiles
            // remain bounded by the independent candidate ceiling.
            remaining_work: (s2_common::resources::ListLimit::MAX.as_usize() + 1)
                * crate::policy::MAX_EVALUATION_WORK,
        })
    }
}
impl CollectionAuthorizer<'_> {
    /// Hosts must honor these scan bounds. All native checks still run per row.
    pub fn resource_scope(&self) -> &ResourceScope {
        let scope = self.request.capability().scope();
        match self.operation {
            Operation::ListBasins => &scope.basins,
            Operation::ListStreams => &scope.streams,
            _ => unreachable!("collection preflight rejects other operations"),
        }
    }
    pub fn check_active(&self, now: i64) -> Result<()> {
        if now < 0 || now >= self.request.lease_expires_at() {
            return Err(AuthError::PermissionDenied);
        }
        Ok(())
    }
    /// `Ok(false)` is a filtered candidate; expiry/budget errors abort the list.
    pub fn authorize_candidate(&mut self, resource: &str, now: i64) -> Result<bool> {
        self.check_active(now)?;
        let work = self.request.capability().evaluation_work;
        if self.remaining_candidates == 0 || self.remaining_work < work {
            return Err(AuthError::ListWorkLimit);
        }
        self.remaining_candidates -= 1;
        self.remaining_work -= work;
        let (basin, stream) = match self.operation {
            Operation::ListBasins => (Some(resource), None),
            Operation::ListStreams => (self.basin, Some(resource)),
            _ => unreachable!("collection preflight rejects other operations"),
        };
        Ok(self
            .request
            .authorize(self.operation, basin, stream, now)
            .is_ok())
    }
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, Method};

    use super::*;
    use crate::{
        ClientKey, GrantScope, PkiCredentials, RequestBody, TrustedIssuers, issue_grant,
        restrict_grant, sign_request, verify_request,
    };
    const NOW: i64 = 1_900_000_000;
    fn identity(deep: bool) -> VerifiedRequest {
        let issuer = ClientKey::generate();
        let holder = ClientKey::generate();
        let operations = if deep {
            vec![
                Operation::ListBasins,
                Operation::CreateBasin,
                Operation::DeleteBasin,
                Operation::GetBasinConfig,
                Operation::ReconfigureBasin,
                Operation::ListStreams,
                Operation::CreateStream,
                Operation::DeleteStream,
                Operation::GetStreamConfig,
                Operation::ReconfigureStream,
                Operation::CheckTail,
                Operation::Append,
                Operation::Read,
                Operation::Trim,
                Operation::Fence,
                Operation::AccountMetrics,
                Operation::BasinMetrics,
                Operation::StreamMetrics,
                Operation::ListLocations,
                Operation::GetDefaultLocation,
                Operation::SetDefaultLocation,
            ]
        } else {
            vec![Operation::ListStreams]
        };
        let scope = GrantScope::new(ResourceScope::Any, ResourceScope::None, operations);
        let mut grant = issue_grant(
            &issuer,
            &holder.public_key(),
            "http://localhost",
            &scope,
            NOW + 1000,
        )
        .unwrap();
        if deep {
            for _ in 1..16 {
                grant = restrict_grant(&grant, &holder, &scope, NOW + 1000).unwrap();
            }
        }
        let credentials = PkiCredentials::new(holder, grant).unwrap();
        let uri = "http://localhost/v1/streams".parse().unwrap();
        let mut headers = HeaderMap::new();
        sign_request(
            &credentials,
            &Method::GET,
            &uri,
            &mut headers,
            RequestBody::Unary(b""),
            NOW,
        )
        .unwrap();
        verify_request(
            &TrustedIssuers::new(vec![issuer.public_key()]),
            "http://localhost",
            &Method::GET,
            &uri,
            &headers,
            RequestBody::Unary(b""),
            NOW,
        )
        .unwrap()
    }
    #[test]
    fn denied_candidates_exhaust_the_budget_and_cannot_resume() {
        let request = identity(false);
        let mut auth = request
            .collection_authorizer(Operation::ListStreams, Some("logs"), NOW)
            .unwrap();
        for _ in 0..4096 {
            assert!(!auth.authorize_candidate("denied", NOW).unwrap());
        }
        for _ in 0..2 {
            assert!(matches!(
                auth.authorize_candidate("denied", NOW),
                Err(AuthError::ListWorkLimit)
            ));
        }
    }
    #[test]
    fn expensive_profiles_hit_aggregate_work_limit_before_candidate_limit() {
        let request = identity(true);
        let mut auth = request
            .collection_authorizer(Operation::ListStreams, Some("logs"), NOW)
            .unwrap();
        // Even the worst admitted profile must fit a maximum page + lookahead.
        for _ in 0..1001 {
            assert!(!auth.authorize_candidate("denied", NOW).unwrap());
        }
        let mut exhausted = false;
        for _ in 1001..4096 {
            match auth.authorize_candidate("denied", NOW) {
                Ok(false) => {}
                Err(AuthError::ListWorkLimit) => {
                    exhausted = true;
                    break;
                }
                other => panic!("unexpected candidate result: {other:?}"),
            }
        }
        assert!(
            exhausted,
            "heavy native profiles need a separate aggregate-work bound"
        );
    }
    #[test]
    fn expired_collection_aborts_instead_of_filtering_candidates() {
        let request = identity(false);
        let mut auth = request
            .collection_authorizer(Operation::ListStreams, Some("logs"), NOW)
            .unwrap();
        assert!(!auth.authorize_candidate("denied", NOW).unwrap());
        assert!(matches!(
            auth.authorize_candidate("denied", NOW + 300),
            Err(AuthError::PermissionDenied)
        ));
        assert!(matches!(
            auth.check_active(NOW + 300),
            Err(AuthError::PermissionDenied)
        ));
        assert!(
            request
                .collection_authorizer(Operation::ListStreams, Some("logs"), -1)
                .is_err()
        );
        assert!(
            request
                .collection_authorizer(Operation::Read, Some("logs"), NOW)
                .is_err()
        );
    }
}
