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
fn list_identity(scope: GrantScope, check: &str) -> VerifiedRequest {
    delegated_list_identity(scope.clone(), scope, check)
}
fn delegated_list_identity(
    parent_scope: GrantScope,
    scope: GrantScope,
    check: &str,
) -> VerifiedRequest {
    list_identity_with_custom_ancestor(parent_scope, scope, check, false)
}
fn list_identity_with_custom_ancestor(
    parent_scope: GrantScope,
    scope: GrantScope,
    check: &str,
    custom_in_ancestor: bool,
) -> VerifiedRequest {
    use biscuit_auth::{
        Biscuit, PrivateKey, PublicKey,
        builder::{Algorithm, BlockBuilder},
    };
    let issuer = ClientKey::generate();
    let holder = ClientKey::generate();
    let public = |key: &ClientPublicKey| {
        PublicKey::from_bytes(
            &bs58::decode(key.to_base58()).into_vec().unwrap(),
            Algorithm::Secp256r1,
        )
        .unwrap()
    };
    let root = issue_grant(
        &issuer,
        &holder.public_key(),
        "http://localhost",
        &parent_scope,
        2_000_000_000,
    )
    .unwrap();
    let restricted = restrict_grant(&root, &holder, &scope, 2_000_000_000).unwrap();
    let restricted = Biscuit::from(&*restricted, public(&issuer.public_key())).unwrap();
    let token = Biscuit::from(&*root, public(&issuer.public_key())).unwrap();
    let block = BlockBuilder::new()
        .code(restricted.print_block_source(1).unwrap())
        .unwrap()
        .code(check)
        .unwrap();
    let key = PrivateKey::from_bytes(
        &bs58::decode(holder.to_base58()).into_vec().unwrap(),
        Algorithm::Secp256r1,
    )
    .unwrap();
    let response = token
        .third_party_request()
        .unwrap()
        .create_block(&key, block)
        .unwrap();
    let child = token
        .append_third_party(public(&holder.public_key()), response)
        .unwrap();
    let grant = Grant::from_base64(
        child.to_base64().unwrap().trim_end_matches('='),
        issuer.public_key(),
    )
    .unwrap();
    let grant = if custom_in_ancestor {
        restrict_grant(&grant, &holder, &scope, 2_000_000_000).unwrap()
    } else {
        grant
    };
    let credentials = PkiCredentials::new(holder, grant).unwrap();
    let uri = "http://localhost/v1/basins".parse().unwrap();
    let mut headers = HeaderMap::new();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    sign_request(
        &credentials,
        &Method::GET,
        &uri,
        &mut headers,
        RequestBody::Unary(b""),
        now,
    )
    .unwrap();
    verify_request(
        &TrustedIssuers::new(vec![issuer.public_key()]),
        "http://localhost",
        &Method::GET,
        &uri,
        &headers,
        RequestBody::Unary(b""),
        now,
    )
    .unwrap()
}

// A single durable transaction keeps the fixture deterministic and avoids
// thousands of unrelated provisioning requests/flushes.
async fn list_fixture(hidden: usize, allowed: &[&str]) -> Backend {
    use s2_common::{
        basin::BasinName,
        config::{BasinConfig, OptionalStreamConfig},
        stream::StreamName,
    };
    let backend = backend().await;
    let txn = backend
        .db
        .begin(IsolationLevel::SerializableSnapshot)
        .await
        .unwrap();
    let basin: BasinName = "allowed1".parse().unwrap();
    let now = time::OffsetDateTime::now_utc();
    let basin_meta = super::super::kv::basin_meta::BasinMeta {
        config: BasinConfig::default(),
        created_at: now,
        deleted_at: None,
        creation_idempotency_key: None,
    };
    let stream_meta = super::super::kv::stream_meta::StreamMeta {
        config: super::super::resolve_stream_config(
            OptionalStreamConfig::default(),
            OptionalStreamConfig::default(),
        ),
        cipher: None,
        created_at: now,
        deleted_at: None,
        creation_idempotency_key: None,
    };
    for name in (0..hidden)
        .map(|i| format!("hidden-{i:06}"))
        .chain(allowed.iter().map(|s| s.to_string()))
    {
        let b: BasinName = name.parse().unwrap();
        let st: StreamName = name.parse().unwrap();
        txn.put(
            super::super::kv::basin_meta::ser_key(&b),
            super::super::kv::basin_meta::ser_value(&basin_meta),
        )
        .unwrap();
        txn.put(
            super::super::kv::stream_meta::ser_key(&basin, &st),
            super::super::kv::stream_meta::ser_value(&stream_meta),
        )
        .unwrap();
    }
    db_txn_commit_durable(txn).await.unwrap();
    backend
}

#[tokio::test]
async fn list_basins_broad_custom_policy_is_denied() {
    let backend = list_fixture(4097, &[]).await;
    let scoped = backend.clone().with_pki(Some(list_identity(
        GrantScope::new(
            ResourceScope::Any,
            ResourceScope::Any,
            vec![Operation::ListBasins],
        ),
        "check if basin(\"absent01\");",
    )));
    let error = scoped
        .list_basins(s2_common::basin::ListBasinsRequest {
            limit: 1.into(),
            ..Default::default()
        })
        .await
        .expect_err("broad custom policy must be rejected before scanning");
    assert_generic_policy_error(error.into()).await;
    backend.close().await.unwrap();
}

#[tokio::test]
async fn list_streams_broad_custom_policy_is_denied() {
    let backend = list_fixture(4097, &[]).await;
    let scoped = backend.clone().with_pki(Some(list_identity(
        GrantScope::new(
            ResourceScope::Any,
            ResourceScope::Any,
            vec![Operation::ListStreams],
        ),
        "check if stream(\"absent\");",
    )));
    let error = scoped
        .list_streams(
            "allowed1".parse().unwrap(),
            s2_common::stream::ListStreamsRequest {
                limit: 1.into(),
                ..Default::default()
            },
        )
        .await
        .expect_err("broad custom policy must be rejected before scanning");
    assert_generic_policy_error(error.into()).await;
    backend.close().await.unwrap();
}

async fn list_names(
    backend: &Backend,
    streams: bool,
    prefix: &str,
    start_after: &str,
    limit: usize,
) -> (Vec<String>, bool) {
    if streams {
        let page = backend
            .list_streams(
                "allowed1".parse().unwrap(),
                s2_common::stream::ListStreamsRequest {
                    prefix: prefix.parse().unwrap(),
                    start_after: start_after.parse().unwrap(),
                    limit: limit.into(),
                },
            )
            .await
            .unwrap();
        (
            page.values
                .into_iter()
                .map(|v| v.name.to_string())
                .collect(),
            page.has_more,
        )
    } else {
        let page = backend
            .list_basins(s2_common::basin::ListBasinsRequest {
                prefix: prefix.parse().unwrap(),
                start_after: start_after.parse().unwrap(),
                limit: limit.into(),
            })
            .await
            .unwrap();
        (
            page.values
                .into_iter()
                .map(|v| v.name.to_string())
                .collect(),
            page.has_more,
        )
    }
}
fn list_scope(streams: bool, resource: ResourceScope) -> GrantScope {
    if streams {
        GrantScope::new(ResourceScope::Any, resource, vec![Operation::ListStreams])
    } else {
        GrantScope::new(resource, ResourceScope::Any, vec![Operation::ListBasins])
    }
}
#[tokio::test]
async fn list_unsupported_custom_policy_never_returns_allowed_partial_pages() {
    let backend = list_fixture(4097, &["allowed1"]).await;
    for streams in [false, true] {
        let check = if streams {
            "check if stream(\"allowed1\");"
        } else {
            "check if basin(\"allowed1\");"
        };
        let scoped = backend.clone().with_pki(Some(list_identity(
            list_scope(streams, ResourceScope::Any),
            check,
        )));
        let error = if streams {
            scoped
                .list_streams(
                    "allowed1".parse().unwrap(),
                    s2_common::stream::ListStreamsRequest {
                        limit: 1.into(),
                        ..Default::default()
                    },
                )
                .await
                .unwrap_err()
                .into()
        } else {
            scoped
                .list_basins(s2_common::basin::ListBasinsRequest {
                    limit: 1.into(),
                    ..Default::default()
                })
                .await
                .unwrap_err()
                .into()
        };
        assert_generic_policy_error(error).await;
    }
    backend.close().await.unwrap();
}
#[tokio::test]
async fn list_literal_scope_clips_hidden_ranges_and_preserves_pagination() {
    let backend = list_fixture(4097, &["allowed1", "allowed1-extra", "allowed2"]).await;
    let cases = [
        (
            ResourceScope::Exact("allowed1".into()),
            "",
            "",
            vec!["allowed1"],
            false,
        ),
        (
            ResourceScope::Exact("allowed1".into()),
            "allowed",
            "",
            vec!["allowed1"],
            false,
        ),
        (
            ResourceScope::Exact("allowed1".into()),
            "hidden",
            "",
            vec![],
            false,
        ),
        (
            ResourceScope::Exact("allowed1".into()),
            "",
            "allowed1",
            vec![],
            false,
        ),
        (
            ResourceScope::Exact("absent01".into()),
            "",
            "",
            vec![],
            false,
        ),
        (
            ResourceScope::Prefix("allowed1".into()),
            "",
            "",
            vec!["allowed1"],
            true,
        ),
        (
            ResourceScope::Prefix("allowed1".into()),
            "",
            "allowed1",
            vec!["allowed1-extra"],
            false,
        ),
        (
            ResourceScope::Prefix("allowed".into()),
            "allowed1",
            "allowed1",
            vec!["allowed1-extra"],
            false,
        ),
        (
            ResourceScope::Prefix("allowed".into()),
            "",
            "allowed2",
            vec![],
            false,
        ),
        (
            ResourceScope::Prefix("allowed".into()),
            "hidden",
            "",
            vec![],
            false,
        ),
        (ResourceScope::None, "", "", vec![], false),
        (
            ResourceScope::Prefix("invalid\0prefix".into()),
            "",
            "",
            vec![],
            false,
        ),
    ];
    for streams in [false, true] {
        for (resource, prefix, after, expected, has_more) in &cases {
            let scoped = backend.clone().with_pki(Some(list_identity(
                list_scope(streams, resource.clone()),
                "",
            )));
            let (names, more) = list_names(&scoped, streams, prefix, after, 1).await;
            assert_eq!(
                names, *expected,
                "scope={resource:?} prefix={prefix} after={after}"
            );
            assert_eq!(more, *has_more, "denied candidates must not set has_more");
        }
    }
    backend.close().await.unwrap();
}
#[tokio::test]
async fn list_delegated_scope_is_optimized_but_custom_checks_still_apply() {
    let backend = list_fixture(4097, &["allowed1", "allowed1-extra"]).await;
    for streams in [false, true] {
        let parent = list_scope(streams, ResourceScope::Any);
        let child = list_scope(streams, ResourceScope::Exact("allowed1".into()));
        let check = if streams {
            "check if stream(\"absent\");"
        } else {
            "check if basin(\"absent01\");"
        };
        for (check, expected) in [("", vec!["allowed1"]), (check, vec![])] {
            let scoped = backend.clone().with_pki(Some(delegated_list_identity(
                parent.clone(),
                child.clone(),
                check,
            )));
            let (names, more) = list_names(&scoped, streams, "", "", 1).await;
            assert_eq!(names, expected);
            assert!(!more);
        }
    }
    backend.close().await.unwrap();
}
#[tokio::test]
async fn list_broad_custom_policy_is_rejected_at_every_page_boundary() {
    let backend = list_fixture(8, &[]).await;
    for streams in [false, true] {
        let resource = if streams { "stream" } else { "basin" };
        let check = format!(
            "check if {resource}(\"hidden-000001\") or {resource}(\"hidden-000003\") or {resource}(\"hidden-000005\");"
        );
        let scoped = backend.clone().with_pki(Some(list_identity(
            list_scope(streams, ResourceScope::Any),
            &check,
        )));
        for (prefix, after, limit) in [
            ("", "", 2),
            ("hidden", "hidden-000003", 2),
            ("hidden", "hidden-000005", 1),
            ("absent", "hidden-999999", 1000),
        ] {
            assert_generic_policy_error(
                list_error_with_request(&scoped, streams, prefix, after, limit).await,
            )
            .await;
        }
    }
    backend.close().await.unwrap();
}
#[tokio::test]
async fn list_exact_and_none_custom_denials_return_empty_without_false_more() {
    let backend = list_fixture(4096, &[]).await;
    for streams in [false, true] {
        let check = if streams {
            "check if stream(\"absent\");"
        } else {
            "check if basin(\"absent01\");"
        };
        for resource in [
            ResourceScope::Exact("hidden-000001".into()),
            ResourceScope::None,
        ] {
            let scoped = backend
                .clone()
                .with_pki(Some(list_identity(list_scope(streams, resource), check)));
            assert_eq!(
                list_names(&scoped, streams, "", "", 1).await,
                (vec![], false)
            );
        }
    }
    backend.close().await.unwrap();
}
#[tokio::test]
async fn list_maximum_pages_and_ordinary_mode_keep_their_contract() {
    let backend = list_fixture(1100, &[]).await;
    for streams in [false, true] {
        let scoped = backend.clone().with_pki(Some(list_identity(
            list_scope(streams, ResourceScope::Any),
            "",
        )));
        let (names, more) = list_names(&scoped, streams, "", "", 1000).await;
        assert_eq!(names.len(), 1000);
        assert_eq!(names.first().unwrap(), "hidden-000000");
        assert_eq!(names.last().unwrap(), "hidden-000999");
        assert!(more);
        let (names, more) = list_names(&scoped, streams, "", "hidden-000999", 1000).await;
        assert_eq!(names.len(), 100);
        assert!(!more);
        assert_eq!(
            list_names(&backend, streams, "", "", 1).await,
            (vec!["hidden-000000".into()], true)
        );
    }
    backend.close().await.unwrap();
}

#[tokio::test]
async fn stream_unicode_scope_ranges_preserve_exact_and_prefix_boundaries() {
    use s2_common::stream::StreamName;
    let backend = list_fixture(4097, &["allowed1"]).await;
    let basin = "allowed1".parse().unwrap();
    let template = backend
        .db
        .get(super::super::kv::stream_meta::ser_key(
            &basin,
            &"allowed1".parse().unwrap(),
        ))
        .await
        .unwrap()
        .unwrap();
    let txn = backend
        .db
        .begin(IsolationLevel::SerializableSnapshot)
        .await
        .unwrap();
    for name in ["é/a", "é/ab", "é/b", "ê/a"] {
        let stream: StreamName = name.parse().unwrap();
        txn.put(
            super::super::kv::stream_meta::ser_key(&basin, &stream),
            template.clone(),
        )
        .unwrap();
    }
    db_txn_commit_durable(txn).await.unwrap();
    let exact = backend.clone().with_pki(Some(list_identity(
        list_scope(true, ResourceScope::Exact("é/a".into())),
        "",
    )));
    assert_eq!(
        list_names(&exact, true, "", "", 1).await,
        (vec!["é/a".into()], false)
    );
    assert_eq!(
        list_names(&exact, true, "é/b", "", 1).await,
        (vec![], false)
    );
    let prefix = backend.clone().with_pki(Some(list_identity(
        list_scope(true, ResourceScope::Prefix("é/".into())),
        "",
    )));
    assert_eq!(
        list_names(&prefix, true, "", "", 2).await,
        (vec!["é/a".into(), "é/ab".into()], true)
    );
    assert_eq!(
        list_names(&prefix, true, "", "é/ab", 2).await,
        (vec!["é/b".into()], false)
    );
    backend.close().await.unwrap();
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

// A generic work error is still an oracle if one denied row changes success
// into failure. The policy outcome must be fixed before reading any rows.
async fn custom_policy_error(
    backend: &Backend,
    streams: bool,
) -> crate::handlers::v1::error::ServiceError {
    list_error_with_request(backend, streams, "", "", 1).await
}
async fn list_error_with_request(
    backend: &Backend,
    streams: bool,
    prefix: &str,
    start_after: &str,
    limit: usize,
) -> crate::handlers::v1::error::ServiceError {
    if streams {
        backend
            .list_streams(
                "allowed1".parse().unwrap(),
                s2_common::stream::ListStreamsRequest {
                    prefix: prefix.parse().unwrap(),
                    start_after: start_after.parse().unwrap(),
                    limit: limit.into(),
                },
            )
            .await
            .expect_err("unsupported broad custom policy must be denied before scanning")
            .into()
    } else {
        backend
            .list_basins(s2_common::basin::ListBasinsRequest {
                prefix: prefix.parse().unwrap(),
                start_after: start_after.parse().unwrap(),
                limit: limit.into(),
            })
            .await
            .expect_err("unsupported broad custom policy must be denied before scanning")
            .into()
    }
}
async fn assert_generic_policy_error(error: crate::handlers::v1::error::ServiceError) {
    use axum::{body::to_bytes, response::IntoResponse};
    let response = error.into_response();
    assert_eq!(response.status(), http::StatusCode::FORBIDDEN);
    let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "code": "permission_denied", "message": "Permission denied"
        })
    );
}
#[tokio::test]
async fn list_custom_policy_rejection_does_not_depend_on_denied_rows() {
    for rows in [4096, 4097, 0] {
        let backend = list_fixture(rows, &[]).await;
        for streams in [false, true] {
            for resource in [ResourceScope::Any, ResourceScope::Prefix("hidden".into())] {
                let scope = list_scope(streams, resource);
                let predicate = if streams { "stream" } else { "basin" };
                let resource_check = format!("check if {predicate}(\"absent01\");");
                for check in ["check if false;", resource_check.as_str()] {
                    for ancestor in [false, true] {
                        let scoped =
                            backend
                                .clone()
                                .with_pki(Some(list_identity_with_custom_ancestor(
                                    scope.clone(),
                                    scope.clone(),
                                    check,
                                    ancestor,
                                )));
                        assert_generic_policy_error(custom_policy_error(&scoped, streams).await)
                            .await;
                    }
                }
            }
        }
        backend.close().await.unwrap();
    }
}
#[tokio::test]
async fn list_broad_custom_policy_rejected_before_storage_reads() {
    let backend = backend().await;
    backend.close().await.unwrap();
    for streams in [false, true] {
        for resource in [ResourceScope::Any, ResourceScope::Prefix("hidden".into())] {
            let scope = list_scope(streams, resource);
            for ancestor in [false, true] {
                let identity = list_identity_with_custom_ancestor(
                    scope.clone(),
                    scope.clone(),
                    "check if false;",
                    ancestor,
                );
                let (operation, basin) = if streams {
                    (Operation::ListStreams, Some("allowed1"))
                } else {
                    (Operation::ListBasins, None)
                };
                assert!(
                    matches!(
                        s2_pki_auth::authorize_collection(
                            identity.capability(),
                            operation,
                            basin,
                            time::OffsetDateTime::now_utc().unix_timestamp(),
                        ),
                        Err(AuthError::PermissionDenied)
                    ),
                    "bare shared preflight must enforce the same policy guard"
                );
                let scoped = backend.clone().with_pki(Some(identity));
                assert_generic_policy_error(custom_policy_error(&scoped, streams).await).await;
            }
        }
    }
}

#[tokio::test]
async fn list_work_limit_error_is_generic_and_non_successful() {
    use axum::{body::to_bytes, response::IntoResponse};
    let error = StorageError::from(AuthError::ListWorkLimit);
    let error: crate::handlers::v1::error::ServiceError =
        super::super::error::ListBasinsError::from(error).into();
    let response = error.into_response();
    assert_eq!(response.status(), http::StatusCode::UNPROCESSABLE_ENTITY);
    let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "code": "invalid", "message": "Listing work limit exceeded"
        })
    );
}
