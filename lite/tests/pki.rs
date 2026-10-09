use std::{sync::Arc, time::Duration};

use axum::{
    body::{Body, to_bytes},
    http::{HeaderMap, Method, Request, StatusCode, Uri},
};
use bytesize::ByteSize;
use s2_common::{access::Operation, config::BasinConfig, resources::ProvisionMode};
use s2_pki_auth::*;
use slatedb::{Db, config::Settings, object_store::memory::InMemory};
use tower::ServiceExt;
async fn setup(scope: GrantScope) -> (axum::Router, s2_lite::backend::Backend, PkiCredentials) {
    let db = Db::builder(
        format!("pki-{}", uuid::Uuid::new_v4()),
        Arc::new(InMemory::new()),
    )
    .with_settings(Settings {
        flush_interval: Some(Duration::from_millis(5)),
        ..Default::default()
    })
    .build()
    .await
    .unwrap();
    let backend = s2_lite::backend::Backend::new(db, ByteSize::mib(10));
    for name in ["allowed1", "hidden01"] {
        backend
            .provision_basin(
                name.parse().unwrap(),
                BasinConfig::default(),
                ProvisionMode::Ensure,
            )
            .await
            .unwrap();
    }
    let issuer = ClientKey::generate();
    let key = ClientKey::generate();
    let grant = issue_grant(
        &issuer,
        &key.public_key(),
        "http://localhost",
        &scope,
        2_000_000_000,
    )
    .unwrap();
    let state = s2_lite::pki::PkiAuthState::new(
        backend.clone(),
        TrustedIssuers::new(vec![issuer.public_key()]),
        "http://localhost".into(),
    )
    .unwrap();
    (
        s2_lite::handlers::router_with_pki(state).with_state(backend.clone()),
        backend,
        PkiCredentials::new(key, grant).unwrap(),
    )
}
fn signed(credentials: &PkiCredentials, method: Method, path: &str, body: &str) -> Request<Body> {
    let uri: Uri = format!("http://localhost{path}").parse().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("content-type", "application/json".parse().unwrap());
    sign_request(
        credentials,
        &method,
        &uri,
        &mut headers,
        RequestBody::Unary(body.as_bytes()),
        time::OffsetDateTime::now_utc().unix_timestamp(),
    )
    .unwrap();
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .body(Body::from(body.to_owned()))
        .unwrap();
    *request.headers_mut() = headers;
    request
}
#[tokio::test]
async fn pki_rejects_bearer_replay_and_hidden_resources_and_filters_lists() {
    let (app, backend, credentials) = setup(GrantScope::new(
        ResourceScope::Exact("allowed1".into()),
        ResourceScope::Any,
        vec![Operation::ListBasins, Operation::GetBasinConfig],
    ))
    .await;
    let bearer = Request::builder()
        .uri("/v1/basins")
        .header("authorization", "Bearer arbitrary")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(bearer).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let request = signed(&credentials, Method::GET, "/v1/basins?limit=1", "");
    let headers = request.headers().clone();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(json["basins"].as_array().unwrap().len(), 1);
    assert_eq!(json["basins"][0]["name"], "allowed1");
    assert_eq!(json["has_more"], false);
    let mut replay = Request::builder()
        .uri("/v1/basins?limit=1")
        .body(Body::empty())
        .unwrap();
    *replay.headers_mut() = headers;
    assert_eq!(
        app.clone().oneshot(replay).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.oneshot(signed(&credentials, Method::GET, "/v1/basins/hidden01", ""))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    backend.close().await.unwrap();
}
#[tokio::test]
async fn ensure_requires_reconfigure_for_an_existing_basin() {
    let (app, backend, credentials) = setup(GrantScope::new(
        ResourceScope::Any,
        ResourceScope::Any,
        vec![Operation::CreateBasin],
    ))
    .await;
    assert_eq!(
        app.clone()
            .oneshot(signed(
                &credentials,
                Method::PUT,
                "/v1/basins/new-basin",
                "{}"
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    assert_eq!(
        app.oneshot(signed(
            &credentials,
            Method::PUT,
            "/v1/basins/allowed1",
            "{}"
        ))
        .await
        .unwrap()
        .status(),
        StatusCode::FORBIDDEN
    );
    backend.close().await.unwrap();
}
#[tokio::test]
async fn revoking_a_parent_invalidates_all_delegated_requests() {
    let (_app, backend, _credentials) = setup(GrantScope::new(
        ResourceScope::Any,
        ResourceScope::Any,
        vec![Operation::ListBasins],
    ))
    .await;
    let bob = ClientKey::generate();
    let issuer = ClientKey::generate();
    let holder = ClientKey::generate();
    let root = issue_grant(
        &issuer,
        &holder.public_key(),
        "http://localhost",
        &GrantScope::new(
            ResourceScope::Any,
            ResourceScope::Any,
            vec![Operation::ListBasins],
        ),
        2_000_000_000,
    )
    .unwrap();
    let child = delegate_grant(
        &root,
        &holder,
        &bob.public_key(),
        &GrantScope::new(
            ResourceScope::Any,
            ResourceScope::Any,
            vec![Operation::ListBasins],
        ),
        1_999_999_000,
    )
    .unwrap();
    let state = s2_lite::pki::PkiAuthState::new(
        backend.clone(),
        TrustedIssuers::new(vec![issuer.public_key()]),
        "http://localhost".into(),
    )
    .unwrap();
    let app = s2_lite::handlers::router_with_pki(state).with_state(backend.clone());
    let alice = PkiCredentials::new(holder, root.clone()).unwrap();
    let bob = PkiCredentials::new(bob, child).unwrap();
    assert_eq!(
        app.clone()
            .oneshot(signed(&bob, Method::GET, "/v1/basins", ""))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let payload = serde_json::json!({"grant":root.to_base64()}).to_string();
    let response = app
        .clone()
        .oneshot(signed(
            &alice,
            Method::POST,
            "/v1/pki/revocations",
            &payload,
        ))
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "revocation response: {body:?}"
    );
    assert_eq!(
        app.oneshot(signed(&bob, Method::GET, "/v1/basins", ""))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    backend.close().await.unwrap();
}

#[tokio::test]
async fn sdk_compressed_unary_and_streaming_appends_use_the_same_pki_profile() {
    use s2_sdk::{S2, append_session::AppendSessionConfig, types as sdk};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let audience = format!("http://{}", listener.local_addr().unwrap());
    let (_app, backend, _credentials) = setup(GrantScope::new(
        ResourceScope::Any,
        ResourceScope::Any,
        vec![Operation::Read],
    ))
    .await;
    let issuer = ClientKey::generate();
    let key = ClientKey::generate();
    let scope = GrantScope::new(
        ResourceScope::Any,
        ResourceScope::Any,
        vec![
            Operation::CreateStream,
            Operation::Append,
            Operation::Read,
            Operation::CheckTail,
        ],
    );
    let grant = issue_grant(&issuer, &key.public_key(), &audience, &scope, 2_000_000_000).unwrap();
    let state = s2_lite::pki::PkiAuthState::new(
        backend.clone(),
        TrustedIssuers::new(vec![issuer.public_key()]),
        audience.clone(),
    )
    .unwrap();
    let app = s2_lite::handlers::router_with_pki(state).with_state(backend.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let s2 = S2::new(
        sdk::S2Config::new_pki(PkiCredentials::new(key, grant.clone()).unwrap())
            .with_endpoints(sdk::S2Endpoints::for_endpoint(&audience).unwrap())
            .with_compression(sdk::Compression::Gzip),
    )
    .unwrap();
    let basin = s2.basin("allowed1".parse().unwrap());
    basin
        .create_stream(sdk::CreateStreamInput::new("events".parse().unwrap()))
        .await
        .unwrap();
    let stream = basin.stream("events".parse().unwrap());
    let input = || {
        sdk::AppendInput::new(
            sdk::AppendRecordBatch::try_from_iter([sdk::AppendRecord::new("payload").unwrap()])
                .unwrap(),
        )
    };
    let ack = stream.append(input()).await.unwrap();
    assert_eq!(ack.end.seq_num, 1);
    let session = stream.append_session(AppendSessionConfig::new());
    let ack = session.submit(input()).await.unwrap().await.unwrap();
    assert_eq!(ack.end.seq_num, 2);
    session.close().await.unwrap();
    let records = stream.read(sdk::ReadInput::new()).await.unwrap();
    assert_eq!(records.records.len(), 2);
    s2.revoke_pki_grant(&grant).await.unwrap();
    assert!(stream.check_tail().await.is_err());
    server.abort();
    backend.close().await.unwrap();
}

#[tokio::test]
async fn append_without_create_permission_cannot_implicitly_create_a_stream() {
    use s2_common::{config::BasinReconfiguration, maybe::Maybe};
    let (app, backend, credentials) = setup(GrantScope::new(
        ResourceScope::Any,
        ResourceScope::Any,
        vec![Operation::Append],
    ))
    .await;
    backend
        .reconfigure_basin(
            "allowed1".parse().unwrap(),
            BasinReconfiguration {
                create_stream_on_append: Maybe::Specified(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let uri: Uri = "http://localhost/v1/streams/new-stream/records"
        .parse()
        .unwrap();
    let payload = br#"{"records":[{"body":"cGF5bG9hZA=="}]}"#;
    let mut headers = HeaderMap::new();
    headers.insert("content-type", "application/json".parse().unwrap());
    headers.insert("s2-basin", "allowed1".parse().unwrap());
    sign_request(
        &credentials,
        &Method::POST,
        &uri,
        &mut headers,
        RequestBody::Unary(payload),
        time::OffsetDateTime::now_utc().unix_timestamp(),
    )
    .unwrap();
    let mut request = Request::builder()
        .method(Method::POST)
        .uri("/v1/streams/new-stream/records")
        .body(Body::from(payload.as_slice()))
        .unwrap();
    *request.headers_mut() = headers;
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        backend
            .get_stream_config("allowed1".parse().unwrap(), "new-stream".parse().unwrap())
            .await
            .is_err()
    );
    backend.close().await.unwrap();
}

async fn idle_read_ends(expire: bool) {
    use futures::StreamExt;
    use s2_common::config::OptionalStreamConfig;
    let (_app, backend, _credentials) = setup(GrantScope::new(
        ResourceScope::Any,
        ResourceScope::Any,
        vec![Operation::Read],
    ))
    .await;
    backend
        .provision_stream(
            "allowed1".parse().unwrap(),
            "events".parse().unwrap(),
            OptionalStreamConfig::default(),
            ProvisionMode::CreateOnly {
                request_token: None,
            },
        )
        .await
        .unwrap();
    let issuer = ClientKey::generate();
    let key = ClientKey::generate();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let grant = issue_grant(
        &issuer,
        &key.public_key(),
        "http://localhost",
        &GrantScope::new(
            ResourceScope::Any,
            ResourceScope::Any,
            vec![Operation::Read],
        ),
        if expire { now + 3 } else { 2_000_000_000 },
    )
    .unwrap();
    let trusted = TrustedIssuers::new(vec![issuer.public_key()]);
    let root = verify_biscuit(&grant, &trusted, "http://localhost").unwrap();
    let state =
        s2_lite::pki::PkiAuthState::new(backend.clone(), trusted, "http://localhost".into())
            .unwrap();
    let app = s2_lite::handlers::router_with_pki(state).with_state(backend.clone());
    let credentials = PkiCredentials::new(key, grant).unwrap();
    let uri: Uri = "http://localhost/v1/streams/events/records?seq_num=0"
        .parse()
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("accept", "text/event-stream".parse().unwrap());
    headers.insert("s2-basin", "allowed1".parse().unwrap());
    sign_request(
        &credentials,
        &Method::GET,
        &uri,
        &mut headers,
        RequestBody::Unary(b""),
        now,
    )
    .unwrap();
    let mut request = Request::builder()
        .uri("/v1/streams/events/records?seq_num=0")
        .body(Body::empty())
        .unwrap();
    *request.headers_mut() = headers;
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body().into_data_stream();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), body.next())
            .await
            .unwrap()
            .unwrap()
            .is_ok()
    );
    if !expire {
        backend
            .pki_revoke(&root.revocation_identifiers()[0])
            .await
            .unwrap();
    }
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(item) = body.next().await {
            if item.is_err() {
                return true;
            }
        }
        false
    })
    .await
    .unwrap();
    assert!(
        result,
        "idle read must be cancelled by expired or revoked authorization"
    );
    drop(body);
    backend.close().await.unwrap();
}
#[tokio::test]
async fn idle_read_is_cancelled_when_an_ancestor_is_revoked() {
    idle_read_ends(false).await
}
#[tokio::test]
async fn idle_read_is_cancelled_at_grant_expiry() {
    idle_read_ends(true).await
}

#[tokio::test]
async fn concurrent_replays_accept_exactly_one_request() {
    let (app, backend, credentials) = setup(GrantScope::new(
        ResourceScope::Any,
        ResourceScope::Any,
        vec![Operation::ListBasins],
    ))
    .await;
    let first = signed(&credentials, Method::GET, "/v1/basins", "");
    let mut second = Request::builder()
        .uri("/v1/basins")
        .body(Body::empty())
        .unwrap();
    *second.headers_mut() = first.headers().clone();
    let (a, b) = tokio::join!(app.clone().oneshot(first), app.oneshot(second));
    let mut statuses = [a.unwrap().status().as_u16(), b.unwrap().status().as_u16()];
    statuses.sort();
    assert_eq!(statuses, [200, 401]);
    backend.close().await.unwrap();
}

#[tokio::test]
async fn nonce_and_revocation_state_survive_database_reopen() {
    let storage = Arc::new(InMemory::new());
    let path = format!("pki-restart-{}", uuid::Uuid::new_v4());
    let db = Db::builder(path.clone(), storage.clone())
        .with_settings(Settings {
            flush_interval: Some(Duration::from_millis(5)),
            ..Default::default()
        })
        .build()
        .await
        .unwrap();
    let backend = s2_lite::backend::Backend::new(db, ByteSize::mib(10));
    let issuer = ClientKey::generate();
    let key = ClientKey::generate();
    let trusted = TrustedIssuers::new(vec![issuer.public_key()]);
    let grant = issue_grant(
        &issuer,
        &key.public_key(),
        "http://localhost",
        &GrantScope::new(
            ResourceScope::Any,
            ResourceScope::Any,
            vec![Operation::ListBasins],
        ),
        2_000_000_000,
    )
    .unwrap();
    let capability = verify_biscuit(&grant, &trusted, "http://localhost").unwrap();
    let credentials = PkiCredentials::new(key, grant).unwrap();
    let state = s2_lite::pki::PkiAuthState::new(
        backend.clone(),
        trusted.clone(),
        "http://localhost".into(),
    )
    .unwrap();
    let app = s2_lite::handlers::router_with_pki(state).with_state(backend.clone());
    let request = signed(&credentials, Method::GET, "/v1/basins", "");
    let headers = request.headers().clone();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    backend.close().await.unwrap();
    let db = Db::builder(path.clone(), storage.clone())
        .with_settings(Settings {
            flush_interval: Some(Duration::from_millis(5)),
            ..Default::default()
        })
        .build()
        .await
        .unwrap();
    let backend = s2_lite::backend::Backend::new(db, ByteSize::mib(10));
    let state =
        s2_lite::pki::PkiAuthState::new(backend.clone(), trusted, "http://localhost".into())
            .unwrap();
    let app = s2_lite::handlers::router_with_pki(state).with_state(backend.clone());
    let mut replay = Request::builder()
        .uri("/v1/basins")
        .body(Body::empty())
        .unwrap();
    *replay.headers_mut() = headers;
    assert_eq!(
        app.oneshot(replay).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    backend
        .pki_revoke(&capability.revocation_identifiers()[0])
        .await
        .unwrap();
    backend.close().await.unwrap();
    let db = Db::builder(path, storage).build().await.unwrap();
    let backend = s2_lite::backend::Backend::new(db, ByteSize::mib(10));
    assert!(
        !backend
            .pki_not_revoked(capability.revocation_identifiers())
            .await
            .unwrap()
    );
    backend.close().await.unwrap();
}

fn grant_with_check(
    issuer: &ClientKey,
    holder: &ClientKey,
    audience: &str,
    scope: &GrantScope,
    check: &str,
) -> Grant {
    use biscuit_auth::{
        Biscuit, PrivateKey, PublicKey,
        builder::{Algorithm, BlockBuilder, bytes, fact, int},
    };
    let public = |key: &ClientPublicKey| {
        PublicKey::from_bytes(
            &bs58::decode(key.to_base58()).into_vec().unwrap(),
            Algorithm::Secp256r1,
        )
        .unwrap()
    };
    let root = issue_grant(issuer, &holder.public_key(), audience, scope, 2_000_000_000).unwrap();
    let token = Biscuit::from(&*root, public(&issuer.public_key())).unwrap();
    let payload = serde_json::to_vec(&serde_json::json!({"version":2,"client":holder.public_key(),"audience":audience,"scope":scope,"expires":2_000_000_000i64,"parent":token.revocation_identifiers()[0]})).unwrap();
    let block = BlockBuilder::new()
        .fact(fact("pki_grant", &[int(1), bytes(&payload)]))
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
    Grant::from_base64(
        child.to_base64().unwrap().trim_end_matches('='),
        issuer.public_key(),
    )
    .unwrap()
}
fn checked_app(
    backend: &s2_lite::backend::Backend,
    audience: &str,
    scope: GrantScope,
    check: &str,
) -> (axum::Router, PkiCredentials) {
    let issuer = ClientKey::generate();
    let holder = ClientKey::generate();
    let grant = grant_with_check(&issuer, &holder, audience, &scope, check);
    let state = s2_lite::pki::PkiAuthState::new(
        backend.clone(),
        TrustedIssuers::new(vec![issuer.public_key()]),
        audience.into(),
    )
    .unwrap();
    (
        s2_lite::handlers::router_with_pki(state).with_state(backend.clone()),
        PkiCredentials::new(holder, grant).unwrap(),
    )
}
fn record_request(
    credentials: &PkiCredentials,
    method: Method,
    path: &str,
    payload: Vec<u8>,
    content_type: &str,
    accept: Option<&str>,
    streaming: bool,
) -> Request<Body> {
    let uri: Uri = format!("{}{path}", credentials.audience()).parse().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("s2-basin", "allowed1".parse().unwrap());
    headers.insert("content-type", content_type.parse().unwrap());
    if let Some(accept) = accept {
        headers.insert("accept", accept.parse().unwrap());
    }
    sign_request(
        credentials,
        &method,
        &uri,
        &mut headers,
        if streaming {
            RequestBody::Streaming
        } else {
            RequestBody::Unary(&payload)
        },
        time::OffsetDateTime::now_utc().unix_timestamp(),
    )
    .unwrap();
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .body(Body::from(payload))
        .unwrap();
    *request.headers_mut() = headers;
    request
}
async fn provision_events(backend: &s2_lite::backend::Backend, name: &str) {
    backend
        .provision_stream(
            "allowed1".parse().unwrap(),
            name.parse().unwrap(),
            s2_common::config::OptionalStreamConfig::default(),
            ProvisionMode::CreateOnly {
                request_token: None,
            },
        )
        .await
        .unwrap();
}
#[tokio::test]
async fn review_remote_http_streaming_reads_and_appends_are_rejected() {
    let (_, backend, _) = setup(GrantScope::new(
        ResourceScope::Any,
        ResourceScope::Any,
        vec![Operation::Read],
    ))
    .await;
    provision_events(&backend, "events").await;
    let (app, credentials) = checked_app(
        &backend,
        "http://remote.example",
        GrantScope::new(
            ResourceScope::Any,
            ResourceScope::Any,
            vec![Operation::Read, Operation::Append],
        ),
        "check if true;",
    );
    for (method, content_type, accept, streaming) in [
        (
            Method::GET,
            "application/json",
            Some("text/event-stream"),
            false,
        ),
        (Method::GET, "s2s/proto", None, false),
        (Method::POST, "s2s/proto", None, true),
    ] {
        let response = app
            .clone()
            .oneshot(record_request(
                &credentials,
                method,
                "/v1/streams/events/records",
                vec![],
                content_type,
                accept,
                streaming,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    backend.close().await.unwrap();
}
#[tokio::test]
async fn review_implicit_creation_requires_no_config_read_permission() {
    use s2_common::{config::BasinReconfiguration, maybe::Maybe};
    let (app, backend, credentials) = setup(GrantScope::new(
        ResourceScope::Any,
        ResourceScope::Any,
        vec![Operation::Append, Operation::Read, Operation::CreateStream],
    ))
    .await;
    backend
        .reconfigure_basin(
            "allowed1".parse().unwrap(),
            BasinReconfiguration {
                create_stream_on_append: Maybe::Specified(true),
                create_stream_on_read: Maybe::Specified(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let response = app
        .clone()
        .oneshot(record_request(
            &credentials,
            Method::POST,
            "/v1/streams/auto-append/records",
            br#"{"records":[{"body":"cGF5bG9hZA=="}]}"#.to_vec(),
            "application/json",
            None,
            false,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let response = app
        .oneshot(record_request(
            &credentials,
            Method::GET,
            "/v1/streams/auto-read/records?count=1&wait=0",
            vec![],
            "application/json",
            None,
            false,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    for name in ["auto-append", "auto-read"] {
        assert!(
            backend
                .get_stream_config("allowed1".parse().unwrap(), name.parse().unwrap())
                .await
                .is_ok()
        );
    }
    backend.close().await.unwrap();
}
async fn denied_command_does_not_create(streaming: bool, fence: bool) {
    use prost::Message;
    use s2_api::v1::stream::{
        proto,
        s2s::{CompressionAlgorithm, SessionMessage},
    };
    use s2_common::{config::BasinReconfiguration, maybe::Maybe};
    use s2_sdk::types as sdk;
    let (app, backend, credentials) = setup(GrantScope::new(
        ResourceScope::Any,
        ResourceScope::Any,
        vec![
            Operation::Append,
            Operation::CreateStream,
            Operation::GetBasinConfig,
        ],
    ))
    .await;
    backend
        .reconfigure_basin(
            "allowed1".parse().unwrap(),
            BasinReconfiguration {
                create_stream_on_append: Maybe::Specified(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let command = if fence {
        sdk::CommandRecord::fence("new-fence".parse().unwrap())
    } else {
        sdk::CommandRecord::trim(42)
    };
    let input: proto::AppendInput = sdk::AppendInput::new(
        sdk::AppendRecordBatch::try_from_iter([
            sdk::AppendRecord::new("payload").unwrap(),
            command.into(),
        ])
        .unwrap(),
    )
    .into();
    let payload = if streaming {
        SessionMessage::regular(CompressionAlgorithm::None, &input)
            .unwrap()
            .encode()
            .to_vec()
    } else {
        input.encode_to_vec()
    };
    let response = app
        .oneshot(record_request(
            &credentials,
            Method::POST,
            "/v1/streams/denied-command/records",
            payload,
            if streaming {
                "s2s/proto"
            } else {
                "application/protobuf"
            },
            None,
            streaming,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        if streaming {
            StatusCode::OK
        } else {
            StatusCode::FORBIDDEN
        }
    );
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    assert!(!bytes.is_empty());
    assert!(
        backend
            .get_stream_config(
                "allowed1".parse().unwrap(),
                "denied-command".parse().unwrap()
            )
            .await
            .is_err(),
        "a rejected first batch must not create the stream"
    );
    backend.close().await.unwrap();
}
#[tokio::test]
async fn review_unary_trim_denial_has_no_creation_effect() {
    denied_command_does_not_create(false, false).await
}
#[tokio::test]
async fn review_unary_fence_denial_has_no_creation_effect() {
    denied_command_does_not_create(false, true).await
}
#[tokio::test]
async fn review_streaming_trim_denial_has_no_creation_effect() {
    denied_command_does_not_create(true, false).await
}
#[tokio::test]
async fn review_streaming_fence_denial_has_no_creation_effect() {
    denied_command_does_not_create(true, true).await
}
#[tokio::test]
async fn review_biscuit_resource_checks_filter_lists_before_pagination() {
    let (_, backend, _) = setup(GrantScope::new(
        ResourceScope::Any,
        ResourceScope::Any,
        vec![Operation::ListBasins],
    ))
    .await;
    let (app, credentials) = checked_app(
        &backend,
        "http://localhost",
        GrantScope::new(
            ResourceScope::Any,
            ResourceScope::Any,
            vec![Operation::ListBasins],
        ),
        "check if basin(\"allowed1\");",
    );
    let response = app
        .oneshot(signed(&credentials, Method::GET, "/v1/basins?limit=1", ""))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(json["basins"][0]["name"], "allowed1");
    assert_eq!(json["basins"].as_array().unwrap().len(), 1);
    assert_eq!(json["has_more"], false);
    provision_events(&backend, "events").await;
    provision_events(&backend, "hidden").await;
    for (check, expected) in [
        ("check if stream(\"events\");", 1),
        ("check if stream(\"absent\");", 0),
    ] {
        let (app, credentials) = checked_app(
            &backend,
            "http://localhost",
            GrantScope::new(
                ResourceScope::Any,
                ResourceScope::Any,
                vec![Operation::ListStreams],
            ),
            check,
        );
        let response = app
            .oneshot(record_request(
                &credentials,
                Method::GET,
                "/v1/streams?limit=1",
                vec![],
                "application/json",
                None,
                false,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(json["streams"].as_array().unwrap().len(), expected);
        assert_eq!(json["has_more"], false);
        if expected == 1 {
            assert_eq!(json["streams"][0]["name"], "events");
        }
    }
    backend.close().await.unwrap();
}
#[tokio::test]
async fn review_idle_read_enforces_a_biscuit_time_check() {
    use futures::StreamExt;
    let (_, backend, _) = setup(GrantScope::new(
        ResourceScope::Any,
        ResourceScope::Any,
        vec![Operation::Read],
    ))
    .await;
    provision_events(&backend, "events").await;
    let deadline = time::OffsetDateTime::now_utc().unix_timestamp() + 3;
    let (app, credentials) = checked_app(
        &backend,
        "http://localhost",
        GrantScope::new(
            ResourceScope::Any,
            ResourceScope::Any,
            vec![Operation::Read],
        ),
        &format!("check if time($t), $t < {deadline};"),
    );
    let response = app
        .oneshot(record_request(
            &credentials,
            Method::GET,
            "/v1/streams/events/records?seq_num=0",
            vec![],
            "application/json",
            Some("text/event-stream"),
            false,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body().into_data_stream();
    let ended = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(item) = body.next().await {
            if item.is_err() {
                return true;
            }
        }
        false
    })
    .await;
    assert!(
        matches!(ended, Ok(true)),
        "read must stop at its Biscuit check deadline, before structured expiry"
    );
    drop(body);
    backend.close().await.unwrap();
}
