use http::{HeaderMap, HeaderValue, Method, Uri};
use s2_common::access::Operation;
use s2_pki_auth::*;
fn credentials() -> (PkiCredentials, TrustedIssuers) {
    let issuer = ClientKey::generate();
    let client = ClientKey::generate();
    let grant = issue_grant(
        &issuer,
        &client.public_key(),
        "http://localhost",
        &GrantScope::new(
            ResourceScope::Any,
            ResourceScope::Any,
            vec![Operation::Read],
        ),
        2_000_000_000,
    )
    .unwrap();
    (
        PkiCredentials::new(client, grant).unwrap(),
        TrustedIssuers::new(vec![issuer.public_key()]),
    )
}
#[test]
fn signatures_bind_query_basin_body_and_client() {
    let (credentials, issuers) = credentials();
    let uri: Uri = "http://localhost/v1/streams/events/records?start_seq_num=1"
        .parse()
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("s2-basin", HeaderValue::from_static("logs"));
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    sign_request(
        &credentials,
        &Method::GET,
        &uri,
        &mut headers,
        RequestBody::Unary(b"payload"),
        now,
    )
    .unwrap();
    let verify = |uri: &Uri, headers: &HeaderMap, body: &[u8]| {
        verify_request(
            &issuers,
            "http://localhost",
            &Method::GET,
            uri,
            headers,
            RequestBody::Unary(body),
            now,
        )
    };
    assert!(verify(&uri, &headers, b"payload").is_ok());
    assert!(
        verify(
            &"http://localhost/v1/streams/events/records?start_seq_num=2"
                .parse()
                .unwrap(),
            &headers,
            b"payload"
        )
        .is_err()
    );
    assert!(verify(&uri, &headers, b"different").is_err());
    let mut changed = headers.clone();
    changed.insert("s2-basin", HeaderValue::from_static("secrets"));
    assert!(verify(&uri, &changed, b"payload").is_err());
    let mut injected = headers.clone();
    injected.insert("s2-encryption-key", HeaderValue::from_static("injected"));
    assert!(verify(&uri, &injected, b"payload").is_err());
    assert!(
        verify_request(
            &issuers,
            "http://another",
            &Method::GET,
            &uri,
            &headers,
            RequestBody::Unary(b"payload"),
            now
        )
        .is_err()
    );
    assert!(
        verify_request(
            &issuers,
            "http://localhost",
            &Method::GET,
            &uri,
            &headers,
            RequestBody::Unary(b"payload"),
            now + 61
        )
        .is_err()
    );
}
#[test]
fn every_attempt_has_a_new_nonce_and_stream_mode_cannot_replace_unary_digest() {
    let (credentials, issuers) = credentials();
    let uri = "http://localhost/v1/streams/events/records"
        .parse()
        .unwrap();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let mut a = HeaderMap::new();
    let mut b = HeaderMap::new();
    sign_request(
        &credentials,
        &Method::POST,
        &uri,
        &mut a,
        RequestBody::Streaming,
        now,
    )
    .unwrap();
    sign_request(
        &credentials,
        &Method::POST,
        &uri,
        &mut b,
        RequestBody::Streaming,
        now,
    )
    .unwrap();
    assert_ne!(a["signature-input"], b["signature-input"]);
    assert!(
        verify_request(
            &issuers,
            "http://localhost",
            &Method::POST,
            &uri,
            &a,
            RequestBody::Unary(b""),
            now
        )
        .is_err()
    );
    assert!(
        verify_request(
            &issuers,
            "http://localhost",
            &Method::POST,
            &uri,
            &a,
            RequestBody::Streaming,
            now
        )
        .is_ok()
    );
}
#[test]
fn replay_cursor_cannot_be_injected_into_a_signed_read() {
    let (credentials, issuers) = credentials();
    let uri = "http://localhost/v1/streams/events/records"
        .parse()
        .unwrap();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let mut headers = HeaderMap::new();
    sign_request(
        &credentials,
        &Method::GET,
        &uri,
        &mut headers,
        RequestBody::Unary(b""),
        now,
    )
    .unwrap();
    headers.insert("last-event-id", HeaderValue::from_static("100"));
    assert!(
        verify_request(
            &issuers,
            "http://localhost",
            &Method::GET,
            &uri,
            &headers,
            RequestBody::Unary(b""),
            now
        )
        .is_err()
    );
}

#[test]
fn unrecognized_signature_parameters_cannot_be_added_to_a_valid_proof() {
    let (credentials, issuers) = credentials();
    let uri = "http://localhost/v1/streams/events/records"
        .parse()
        .unwrap();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let mut headers = HeaderMap::new();
    sign_request(
        &credentials,
        &Method::GET,
        &uri,
        &mut headers,
        RequestBody::Unary(b""),
        now,
    )
    .unwrap();
    let value = format!(
        "{};unexpected=\"value\"",
        headers["signature-input"].to_str().unwrap()
    );
    headers.insert("signature-input", value.parse().unwrap());
    assert!(
        verify_request(
            &issuers,
            "http://localhost",
            &Method::GET,
            &uri,
            &headers,
            RequestBody::Unary(b""),
            now
        )
        .is_err()
    );
}
