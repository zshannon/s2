use biscuit_auth::{
    Biscuit, PublicKey,
    builder::{Algorithm, AuthorizerBuilder, boolean, fact, int, string},
};
use s2_pki_auth::*;

fn token(grant: &Grant) -> Biscuit {
    let key = PublicKey::from_bytes(
        &bs58::decode(grant.issuer().to_base58()).into_vec().unwrap(),
        Algorithm::Secp256r1,
    )
    .unwrap();
    Biscuit::from(&**grant, key).unwrap()
}

// This deliberately uses Biscuit directly, without S2's permission evaluator:
// the issued token itself must carry enforceable native authorization policy.
fn native_authorize(
    token: &Biscuit,
    operation: &str,
    basin: &str,
    stream: &str,
    audience: &str,
    now: i64,
) -> bool {
    AuthorizerBuilder::new()
        .fact(fact("operation", &[string(operation)]))
        .unwrap()
        .fact(fact("basin", &[string(basin)]))
        .unwrap()
        .fact(fact("stream", &[string(stream)]))
        .unwrap()
        .fact(fact("basin_present", &[boolean(true)]))
        .unwrap()
        .fact(fact("stream_present", &[boolean(true)]))
        .unwrap()
        .fact(fact("audience", &[string(audience)]))
        .unwrap()
        .fact(fact("time", &[int(now)]))
        .unwrap()
        .code("allow if operation($op), pki_operation(0, $op) trusting authority;")
        .unwrap()
        .build(token)
        .unwrap()
        .authorize()
        .is_ok()
}

#[test]
fn issued_permissions_are_enforced_by_native_biscuit_alone() {
    let issuer = ClientKey::generate();
    let alice = ClientKey::generate();
    let grant = issue_grant(
        &issuer,
        &alice.public_key(),
        "http://localhost",
        &GrantScope::new(
            ResourceScope::Exact("logs".into()),
            ResourceScope::Prefix("events/".into()),
            vec![Operation::Read],
        ),
        2_000_000_000,
    )
    .unwrap();
    let token = token(&grant);
    assert!(native_authorize(
        &token,
        "Read",
        "logs",
        "events/one",
        "http://localhost",
        1_900_000_000
    ));
    for (op, basin, stream, audience, now) in [
        (
            "Append",
            "logs",
            "events/one",
            "http://localhost",
            1_900_000_000,
        ),
        (
            "Read",
            "private",
            "events/one",
            "http://localhost",
            1_900_000_000,
        ),
        (
            "Read",
            "logs",
            "private/one",
            "http://localhost",
            1_900_000_000,
        ),
        (
            "Read",
            "logs",
            "events/one",
            "http://elsewhere",
            1_900_000_000,
        ),
        (
            "Read",
            "logs",
            "events/one",
            "http://localhost",
            2_000_000_000,
        ),
    ] {
        assert!(!native_authorize(&token, op, basin, stream, audience, now));
    }
}

#[test]
fn native_delegation_checks_narrow_the_authority_grant() {
    let issuer = ClientKey::generate();
    let alice = ClientKey::generate();
    let bob = ClientKey::generate();
    let broad = GrantScope::new(
        ResourceScope::Any,
        ResourceScope::Any,
        vec![Operation::Read, Operation::Append],
    );
    let narrow = GrantScope::new(
        ResourceScope::Exact("logs".into()),
        ResourceScope::Exact("events".into()),
        vec![Operation::Read],
    );
    let parent = issue_grant(
        &issuer,
        &alice.public_key(),
        "http://localhost",
        &broad,
        2_000_000_000,
    )
    .unwrap();
    let child = delegate_grant(&parent, &alice, &bob.public_key(), &narrow, 1_999_999_000).unwrap();
    let token = token(&child);
    assert!(native_authorize(
        &token,
        "Read",
        "logs",
        "events",
        "http://localhost",
        1_900_000_000
    ));
    assert!(!native_authorize(
        &token,
        "Append",
        "logs",
        "events",
        "http://localhost",
        1_900_000_000
    ));
    assert!(!native_authorize(
        &token,
        "Read",
        "logs",
        "other",
        "http://localhost",
        1_900_000_000
    ));
    assert!(!native_authorize(
        &token,
        "Read",
        "logs",
        "events",
        "http://localhost",
        1_999_999_000
    ));
}

#[test]
fn native_scope_values_round_trip_as_literals_without_source_interpretation() {
    let issuer = ClientKey::generate();
    let alice = ClientKey::generate();
    let name = "events/\"quoted\"\\path\nline";
    let grant = issue_grant(
        &issuer,
        &alice.public_key(),
        "http://localhost",
        &GrantScope::new(
            ResourceScope::Exact("logs".into()),
            ResourceScope::Exact(name.into()),
            vec![Operation::Read],
        ),
        2_000_000_000,
    )
    .unwrap();
    let capability = verify_biscuit(
        &grant,
        &TrustedIssuers::new(vec![issuer.public_key()]),
        "http://localhost",
    )
    .unwrap();
    assert_eq!(
        capability.scope().streams,
        ResourceScope::Exact(name.into())
    );
    let sources = capability.datalog_blocks().unwrap();
    let displayed = biscuit_auth::builder::BlockBuilder::new()
        .code(&sources[0])
        .unwrap();
    let stream = displayed
        .facts
        .iter()
        .find(|f| f.predicate.name == "pki_stream")
        .unwrap();
    assert_eq!(stream.predicate.terms[2], string(name));
    assert!(
        authorize_operation(
            &capability,
            Operation::Read,
            Some("logs"),
            Some(name),
            1_900_000_000
        )
        .is_ok()
    );
    assert!(
        authorize_operation(
            &capability,
            Operation::Read,
            Some("logs"),
            Some("events/quoted"),
            1_900_000_000
        )
        .is_err()
    );
}

#[test]
fn equivalent_p256_authority_signatures_keep_the_same_revocation_identity() {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use prost::Message;
    let issuer = ClientKey::generate();
    let alice = ClientKey::generate();
    let bob = ClientKey::generate();
    let scope = GrantScope::new(
        ResourceScope::Any,
        ResourceScope::Any,
        vec![Operation::Read],
    );
    let grant = issue_grant(
        &issuer,
        &alice.public_key(),
        "http://localhost",
        &scope,
        2_000_000_000,
    )
    .unwrap();
    let mut encoded = biscuit_auth::format::schema::Biscuit::decode(&*grant).unwrap();
    let signature = p256::ecdsa::Signature::from_der(&encoded.authority.signature).unwrap();
    let (r, s) = signature.split_scalars();
    let alternate = p256::ecdsa::Signature::from_scalars(r.to_bytes(), (-s).to_bytes()).unwrap();
    encoded.authority.signature = alternate.to_der().as_bytes().to_vec();
    let alternate = Grant::from_base64(
        &Base64UrlUnpadded::encode_string(&encoded.encode_to_vec()),
        issuer.public_key(),
    )
    .unwrap();
    let trusted = TrustedIssuers::new(vec![issuer.public_key()]);
    let original = verify_biscuit(&grant, &trusted, "http://localhost").unwrap();
    let changed = verify_biscuit(&alternate, &trusted, "http://localhost").unwrap();
    assert_eq!(
        original.revocation_identifiers(),
        changed.revocation_identifiers(),
        "equivalent ECDSA encodings must not evade a stored revocation"
    );
    for parent in [&grant, &alternate] {
        let child =
            delegate_grant(parent, &alice, &bob.public_key(), &scope, 1_999_999_000).unwrap();
        let child = verify_biscuit(&child, &trusted, "http://localhost").unwrap();
        assert_eq!(
            child.revocation_identifiers()[0],
            original.revocation_identifiers()[0]
        );
    }
}
