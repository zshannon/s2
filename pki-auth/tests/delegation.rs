use s2_common::access::Operation;
use s2_pki_auth::{
    ClientKey, GrantScope, ResourceScope, TrustedIssuers, authorize_append, authorize_operation,
    delegate_grant, issue_grant, verify_biscuit,
};

#[test]
fn alice_must_sign_delegation_and_bob_can_only_read_granted_stream() {
    let issuer = ClientKey::generate();
    let alice = ClientKey::generate();
    let bob = ClientKey::generate();
    let scope = GrantScope::new(
        ResourceScope::Exact("logs".into()),
        ResourceScope::Prefix("events/".into()),
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
    let child = delegate_grant(&grant, &alice, &bob.public_key(), &scope, 1_999_999_000).unwrap();
    let verified = verify_biscuit(
        &child,
        &TrustedIssuers::new(vec![issuer.public_key()]),
        "http://localhost",
    )
    .unwrap();
    assert_eq!(verified.client_public_key(), &bob.public_key());
    assert!(
        authorize_operation(
            &verified,
            Operation::Read,
            Some("logs"),
            Some("events/one"),
            1_900_000_000
        )
        .is_ok()
    );
    assert!(
        authorize_operation(
            &verified,
            Operation::Append,
            Some("logs"),
            Some("events/one"),
            1_900_000_000
        )
        .is_err()
    );
    assert!(
        authorize_operation(
            &verified,
            Operation::Read,
            Some("logs"),
            Some("private/one"),
            1_900_000_000
        )
        .is_err()
    );
    assert!(delegate_grant(&grant, &bob, &bob.public_key(), &scope, 1_999_999_000).is_err());
}

#[test]
fn delegation_cannot_widen_scope_or_expiry() {
    let issuer = ClientKey::generate();
    let alice = ClientKey::generate();
    let bob = ClientKey::generate();
    let scope = GrantScope::new(
        ResourceScope::Exact("logs".into()),
        ResourceScope::Exact("events".into()),
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
    let wider = GrantScope::new(
        ResourceScope::Any,
        ResourceScope::Any,
        vec![Operation::Read, Operation::Append],
    );
    assert!(delegate_grant(&grant, &alice, &bob.public_key(), &wider, 1_999_999_000).is_err());
    assert!(delegate_grant(&grant, &alice, &bob.public_key(), &scope, 2_000_000_001).is_err());
}
#[test]
fn append_does_not_authorize_trim_or_fence_commands() {
    use s2_common::{
        record::{CommandRecord, Metered, Record},
        stream::{AppendInput, AppendRecord, AppendRecordBatch, AppendRecordParts},
    };
    let issuer = ClientKey::generate();
    let alice = ClientKey::generate();
    let grant = issue_grant(
        &issuer,
        &alice.public_key(),
        "http://localhost",
        &GrantScope::new(
            ResourceScope::Any,
            ResourceScope::Any,
            vec![Operation::Append],
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
    let record = AppendRecord::try_from(AppendRecordParts {
        timestamp: None,
        record: Metered::from(Record::Command(CommandRecord::Trim(42))),
    })
    .unwrap();
    let input = AppendInput {
        records: AppendRecordBatch::try_from(vec![record]).unwrap(),
        match_seq_num: None,
        fencing_token: None,
    };
    assert!(authorize_append(&capability, &input, "logs", "events", 1_900_000_000).is_err());
}
#[test]
fn stream_authorization_requires_a_basin_and_stream() {
    let issuer = ClientKey::generate();
    let alice = ClientKey::generate();
    let grant = issue_grant(
        &issuer,
        &alice.public_key(),
        "http://localhost",
        &GrantScope::new(
            ResourceScope::Any,
            ResourceScope::Any,
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
    assert!(authorize_operation(&capability, Operation::Read, None, None, 1_900_000_000).is_err());
    assert!(
        authorize_operation(
            &capability,
            Operation::Read,
            Some("logs"),
            None,
            1_900_000_000
        )
        .is_err()
    );
}
