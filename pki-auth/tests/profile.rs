use s2_common::access::Operation;
use s2_pki_auth::*;
#[test]
fn unsigned_append_cannot_change_the_holder_even_with_a_valid_biscuit_proof() {
    use biscuit_auth::{Biscuit, builder::BlockBuilder};
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
    let root = biscuit_auth::PublicKey::from_bytes(
        &bs58::decode(issuer.public_key().to_base58())
            .into_vec()
            .unwrap(),
        biscuit_auth::builder::Algorithm::Secp256r1,
    )
    .unwrap();
    let token = Biscuit::from(&*grant, root).unwrap();
    let stolen = token
        .append(BlockBuilder::new().code("unrelated(\"fact\");").unwrap())
        .unwrap();
    assert!(
        verify_biscuit(
            &stolen.to_vec().unwrap(),
            &TrustedIssuers::new(vec![issuer.public_key()]),
            "http://localhost"
        )
        .is_err()
    );
}
#[test]
fn multi_hop_delegation_preserves_all_revocation_ancestors() {
    let issuer = ClientKey::generate();
    let alice = ClientKey::generate();
    let bob = ClientKey::generate();
    let carol = ClientKey::generate();
    let scope = GrantScope::new(
        ResourceScope::Any,
        ResourceScope::Any,
        vec![Operation::Read],
    );
    let root = issue_grant(
        &issuer,
        &alice.public_key(),
        "http://localhost",
        &scope,
        2_000_000_000,
    )
    .unwrap();
    let child = delegate_grant(&root, &alice, &bob.public_key(), &scope, 1_999_999_000).unwrap();
    let leaf = delegate_grant(&child, &bob, &carol.public_key(), &scope, 1_999_998_000).unwrap();
    let trusted = TrustedIssuers::new(vec![issuer.public_key()]);
    let root = verify_biscuit(&root, &trusted, "http://localhost").unwrap();
    let leaf = verify_biscuit(&leaf, &trusted, "http://localhost").unwrap();
    assert_eq!(leaf.revocation_identifiers().len(), 3);
    assert_eq!(
        root.revocation_identifiers()[0],
        leaf.revocation_identifiers()[0]
    );
    assert_eq!(leaf.client_public_key(), &carol.public_key());
}
#[test]
fn only_the_issuer_or_an_ancestor_holder_can_revoke_a_grant() {
    let issuer = ClientKey::generate();
    let alice = ClientKey::generate();
    let bob = ClientKey::generate();
    let stranger = ClientKey::generate();
    let scope = GrantScope::new(
        ResourceScope::Any,
        ResourceScope::Any,
        vec![Operation::Read],
    );
    let trusted = TrustedIssuers::new(vec![issuer.public_key()]);
    let root = issue_grant(
        &issuer,
        &alice.public_key(),
        "http://localhost",
        &scope,
        2_000_000_000,
    )
    .unwrap();
    let child = delegate_grant(&root, &alice, &bob.public_key(), &scope, 1_999_999_000).unwrap();
    let actor = verify_biscuit(&root, &trusted, "http://localhost").unwrap();
    let target = verify_biscuit(&child, &trusted, "http://localhost").unwrap();
    assert_eq!(
        authorize_revocation(actor.client_public_key(), &target).unwrap(),
        target.revocation_identifiers().last().unwrap().as_slice()
    );
    assert!(authorize_revocation(&stranger.public_key(), &target).is_err());
    assert!(authorize_revocation(&bob.public_key(), &actor).is_err());
    assert!(authorize_revocation(&issuer.public_key(), &target).is_ok());
}

fn external_block(
    parent: &Grant,
    holder: &ClientKey,
    recipient: &ClientPublicKey,
    scope: &GrantScope,
    expiry: i64,
    check: Option<&str>,
) -> Vec<u8> {
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
    let token = Biscuit::from(&**parent, public(parent.issuer())).unwrap();
    let payload=serde_json::to_vec(&serde_json::json!({"version":2,"client":recipient,"audience":"http://localhost","scope":scope,"expires":expiry,"parent":token.revocation_identifiers()[0]})).unwrap();
    let mut block = BlockBuilder::new()
        .fact(fact("pki_grant", &[int(1), bytes(&payload)]))
        .unwrap();
    if let Some(check) = check {
        block = block.code(check).unwrap();
    }
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
    token
        .append_third_party(public(&holder.public_key()), response)
        .unwrap()
        .to_vec()
        .unwrap()
}
#[test]
fn verifier_rejects_widened_claims_even_if_the_holder_signs_them_directly() {
    let issuer = ClientKey::generate();
    let alice = ClientKey::generate();
    let bob = ClientKey::generate();
    let scope = GrantScope::new(
        ResourceScope::Exact("logs".into()),
        ResourceScope::Exact("events".into()),
        vec![Operation::Read],
    );
    let root = issue_grant(
        &issuer,
        &alice.public_key(),
        "http://localhost",
        &scope,
        2_000_000_000,
    )
    .unwrap();
    let trusted = TrustedIssuers::new(vec![issuer.public_key()]);
    let broad = GrantScope::new(
        ResourceScope::Any,
        ResourceScope::Any,
        vec![Operation::Read, Operation::Append],
    );
    assert!(
        verify_biscuit(
            &external_block(
                &root,
                &alice,
                &bob.public_key(),
                &broad,
                1_999_999_000,
                None
            ),
            &trusted,
            "http://localhost"
        )
        .is_err()
    );
    assert!(
        verify_biscuit(
            &external_block(
                &root,
                &alice,
                &bob.public_key(),
                &scope,
                2_000_000_001,
                None
            ),
            &trusted,
            "http://localhost"
        )
        .is_err()
    );
}
#[test]
fn signed_biscuit_checks_are_evaluated_in_addition_to_structured_scope() {
    let issuer = ClientKey::generate();
    let alice = ClientKey::generate();
    let bob = ClientKey::generate();
    let scope = GrantScope::new(
        ResourceScope::Any,
        ResourceScope::Any,
        vec![Operation::Read, Operation::Append],
    );
    let root = issue_grant(
        &issuer,
        &alice.public_key(),
        "http://localhost",
        &scope,
        2_000_000_000,
    )
    .unwrap();
    let trusted = TrustedIssuers::new(vec![issuer.public_key()]);
    let child = external_block(
        &root,
        &alice,
        &bob.public_key(),
        &scope,
        1_999_999_000,
        Some("check if operation(\"Append\");"),
    );
    let capability = verify_biscuit(&child, &trusted, "http://localhost").unwrap();
    assert!(
        authorize_operation(
            &capability,
            Operation::Read,
            Some("logs"),
            Some("events"),
            1_900_000_000
        )
        .is_err()
    );
    assert!(
        authorize_operation(
            &capability,
            Operation::Append,
            Some("logs"),
            Some("events"),
            1_900_000_000
        )
        .is_ok()
    );
}
