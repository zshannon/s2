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
    external_block_custom(
        parent,
        holder,
        recipient,
        scope,
        expiry,
        |block| match check {
            Some(check) => block.code(check).unwrap(),
            None => block,
        },
    )
}

fn external_block_custom(
    parent: &Grant,
    holder: &ClientKey,
    recipient: &ClientPublicKey,
    scope: &GrantScope,
    expiry: i64,
    customize: impl FnOnce(biscuit_auth::builder::BlockBuilder) -> biscuit_auth::builder::BlockBuilder,
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
    // Build native facts/checks independently of delegation validation, allowing
    // tests to sign an otherwise well-formed block with widened permissions.
    let template = issue_grant(holder, recipient, "http://localhost", scope, expiry).unwrap();
    let template = Biscuit::from(&*template, public(&holder.public_key())).unwrap();
    let index = token.block_count();
    let mut block = BlockBuilder::new()
        .code(template.print_block_source(0).unwrap())
        .unwrap();
    for f in &mut block.facts {
        f.predicate.terms[0] = int(index as i64);
    }
    for check in &mut block.checks {
        for query in &mut check.queries {
            for predicate in &mut query.body {
                if predicate.name.starts_with("pki_") {
                    predicate.terms[0] = int(index as i64);
                }
            }
        }
    }
    block = block
        .fact(fact(
            "pki_parent",
            &[
                int(index as i64),
                bytes(
                    verify_biscuit(
                        parent,
                        &TrustedIssuers::new(vec![parent.issuer().clone()]),
                        "http://localhost",
                    )
                    .unwrap()
                    .revocation_identifiers()
                    .last()
                    .unwrap(),
                ),
            ],
        ))
        .unwrap();
    let block = customize(block);
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
fn verifier_rejects_widened_facts_even_if_the_holder_signs_them_directly() {
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
fn additional_biscuit_checks_are_evaluated_with_native_scope_checks() {
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

#[test]
fn delegation_cannot_assert_or_derive_server_request_facts() {
    let issuer = ClientKey::generate();
    let alice = ClientKey::generate();
    let bob = ClientKey::generate();
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
    let trusted = TrustedIssuers::new(vec![issuer.public_key()]);
    for injection in [
        "operation(\"Read\");",
        "time(0);",
        "audience(\"http://localhost\");",
        "basin(\"logs\");",
        "stream(\"events\");",
        "basin_present(false);",
        "stream_present(false);",
        "operation(\"Read\") <- true;",
        "time(0) <- true;",
        "pki_operation(1, \"Append\") <- true;",
    ] {
        let child = external_block(
            &root,
            &alice,
            &bob.public_key(),
            &scope,
            1_999_999_000,
            Some(injection),
        );
        assert!(
            matches!(
                verify_biscuit(&child, &trusted, "http://localhost"),
                Err(AuthError::InvalidGrant)
            ),
            "accepted {injection}"
        );
    }
}

#[test]
fn repeated_holder_blocks_cannot_inject_metadata_for_an_earlier_index() {
    let issuer = ClientKey::generate();
    let alice = ClientKey::generate();
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
    let restricted = restrict_grant(&root, &alice, &scope, 1_999_999_000).unwrap();
    let trusted = TrustedIssuers::new(vec![issuer.public_key()]);
    let valid = external_block(
        &restricted,
        &alice,
        &alice.public_key(),
        &scope,
        1_999_998_000,
        None,
    );
    let verified = verify_biscuit(&valid, &trusted, "http://localhost").unwrap();
    assert_eq!(verified.revocation_identifiers().len(), 3);
    assert!(
        authorize_operation(
            &verified,
            Operation::Read,
            Some("logs"),
            Some("events"),
            1_900_000_000
        )
        .is_ok()
    );
    for injection in [
        "pki_expires(1, 2000000000);",
        "pki_operation(0, \"Append\");",
        "pki_expires(2, 2000000000);",
    ] {
        let child = external_block(
            &restricted,
            &alice,
            &alice.public_key(),
            &scope,
            1_999_998_000,
            Some(injection),
        );
        assert!(
            matches!(
                verify_biscuit(&child, &trusted, "http://localhost"),
                Err(AuthError::InvalidGrant)
            ),
            "accepted {injection}"
        );
    }
}

#[test]
fn delegation_must_retain_every_native_profile_check() {
    use biscuit_auth::{
        Biscuit, PrivateKey, PublicKey,
        builder::{Algorithm, BlockBuilder, int, var},
    };
    let issuer = ClientKey::generate();
    let alice = ClientKey::generate();
    let bob = ClientKey::generate();
    let public = |key: &ClientPublicKey| {
        PublicKey::from_bytes(
            &bs58::decode(key.to_base58()).into_vec().unwrap(),
            Algorithm::Secp256r1,
        )
        .unwrap()
    };
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
    let valid = delegate_grant(&root, &alice, &bob.public_key(), &scope, 1_999_999_000).unwrap();
    let token = Biscuit::from(&*root, public(&issuer.public_key())).unwrap();
    let valid = Biscuit::from(&*valid, public(&issuer.public_key())).unwrap();
    let template = BlockBuilder::new()
        .code(valid.print_block_source(1).unwrap())
        .unwrap();
    let key = PrivateKey::from_bytes(
        &bs58::decode(alice.to_base58()).into_vec().unwrap(),
        Algorithm::Secp256r1,
    )
    .unwrap();
    let trusted = TrustedIssuers::new(vec![issuer.public_key()]);
    let verify = |block| {
        let response = token
            .third_party_request()
            .unwrap()
            .create_block(&key, block)
            .unwrap();
        let child = token
            .append_third_party(public(&alice.public_key()), response)
            .unwrap();
        verify_biscuit(&child.to_vec().unwrap(), &trusted, "http://localhost")
    };
    for index in 0..template.checks.len() {
        let mut block = template.clone();
        block.checks.remove(index);
        assert!(matches!(verify(block), Err(AuthError::InvalidGrant)));
    }
    let mut block = template.clone();
    // The printed representation looks identical to the required operation
    // check, but the AST contains just one predicate and a forged variable name.
    // Validation must compare authenticated structure, never formatted source.
    let query = &mut block.checks[0].queries[0];
    query.body.truncate(1);
    query.body[0].terms = vec![var("op), pki_operation(1, $op")];
    assert!(matches!(verify(block), Err(AuthError::InvalidGrant)));
    let mut block = template;
    block.checks[0].queries[0].body[1].terms[0] = int(0);
    assert!(matches!(verify(block), Err(AuthError::InvalidGrant)));
}

fn reject_future_key_scope(kind: &str) {
    use biscuit_auth::{
        PublicKey,
        builder::{Algorithm, Scope},
    };
    let issuer = ClientKey::generate();
    let alice = ClientKey::generate();
    let bob = ClientKey::generate();
    let scope = GrantScope::new(
        ResourceScope::Any,
        ResourceScope::Any,
        vec![Operation::Read],
    );
    let parent = issue_grant(
        &issuer,
        &alice.public_key(),
        "http://localhost",
        &scope,
        2_000_000_000,
    )
    .unwrap();
    let public = PublicKey::from_bytes(
        &bs58::decode(bob.public_key().to_base58())
            .into_vec()
            .unwrap(),
        Algorithm::Secp256r1,
    )
    .unwrap();
    let child = external_block_custom(
        &parent,
        &alice,
        &bob.public_key(),
        &scope,
        1_999_999_000,
        |block| match kind {
            "check" => block
                .code(format!(
                    "check if operation(\"Append\") or override(true) trusting {public};"
                ))
                .unwrap(),
            "global" => block
                .scope(Scope::PublicKey(public))
                .code("check if operation(\"Append\") or override(true);")
                .unwrap(),
            "rule" => block
                .code(format!(
                    "allowed($op) <- operation($op) trusting {public}; check if allowed(\"Read\");"
                ))
                .unwrap(),
            _ => unreachable!(),
        },
    );
    assert!(
        matches!(
            verify_biscuit(
                &child,
                &TrustedIssuers::new(vec![issuer.public_key()]),
                "http://localhost"
            ),
            Err(AuthError::InvalidGrant)
        ),
        "future-resolving {kind} origins must be rejected by the shared profile"
    );
}

#[test]
fn custom_checks_cannot_trust_future_signer_blocks() {
    reject_future_key_scope("check");
}
#[test]
fn global_scopes_cannot_trust_future_signer_blocks() {
    reject_future_key_scope("global");
}
#[test]
fn custom_rules_cannot_trust_future_signer_blocks() {
    reject_future_key_scope("rule");
}

#[test]
fn prefix_scoped_custom_checks_remain_supported() {
    let issuer = ClientKey::generate();
    let alice = ClientKey::generate();
    let bob = ClientKey::generate();
    let scope = GrantScope::new(
        ResourceScope::Any,
        ResourceScope::Any,
        vec![Operation::Read],
    );
    let parent = issue_grant(
        &issuer,
        &alice.public_key(),
        "http://localhost",
        &scope,
        2_000_000_000,
    )
    .unwrap();
    let child = external_block(
        &parent,
        &alice,
        &bob.public_key(),
        &scope,
        1_999_999_000,
        Some("check if pki_operation(0, \"Read\") trusting previous;"),
    );
    let capability = verify_biscuit(
        &child,
        &TrustedIssuers::new(vec![issuer.public_key()]),
        "http://localhost",
    )
    .unwrap();
    authorize_operation(
        &capability,
        Operation::Read,
        Some("logs"),
        Some("events"),
        1_900_000_000,
    )
    .unwrap();
    assert!(
        authorize_operation(
            &capability,
            Operation::Append,
            Some("logs"),
            Some("events"),
            1_900_000_000
        )
        .is_err()
    );
}
