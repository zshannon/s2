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

fn budgeted_child(source: &str) -> (Vec<u8>, TrustedIssuers) {
    let issuer = ClientKey::generate();
    let holder = ClientKey::generate();
    let scope = GrantScope::new(
        ResourceScope::Any,
        ResourceScope::Any,
        vec![Operation::Read],
    );
    let parent = issue_grant(
        &issuer,
        &holder.public_key(),
        "http://localhost",
        &scope,
        2_000_000_000,
    )
    .unwrap();
    let child = external_block(
        &parent,
        &holder,
        &holder.public_key(),
        &scope,
        1_999_999_000,
        Some(source),
    );
    (child, TrustedIssuers::new(vec![issuer.public_key()]))
}
fn assert_policy_rejected(source: &str) {
    let (child, trusted) = budgeted_child(source);
    assert!(
        matches!(
            verify_biscuit(&child, &trusted, "http://localhost"),
            Err(AuthError::InvalidGrant)
        ),
        "unbounded custom policy must be rejected before native evaluation"
    );
}
#[test]
fn resource_budget_rejects_custom_fact_generation() {
    assert_policy_rejected(
        "item(0); item(1); pair($a, $b) <- item($a), item($b); check if pair(0, 1);",
    );
}
#[test]
fn resource_budget_rejects_custom_query_cartesian_products() {
    assert_policy_rejected("item(0); item(1); check if item($a), item($b), $a > $b;");
}
#[test]
fn resource_budget_rejects_expanding_string_expressions() {
    assert_policy_rejected("check if stream($s), ($s + $s).length() > 0;");
}
#[test]
fn resource_budget_rejects_custom_regex_evaluation() {
    assert_policy_rejected("check if stream($s), $s.matches(\"^events$\");");
}
#[test]
fn resource_budget_rejects_excess_literal_facts() {
    let facts = (0..520).map(|i| format!("item({i});")).collect::<String>();
    assert_policy_rejected(&facts);
}
#[test]
fn resource_budget_rejects_excess_custom_queries() {
    assert_policy_rejected(&"check if operation(\"Read\");".repeat(65));
}
#[test]
fn resource_budget_rejects_excess_linear_query_work() {
    let mut source = (0..200).map(|i| format!("item({i});")).collect::<String>();
    source.push_str(&"check if item($v), $v >= 0;".repeat(16));
    assert_policy_rejected(&source);
}
#[test]
fn bounded_custom_native_checks_preserve_resource_and_time_restrictions() {
    let (child, trusted) = budgeted_child(
        "item(\"events/\"); check all item($v), $v == \"events/\"; check if stream($s), $s.starts_with(\"events/\"); check if time($t), $t < 1950000000; reject if operation(\"Append\");",
    );
    let capability = verify_biscuit(&child, &trusted, "http://localhost").unwrap();
    authorize_operation(
        &capability,
        Operation::Read,
        Some("logs"),
        Some("events/one"),
        1_900_000_000,
    )
    .unwrap();
    for (operation, stream, now) in [
        (Operation::Read, "private/one", 1_900_000_000),
        (Operation::Read, "events/one", 1_950_000_000),
        (Operation::Append, "events/one", 1_900_000_000),
    ] {
        assert!(
            authorize_operation(&capability, operation, Some("logs"), Some(stream), now).is_err()
        );
    }
}
#[test]
fn resource_budget_rejects_collection_values() {
    assert_policy_rejected("item([1, 2]); check if true;");
}
#[test]
fn resource_budget_rejects_large_scalar_values() {
    assert_policy_rejected(&format!("item(\"{}\");", "x".repeat(1025)));
}
#[test]
fn resource_budget_rejects_wide_predicates() {
    assert_policy_rejected("item(0, 1, 2, 3, 4, 5, 6, 7, 8);");
}
#[test]
fn resource_budget_rejects_duplicate_native_checks() {
    assert_policy_rejected("check if operation($op), pki_operation(1, $op) trusting authority;");
}
#[test]
fn resource_budget_rejects_empty_custom_checks() {
    use biscuit_auth::builder::{Check, CheckKind};
    let issuer = ClientKey::generate();
    let holder = ClientKey::generate();
    let scope = GrantScope::new(
        ResourceScope::Any,
        ResourceScope::Any,
        vec![Operation::Read],
    );
    let parent = issue_grant(
        &issuer,
        &holder.public_key(),
        "http://localhost",
        &scope,
        2_000_000_000,
    )
    .unwrap();
    let child = external_block_custom(
        &parent,
        &holder,
        &holder.public_key(),
        &scope,
        1_999_999_000,
        |block| {
            block
                .check(Check {
                    queries: vec![],
                    kind: CheckKind::One,
                })
                .unwrap()
        },
    );
    assert!(matches!(
        verify_biscuit(
            &child,
            &TrustedIssuers::new(vec![issuer.public_key()]),
            "http://localhost"
        ),
        Err(AuthError::InvalidGrant)
    ));
}
#[test]
fn full_length_native_delegation_chain_fits_the_resource_budget() {
    let issuer = ClientKey::generate();
    let holder = ClientKey::generate();
    let scope = GrantScope::new(
        ResourceScope::Any,
        ResourceScope::Any,
        vec![
            Operation::ListBasins,
            Operation::CreateBasin,
            Operation::DeleteBasin,
            Operation::ReconfigureBasin,
            Operation::GetBasinConfig,
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
        ],
    );
    let mut grant = issue_grant(
        &issuer,
        &holder.public_key(),
        "http://localhost",
        &scope,
        2_000_000_000,
    )
    .unwrap();
    for index in 1..MAX_GRANT_BLOCKS {
        grant = restrict_grant(&grant, &holder, &scope, 2_000_000_000 - index as i64).unwrap();
    }
    let capability = verify_biscuit(
        &grant,
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
}

#[test]
fn resource_budget_rejects_excess_preconversion_items() {
    // Each literal remains individually small and the fact count stays below
    // 512, but expanding all its references exceeds the aggregate raw budget.
    let source = (0..450)
        .map(|i| format!("item({i}, \"x\", \"x\", \"x\", \"x\", \"x\", \"x\", \"x\");"))
        .collect::<String>();
    assert_policy_rejected(&source);
}

#[test]
fn collection_preflight_rejects_all_broad_custom_check_kinds() {
    let issuer = ClientKey::generate();
    let holder = ClientKey::generate();
    let trusted = TrustedIssuers::new(vec![issuer.public_key()]);
    for operation in [Operation::ListBasins, Operation::ListStreams] {
        for resource in [
            ResourceScope::Any,
            ResourceScope::Prefix("allowed".into()),
            ResourceScope::Exact("allowed1".into()),
            ResourceScope::None,
        ] {
            let broad = matches!(resource, ResourceScope::Any | ResourceScope::Prefix(_));
            let scope = if operation == Operation::ListBasins {
                GrantScope::new(resource, ResourceScope::Any, vec![operation])
            } else {
                GrantScope::new(ResourceScope::Any, resource, vec![operation])
            };
            let root = issue_grant(
                &issuer,
                &holder.public_key(),
                "http://localhost",
                &scope,
                2_000_000_000,
            )
            .unwrap();
            for check in [
                "check if false;",
                "check if true;",
                "check all time($t), $t > 0;",
                "reject if operation(\"Read\");",
            ] {
                let child = external_block(
                    &root,
                    &holder,
                    &holder.public_key(),
                    &scope,
                    1_999_999_000,
                    Some(check),
                );
                let capability = verify_biscuit(&child, &trusted, "http://localhost").unwrap();
                let basin = (operation == Operation::ListStreams).then_some("allowed1");
                let result = authorize_collection(&capability, operation, basin, 1_900_000_000);
                if broad {
                    assert!(
                        matches!(result, Err(AuthError::PermissionDenied)),
                        "all additional native check kinds must fail broad preflight"
                    );
                } else {
                    result.unwrap();
                    if check == "check if false;" {
                        assert!(
                            authorize_operation(
                                &capability,
                                operation,
                                Some("allowed1"),
                                (operation == Operation::ListStreams).then_some("allowed1"),
                                1_900_000_000,
                            )
                            .is_err(),
                            "retaining exact preflight must not bypass a native custom denial"
                        );
                    }
                }
            }
        }
    }
}
