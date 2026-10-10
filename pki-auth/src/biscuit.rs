use std::{ops::Deref, time::Duration};

use base64ct::{Base64UrlUnpadded, Encoding};
use biscuit_auth::{
    AuthorizerLimits, Biscuit,
    builder::{
        AuthorizerBuilder, BiscuitBuilder, BlockBuilder, Check, Convert, Fact, Rule, Scope, Term,
        boolean, bytes, fact, int, string,
    },
    datalog::SymbolTable,
    format::convert::proto_snapshot_block_to_token_block,
};
use s2_common::access::Operation;
use serde::{Deserialize, Serialize};

use crate::{AuthError, ClientKey, ClientPublicKey, Result, TrustedIssuers};

pub const MAX_GRANT_BYTES: usize = 64 * 1024;
pub const MAX_GRANT_BLOCKS: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceScope {
    None,
    Exact(String),
    Prefix(String),
    Any,
}
impl ResourceScope {
    pub fn contains(&self, resource: &str) -> bool {
        match self {
            Self::None => false,
            Self::Exact(s) => s == resource,
            Self::Prefix(s) => resource.starts_with(s),
            Self::Any => true,
        }
    }
    fn subset_of(&self, parent: &Self) -> bool {
        match (self, parent) {
            (Self::None, _) | (_, Self::Any) => true,
            (Self::Exact(v), p) => p.contains(v),
            (Self::Prefix(v), Self::Prefix(p)) => v.starts_with(p),
            _ => self == parent,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantScope {
    pub basins: ResourceScope,
    pub streams: ResourceScope,
    operations: Vec<u8>,
}
impl GrantScope {
    pub fn new(basins: ResourceScope, streams: ResourceScope, operations: Vec<Operation>) -> Self {
        Self {
            basins,
            streams,
            operations: operations.into_iter().map(|o| o as u8).collect(),
        }
    }
    fn subset_of(&self, parent: &Self) -> bool {
        self.basins.subset_of(&parent.basins)
            && self.streams.subset_of(&parent.streams)
            && self
                .operations
                .iter()
                .all(|o| parent.operations.contains(o))
    }
    pub fn permits(&self, operation: Operation) -> bool {
        self.operations.contains(&(operation as u8))
            && !matches!(
                operation,
                Operation::IssueAccessToken
                    | Operation::ListAccessTokens
                    | Operation::RevokeAccessToken
            )
    }
}

#[derive(Clone)]
pub struct Grant {
    bytes: Vec<u8>,
    issuer: ClientPublicKey,
}
impl std::fmt::Debug for Grant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Grant")
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}
impl Deref for Grant {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}
impl Grant {
    pub fn from_base64(value: &str, issuer: ClientPublicKey) -> Result<Self> {
        let bytes = decode_grant(value)?;
        let grant = Self { bytes, issuer };
        verify_biscuit(&grant, &TrustedIssuers::new(vec![grant.issuer.clone()]), "")?;
        Ok(grant)
    }
    pub fn to_base64(&self) -> String {
        Base64UrlUnpadded::encode_string(&self.bytes)
    }
    pub fn issuer(&self) -> &ClientPublicKey {
        &self.issuer
    }
}
// Metadata is read from the literal facts of each authenticated block. It is
// used for identity/delegation validation and inspection, never permission evaluation.
#[derive(Clone, Debug)]
struct BlockMetadata {
    client: ClientPublicKey,
    audience: String,
    scope: GrantScope,
    expires: i64,
    parent: Option<Vec<u8>>,
}
#[derive(Clone)]
pub struct VerifiedCapability {
    issuer: ClientPublicKey,
    holders: Vec<ClientPublicKey>,
    biscuit: Biscuit,
    metadata: BlockMetadata,
    blocks: Vec<BlockBuilder>,
    revocation_ids: Vec<Vec<u8>>,
}
impl std::fmt::Debug for VerifiedCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedCapability")
            .field("client", &self.metadata.client)
            .field("expires", &self.metadata.expires)
            .finish_non_exhaustive()
    }
}
impl VerifiedCapability {
    pub fn client_public_key(&self) -> &ClientPublicKey {
        &self.metadata.client
    }
    pub fn expires_at(&self) -> i64 {
        self.metadata.expires
    }
    pub fn scope(&self) -> &GrantScope {
        &self.metadata.scope
    }
    pub fn audience(&self) -> &str {
        &self.metadata.audience
    }
    /// Stable S2 block IDs: low-S DER for P-256, raw signature bytes for Ed25519.
    pub fn revocation_identifiers(&self) -> &[Vec<u8>] {
        &self.revocation_ids
    }
    /// Native Datalog source of each authenticated block, in delegation order.
    pub fn datalog_blocks(&self) -> Result<Vec<String>> {
        datalog_sources(&self.biscuit)
    }
}
fn limits() -> AuthorizerLimits {
    AuthorizerLimits {
        max_facts: 1000,
        max_iterations: 100,
        max_time: Duration::from_millis(100),
    }
}
// These are the S2 operations available in PKI mode. Token management is excluded.
const OPERATIONS: [Operation; 21] = [
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
];
const ALLOW_POLICY: &str = "allow if operation($op), pki_operation(0, $op) trusting authority;";

fn ambient_predicate(name: &str) -> bool {
    matches!(
        name,
        "time" | "operation" | "audience" | "basin" | "stream" | "basin_present" | "stream_present"
    )
}

// Explicit authority scopes prevent a block-level `trusting previous` or a
// future block signed by the same holder from changing these checks' origins.
// The current block and authorizer are always included by Biscuit.
fn required_checks(index: usize) -> Result<BlockBuilder> {
    let mut block = BlockBuilder::new().code(format!(
        r#"
        check if operation($op), pki_operation({index}, $op) trusting authority;
        check if audience($a), pki_audience({index}, $a) trusting authority;
        check if time($now), pki_expires({index}, $expiry), $now < $expiry trusting authority;
        check if basin_present(false) trusting authority
            or basin($b), pki_basin({index}, "any", "") trusting authority
            or basin($b), pki_basin({index}, "exact", $b) trusting authority
            or basin($b), pki_basin({index}, "prefix", $p), $b.starts_with($p) trusting authority;
        check if stream_present(false) trusting authority
            or stream($s), pki_stream({index}, "any", "") trusting authority
            or stream($s), pki_stream({index}, "exact", $s) trusting authority
            or stream($s), pki_stream({index}, "prefix", $p), $s.starts_with($p) trusting authority;
    "#
    ))?;
    // Normalize parser-only parameter maps for structural comparison with the
    // authenticated AST. These checks contain no substitution parameters.
    for check in &mut block.checks {
        for query in &mut check.queries {
            query.parameters = None;
            query.scope_parameters = None;
        }
    }
    Ok(block)
}

fn scope_terms(scope: &ResourceScope) -> [Term; 2] {
    let (kind, value) = match scope {
        ResourceScope::None => ("none", ""),
        ResourceScope::Any => ("any", ""),
        ResourceScope::Exact(v) => ("exact", v.as_str()),
        ResourceScope::Prefix(v) => ("prefix", v.as_str()),
    };
    [string(kind), string(value)]
}

fn native_block(index: usize, metadata: &BlockMetadata) -> Result<BlockBuilder> {
    let i = int(index as i64);
    let mut block = required_checks(index)?
        .fact(fact("pki_version", &[i.clone(), int(2)]))?
        .fact(fact(
            "pki_holder",
            &[i.clone(), string(metadata.client.to_base58())],
        ))?
        .fact(fact(
            "pki_audience",
            &[i.clone(), string(&metadata.audience)],
        ))?
        .fact(fact("pki_expires", &[i.clone(), int(metadata.expires)]))?;
    for (name, scope) in [
        ("pki_basin", &metadata.scope.basins),
        ("pki_stream", &metadata.scope.streams),
    ] {
        let [kind, value] = scope_terms(scope);
        block = block.fact(fact(name, &[i.clone(), kind, value]))?;
    }
    if metadata.scope.operations.is_empty() {
        return Err(AuthError::InvalidGrant);
    }
    for id in &metadata.scope.operations {
        let operation = OPERATIONS
            .iter()
            .find(|op| **op as u8 == *id)
            .ok_or(AuthError::InvalidGrant)?;
        block = block.fact(fact(
            "pki_operation",
            &[i.clone(), string(&format!("{operation:?}"))],
        ))?;
    }
    if let Some(parent) = &metadata.parent {
        block = block.fact(fact("pki_parent", &[i, bytes(parent)]))?;
    }
    Ok(block)
}

fn one_fact<'a>(block: &'a BlockBuilder, name: &str) -> Result<&'a [Term]> {
    let mut matches = block.facts.iter().filter(|f| f.predicate.name == name);
    let terms = &matches
        .next()
        .ok_or(AuthError::InvalidGrant)?
        .predicate
        .terms;
    if matches.next().is_some() {
        return Err(AuthError::InvalidGrant);
    }
    Ok(&terms[1..])
}
fn read_scope(terms: &[Term]) -> Result<ResourceScope> {
    match terms {
        [Term::Str(kind), Term::Str(value)] => match (kind.as_str(), value.as_str()) {
            ("none", "") => Ok(ResourceScope::None),
            ("any", "") => Ok(ResourceScope::Any),
            ("exact", _) => Ok(ResourceScope::Exact(value.clone())),
            ("prefix", _) => Ok(ResourceScope::Prefix(value.clone())),
            _ => Err(AuthError::InvalidGrant),
        },
        _ => Err(AuthError::InvalidGrant),
    }
}

fn native_world(biscuit: &Biscuit) -> Result<biscuit_auth::format::schema::AuthorizerWorld> {
    Ok(AuthorizerBuilder::new()
        .set_limits(limits())
        .build(biscuit)?
        .snapshot()
        .map_err(biscuit_auth::error::Token::from)?
        .world)
}
fn world_symbols(world: &biscuit_auth::format::schema::AuthorizerWorld) -> Result<SymbolTable> {
    let keys = world
        .public_keys
        .iter()
        .map(biscuit_auth::PublicKey::from_proto)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(biscuit_auth::error::Token::from)?;
    Ok(
        SymbolTable::from_symbols_and_public_keys(world.symbols.clone(), keys)
            .map_err(biscuit_auth::error::Token::from)?,
    )
}
fn datalog_sources(biscuit: &Biscuit) -> Result<Vec<String>> {
    // Escape the display symbol table only. The authorizer and metadata reader
    // always consume the original structured values.
    let mut world = native_world(biscuit)?;
    for symbol in &mut world.symbols {
        *symbol = symbol
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n");
    }
    let symbols = world_symbols(&world)?;
    world
        .blocks
        .iter()
        .map(
            |source| -> std::result::Result<String, biscuit_auth::error::Token> {
                let native = proto_snapshot_block_to_token_block(source)?;
                let mut lines = Vec::new();
                if !native.scopes.is_empty() {
                    let scopes = native
                        .scopes
                        .iter()
                        .map(|s| Scope::convert_from(s, &symbols))
                        .collect::<std::result::Result<Vec<_>, _>>()?;
                    lines.push(format!(
                        "trusting {};",
                        scopes
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                lines.extend(
                    native
                        .facts
                        .iter()
                        .map(|f| format!("{};", symbols.print_fact(f))),
                );
                lines.extend(
                    native
                        .rules
                        .iter()
                        .map(|r| format!("{};", symbols.print_rule(r))),
                );
                lines.extend(
                    native
                        .checks
                        .iter()
                        .map(|c| format!("{};", symbols.print_check(c))),
                );
                Ok(lines.join("\n"))
            },
        )
        .collect::<std::result::Result<_, _>>()
        .map_err(Into::into)
}
fn literal_blocks(biscuit: &Biscuit) -> Result<Vec<BlockBuilder>> {
    // A structured snapshot exposes each block's literal AST without running
    // rules or losing its origin. Never parse print_block_source: display text
    // in biscuit-auth 6 does not escape string values.
    let world = native_world(biscuit)?;
    let symbols = world_symbols(&world)?;
    world
        .blocks
        .iter()
        .map(
            |source| -> std::result::Result<BlockBuilder, biscuit_auth::error::Token> {
                let native = proto_snapshot_block_to_token_block(source)?;
                let mut block = BlockBuilder::new();
                for f in native.facts {
                    block = block.fact(Fact::convert_from(&f, &symbols)?)?;
                }
                for r in native.rules {
                    block = block.rule(Rule::convert_from(&r, &symbols)?)?;
                }
                for c in native.checks {
                    block = block.check(Check::convert_from(&c, &symbols)?)?;
                }
                for scope in native.scopes {
                    block = block.scope(Scope::convert_from(&scope, &symbols)?);
                }
                Ok(block)
            },
        )
        .collect::<std::result::Result<_, _>>()
        .map_err(Into::into)
}

fn read_block(block: &BlockBuilder, index: usize) -> Result<BlockMetadata> {
    for f in &block.facts {
        let name = f.predicate.name.as_str();
        if ambient_predicate(name) {
            return Err(AuthError::InvalidGrant);
        }
        if name.starts_with("pki_")
            && (!matches!(
                name,
                "pki_version"
                    | "pki_holder"
                    | "pki_audience"
                    | "pki_expires"
                    | "pki_basin"
                    | "pki_stream"
                    | "pki_operation"
                    | "pki_parent"
            ) || f.predicate.terms.first() != Some(&int(index as i64)))
        {
            return Err(AuthError::InvalidGrant);
        }
    }
    if block
        .rules
        .iter()
        .any(|r| r.head.name.starts_with("pki_") || ambient_predicate(&r.head.name))
    {
        return Err(AuthError::InvalidGrant);
    }
    if required_checks(index)?
        .checks
        .iter()
        .any(|c| !block.checks.contains(c))
    {
        return Err(AuthError::InvalidGrant);
    }
    if one_fact(block, "pki_version")? != [int(2)] {
        return Err(AuthError::InvalidGrant);
    }
    let [Term::Str(holder)] = one_fact(block, "pki_holder")? else {
        return Err(AuthError::InvalidGrant);
    };
    let client = ClientPublicKey::from_base58(holder)?;
    let [Term::Str(audience)] = one_fact(block, "pki_audience")? else {
        return Err(AuthError::InvalidGrant);
    };
    let [Term::Integer(expires)] = one_fact(block, "pki_expires")? else {
        return Err(AuthError::InvalidGrant);
    };
    if audience.is_empty() || *expires <= 0 {
        return Err(AuthError::InvalidGrant);
    }
    let mut operations = Vec::new();
    for f in block
        .facts
        .iter()
        .filter(|f| f.predicate.name == "pki_operation")
    {
        let [_, Term::Str(name)] = f.predicate.terms.as_slice() else {
            return Err(AuthError::InvalidGrant);
        };
        let op = OPERATIONS
            .iter()
            .find(|op| format!("{op:?}") == *name)
            .ok_or(AuthError::InvalidGrant)?;
        operations.push(*op as u8);
    }
    if operations.is_empty() {
        return Err(AuthError::InvalidGrant);
    }
    let parent = if block.facts.iter().any(|f| f.predicate.name == "pki_parent") {
        let [Term::Bytes(parent)] = one_fact(block, "pki_parent")? else {
            return Err(AuthError::InvalidGrant);
        };
        Some(parent.clone())
    } else {
        None
    };
    let metadata = BlockMetadata {
        client,
        audience: audience.clone(),
        expires: *expires,
        parent,
        scope: GrantScope {
            basins: read_scope(one_fact(block, "pki_basin")?)?,
            streams: read_scope(one_fact(block, "pki_stream")?)?,
            operations,
        },
    };
    Ok(metadata)
}
pub fn decode_grant(value: &str) -> Result<Vec<u8>> {
    if value.len() > MAX_GRANT_BYTES * 2 {
        return Err(AuthError::InvalidGrant);
    }
    Base64UrlUnpadded::decode_vec(value).map_err(|_| AuthError::InvalidGrant)
}
// Biscuit exposes raw internal signature bytes as revocation identifiers.
// ECDSA has two equivalent S representations, so raw DER is not a stable ID.
// Normalize the identifier only; retain the original token bytes for all
// cryptographic chain/third-party verification.
fn revocation_ids(biscuit: &Biscuit) -> Result<Vec<Vec<u8>>> {
    use biscuit_auth::format::schema::public_key::Algorithm;
    let container = biscuit.container().to_proto();
    let mut signer_algorithm = Algorithm::Secp256r1; // TrustedIssuers are P-256 keys.
    let mut identifiers = Vec::with_capacity(biscuit.block_count());
    for block in std::iter::once(&container.authority).chain(&container.blocks) {
        let raw = block.signature.as_slice();
        let identifier = match signer_algorithm {
            Algorithm::Secp256r1 => {
                let signature =
                    p256::ecdsa::Signature::from_der(raw).map_err(|_| AuthError::InvalidGrant)?;
                signature
                    .normalize_s()
                    .unwrap_or(signature)
                    .to_der()
                    .as_bytes()
                    .to_vec()
            }
            Algorithm::Ed25519 => raw.to_vec(),
        };
        identifiers.push(identifier);
        signer_algorithm =
            Algorithm::from_i32(block.next_key.algorithm).ok_or(AuthError::InvalidGrant)?;
    }
    Ok(identifiers)
}
pub fn verify_biscuit(
    encoded: &[u8],
    issuers: &TrustedIssuers,
    audience: &str,
) -> Result<VerifiedCapability> {
    if encoded.len() > MAX_GRANT_BYTES {
        return Err(AuthError::InvalidGrant);
    }
    let (issuer, biscuit) = issuers
        .0
        .iter()
        .find_map(|key| {
            key.biscuit_public()
                .ok()
                .and_then(|pk| Biscuit::from(encoded, pk).ok())
                .map(|biscuit| (key.clone(), biscuit))
        })
        .ok_or(AuthError::UntrustedIssuer)?;
    if biscuit.block_count() > MAX_GRANT_BLOCKS {
        return Err(AuthError::InvalidGrant);
    }
    let blocks = literal_blocks(&biscuit)?;
    let mut current = read_block(&blocks[0], 0)?;
    if current.parent.is_some() || (!audience.is_empty() && current.audience != audience) {
        return Err(AuthError::Audience);
    }
    let ids = revocation_ids(&biscuit)?;
    let mut holders = vec![current.client.clone()];
    for index in 1..biscuit.block_count() {
        let external = biscuit
            .block_external_key(index)?
            .ok_or(AuthError::Delegation)?;
        if external != current.client.biscuit_public()? {
            return Err(AuthError::Delegation);
        }
        let child = read_block(&blocks[index], index)?;
        if child.parent.as_deref() != Some(ids[index - 1].as_slice())
            || child.audience != current.audience
            || child.expires > current.expires
            || !child.scope.subset_of(&current.scope)
        {
            return Err(AuthError::Delegation);
        }
        holders.push(child.client.clone());
        current = child;
    }
    Ok(VerifiedCapability {
        issuer,
        holders,
        biscuit,
        metadata: current,
        blocks,
        revocation_ids: ids,
    })
}
pub fn issue_grant(
    issuer: &ClientKey,
    client: &ClientPublicKey,
    audience: &str,
    scope: &GrantScope,
    expires: i64,
) -> Result<Grant> {
    client.verifying_key()?;
    if audience.is_empty() || expires <= time::OffsetDateTime::now_utc().unix_timestamp() {
        return Err(AuthError::InvalidGrant);
    }
    let metadata = BlockMetadata {
        client: client.clone(),
        audience: audience.into(),
        scope: scope.clone(),
        expires,
        parent: None,
    };
    let biscuit = BiscuitBuilder::new()
        .merge(native_block(0, &metadata)?)
        .build(&issuer.biscuit_keypair()?)?;
    let grant = Grant {
        bytes: biscuit.to_vec()?,
        issuer: issuer.public_key(),
    };
    verify_biscuit(
        &grant,
        &TrustedIssuers::new(vec![grant.issuer.clone()]),
        audience,
    )?;
    Ok(grant)
}
pub fn delegate_grant(
    parent: &Grant,
    delegator: &ClientKey,
    client: &ClientPublicKey,
    scope: &GrantScope,
    expires: i64,
) -> Result<Grant> {
    let verified = verify_biscuit(
        parent,
        &TrustedIssuers::new(vec![parent.issuer.clone()]),
        "",
    )?;
    if delegator.public_key() != *verified.client_public_key()
        || expires > verified.expires_at()
        || expires <= time::OffsetDateTime::now_utc().unix_timestamp()
        || !scope.subset_of(verified.scope())
    {
        return Err(AuthError::Delegation);
    }
    let metadata = BlockMetadata {
        client: client.clone(),
        audience: verified.audience().into(),
        scope: scope.clone(),
        expires,
        parent: verified.revocation_ids.last().cloned(),
    };
    let block = native_block(verified.biscuit.block_count(), &metadata)?;
    let response = verified
        .biscuit
        .third_party_request()?
        .create_block(&delegator.biscuit_private()?, block)?;
    let child = verified
        .biscuit
        .append_third_party(delegator.public_key().biscuit_public()?, response)?;
    let grant = Grant {
        bytes: child.to_vec()?,
        issuer: parent.issuer.clone(),
    };
    verify_biscuit(
        &grant,
        &TrustedIssuers::new(vec![parent.issuer.clone()]),
        verified.audience(),
    )?;
    Ok(grant)
}
/// Evaluate native operation, expiry and known basin checks without checks that need
/// candidate resource facts. Call `authorize_operation` on every candidate before disclosing it.
pub fn authorize_collection(
    capability: &VerifiedCapability,
    operation: Operation,
    basin: Option<&str>,
    now: i64,
) -> Result<()> {
    if !matches!(
        (operation, basin),
        (Operation::ListBasins, None) | (Operation::ListStreams, Some(_))
    ) {
        return Err(AuthError::PermissionDenied);
    }
    // Collection preflight evaluates the signed profile facts and native checks.
    // Additional arbitrary checks need each candidate's resource context and are
    // evaluated by authorize_operation before any row or count is disclosed.
    let mut builder = request_context(capability, operation, basin, None, now)?;
    for (index, block) in capability.blocks.iter().enumerate() {
        for f in block
            .facts
            .iter()
            .filter(|f| f.predicate.name.starts_with("pki_"))
        {
            builder = builder.fact(f.clone())?;
        }
        builder = builder.merge_block(required_checks(index)?);
    }
    builder
        .code(ALLOW_POLICY)?
        .build_unauthenticated()?
        .authorize()?;
    Ok(())
}

fn request_context(
    capability: &VerifiedCapability,
    operation: Operation,
    basin: Option<&str>,
    stream: Option<&str>,
    now: i64,
) -> Result<AuthorizerBuilder> {
    let mut builder = AuthorizerBuilder::new()
        .set_limits(limits())
        .fact(fact("time", &[int(now)]))?
        .fact(fact("operation", &[string(&format!("{operation:?}"))]))?
        .fact(fact("audience", &[string(capability.audience())]))?
        .fact(fact("basin_present", &[boolean(basin.is_some())]))?
        .fact(fact("stream_present", &[boolean(stream.is_some())]))?;
    if let Some(b) = basin {
        builder = builder.fact(fact("basin", &[string(b)]))?;
    }
    if let Some(s) = stream {
        builder = builder.fact(fact("stream", &[string(s)]))?;
    }
    Ok(builder)
}

pub fn authorize_operation(
    capability: &VerifiedCapability,
    operation: Operation,
    basin: Option<&str>,
    stream: Option<&str>,
    now: i64,
) -> Result<()> {
    let basin_required = matches!(
        operation,
        Operation::CreateBasin
            | Operation::DeleteBasin
            | Operation::ReconfigureBasin
            | Operation::GetBasinConfig
            | Operation::ListStreams
            | Operation::CreateStream
            | Operation::DeleteStream
            | Operation::GetStreamConfig
            | Operation::ReconfigureStream
            | Operation::CheckTail
            | Operation::Append
            | Operation::Read
            | Operation::Trim
            | Operation::Fence
            | Operation::BasinMetrics
            | Operation::StreamMetrics
    );
    let stream_required = matches!(
        operation,
        Operation::CreateStream
            | Operation::DeleteStream
            | Operation::GetStreamConfig
            | Operation::ReconfigureStream
            | Operation::CheckTail
            | Operation::Append
            | Operation::Read
            | Operation::Trim
            | Operation::Fence
            | Operation::StreamMetrics
    );
    if (basin_required && basin.is_none()) || (stream_required && stream.is_none()) {
        return Err(AuthError::PermissionDenied);
    }
    request_context(capability, operation, basin, stream, now)?
        .code(ALLOW_POLICY)?
        .build(&capability.biscuit)?
        .authorize()?;
    Ok(())
}

/// Check every command in a batch before any records are appended.
pub fn authorize_append(
    capability: &VerifiedCapability,
    input: &s2_common::stream::AppendInput,
    basin: &str,
    stream: &str,
    now: i64,
) -> Result<()> {
    use s2_common::record::{CommandRecord, Record};
    authorize_operation(
        capability,
        Operation::Append,
        Some(basin),
        Some(stream),
        now,
    )?;
    for record in input.records.iter() {
        let op = match &*record.parts().record {
            Record::Command(CommandRecord::Trim(_)) => Some(Operation::Trim),
            Record::Command(CommandRecord::Fence(_)) => Some(Operation::Fence),
            Record::Envelope(_) => None,
        };
        if let Some(op) = op {
            authorize_operation(capability, op, Some(basin), Some(stream), now)?;
        }
    }
    Ok(())
}

/// A holder may revoke its own grant or a descendant; the issuer may revoke any grant it issued.
/// Return the target block identifier. Its presence in descendants supplies cascading revocation.
pub fn authorize_revocation<'a>(
    actor: &ClientPublicKey,
    target: &'a VerifiedCapability,
) -> Result<&'a [u8]> {
    if actor != &target.issuer && !target.holders.contains(actor) {
        return Err(AuthError::PermissionDenied);
    }
    target
        .revocation_ids
        .last()
        .map(Vec::as_slice)
        .ok_or(AuthError::InvalidGrant)
}
/// Restrict a grant without changing the holder. The holder signs the new block.
pub fn restrict_grant(
    parent: &Grant,
    holder: &ClientKey,
    scope: &GrantScope,
    expires: i64,
) -> Result<Grant> {
    delegate_grant(parent, holder, &holder.public_key(), scope, expires)
}
