use std::{ops::Deref, time::Duration};

use base64ct::{Base64UrlUnpadded, Encoding};
use biscuit_auth::{
    AuthorizerLimits, Biscuit,
    builder::{AuthorizerBuilder, BiscuitBuilder, BlockBuilder, bytes, fact, int, string},
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
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    version: u8,
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
    claims: Claims,
    revocation_ids: Vec<Vec<u8>>,
}
impl std::fmt::Debug for VerifiedCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedCapability")
            .field("client", &self.claims.client)
            .field("expires", &self.claims.expires)
            .finish_non_exhaustive()
    }
}
impl VerifiedCapability {
    pub fn client_public_key(&self) -> &ClientPublicKey {
        &self.claims.client
    }
    pub fn expires_at(&self) -> i64 {
        self.claims.expires
    }
    pub fn scope(&self) -> &GrantScope {
        &self.claims.scope
    }
    pub fn audience(&self) -> &str {
        &self.claims.audience
    }
    pub fn revocation_identifiers(&self) -> &[Vec<u8>] {
        &self.revocation_ids
    }
}
fn limits() -> AuthorizerLimits {
    AuthorizerLimits {
        max_facts: 1000,
        max_iterations: 100,
        max_time: Duration::from_millis(100),
    }
}
fn claims(biscuit: &Biscuit, index: usize, origin: &str) -> Result<Claims> {
    let mut a = AuthorizerBuilder::new()
        .set_limits(limits())
        .build(biscuit)?;
    let query = format!("data($p) <- pki_grant({index}, $p) trusting {origin}");
    let (data,): (Vec<u8>,) = a.query_exactly_one(query.as_str())?;
    let claims: Claims = serde_json::from_slice(&data)?;
    if claims.version != 2
        || claims.expires <= 0
        || claims.scope.operations.is_empty()
        || claims
            .scope
            .operations
            .iter()
            .any(|o| *o == 0 || *o > 24 || [6, 7, 8].contains(o))
    {
        return Err(AuthError::InvalidGrant);
    }
    claims.client.verifying_key()?;
    Ok(claims)
}
pub fn decode_grant(value: &str) -> Result<Vec<u8>> {
    if value.len() > MAX_GRANT_BYTES * 2 {
        return Err(AuthError::InvalidGrant);
    }
    Base64UrlUnpadded::decode_vec(value).map_err(|_| AuthError::InvalidGrant)
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
    let mut current = claims(&biscuit, 0, "authority")?;
    if current.parent.is_some() || (!audience.is_empty() && current.audience != audience) {
        return Err(AuthError::Audience);
    }
    let ids = biscuit.revocation_identifiers();
    let mut holders = vec![current.client.clone()];
    for index in 1..biscuit.block_count() {
        let external = biscuit
            .block_external_key(index)?
            .ok_or(AuthError::Delegation)?;
        if external != current.client.biscuit_public()? {
            return Err(AuthError::Delegation);
        }
        let child = claims(&biscuit, index, &external.print())?;
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
        claims: current,
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
    let claims = Claims {
        version: 2,
        client: client.clone(),
        audience: audience.into(),
        scope: scope.clone(),
        expires,
        parent: None,
    };
    let biscuit = BiscuitBuilder::new()
        .fact(fact(
            "pki_grant",
            &[int(0), bytes(&serde_json::to_vec(&claims)?)],
        ))?
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
    let claims = Claims {
        version: 2,
        client: client.clone(),
        audience: verified.audience().into(),
        scope: scope.clone(),
        expires,
        parent: verified.revocation_ids.last().cloned(),
    };
    let block = BlockBuilder::new().fact(fact(
        "pki_grant",
        &[
            int(verified.biscuit.block_count() as i64),
            bytes(&serde_json::to_vec(&claims)?),
        ],
    ))?;
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
/// Check a collection's operation grant and expiry without evaluating checks that need
/// candidate resource facts. Call `authorize_operation` on every candidate before disclosing it.
pub fn authorize_collection(
    capability: &VerifiedCapability,
    operation: Operation,
    basin: Option<&str>,
    now: i64,
) -> Result<()> {
    let target_valid = match operation {
        Operation::ListBasins => basin.is_none(),
        Operation::ListStreams => basin.is_some_and(|b| capability.scope().basins.contains(b)),
        _ => false,
    };
    if !target_valid || now >= capability.expires_at() || !capability.scope().permits(operation) {
        return Err(AuthError::PermissionDenied);
    }
    Ok(())
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
    if now >= capability.expires_at()
        || !capability.scope().permits(operation)
        || basin.is_some_and(|b| !capability.scope().basins.contains(b))
        || stream.is_some_and(|s| !capability.scope().streams.contains(s))
    {
        return Err(AuthError::PermissionDenied);
    }
    let mut builder = AuthorizerBuilder::new()
        .set_limits(limits())
        .fact(fact("time", &[int(now)]))?
        .fact(fact("operation", &[string(&format!("{operation:?}"))]))?;
    if let Some(b) = basin {
        builder = builder.fact(fact("basin", &[string(b)]))?;
    }
    if let Some(s) = stream {
        builder = builder.fact(fact("stream", &[string(s)]))?;
    }
    builder
        .code("allow if true")?
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
