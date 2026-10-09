use base64ct::{Base64, Encoding};
use http::{HeaderMap, HeaderValue, Method, Uri};
use httpsig::prelude::{
    message_component::{HttpMessageComponent, HttpMessageComponentId},
    *,
};
use sha2::{Digest, Sha256};

use crate::*;

pub const PROOF_LIFETIME_SECONDS: i64 = 60;
pub const SESSION_LEASE_SECONDS: i64 = 300;
#[derive(Clone, Debug)]
pub struct PkiCredentials {
    key: ClientKey,
    grant: Grant,
    capability: VerifiedCapability,
}
impl PkiCredentials {
    pub fn new(key: ClientKey, grant: Grant) -> Result<Self> {
        let capability = verify_biscuit(
            &grant,
            &TrustedIssuers::new(vec![grant.issuer().clone()]),
            "",
        )?;
        if key.public_key() != *capability.client_public_key() {
            return Err(AuthError::Key);
        }
        Ok(Self {
            key,
            grant,
            capability,
        })
    }
    pub fn grant(&self) -> &Grant {
        &self.grant
    }
    pub fn audience(&self) -> &str {
        self.capability.audience()
    }
}
#[derive(Clone, Copy)]
pub enum RequestBody<'a> {
    Unary(&'a [u8]),
    Streaming,
}
/// Constructible only after both the issuer chain and HTTP key possession verify.
#[derive(Clone, Debug)]
pub struct VerifiedRequest {
    capability: VerifiedCapability,
    nonce: String,
    proof_expires: i64,
    lease_expires: i64,
}
impl VerifiedRequest {
    pub fn capability(&self) -> &VerifiedCapability {
        &self.capability
    }
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
    pub fn proof_expires_at(&self) -> i64 {
        self.proof_expires
    }
    pub fn lease_expires_at(&self) -> i64 {
        self.lease_expires
    }
    pub fn authorize(
        &self,
        op: s2_common::access::Operation,
        basin: Option<&str>,
        stream: Option<&str>,
        now: i64,
    ) -> Result<()> {
        if now >= self.lease_expires {
            return Err(AuthError::PermissionDenied);
        }
        authorize_operation(&self.capability, op, basin, stream, now)
    }
}
fn sigerr(_: impl std::fmt::Display) -> AuthError {
    AuthError::Signature
}
fn single<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(AuthError::Signature)?;
    if values.next().is_some() {
        return Err(AuthError::Signature);
    }
    value.to_str().map_err(sigerr)
}
fn origin(uri: &Uri) -> Result<String> {
    Ok(format!(
        "{}://{}",
        uri.scheme_str().ok_or(AuthError::Audience)?,
        uri.authority().ok_or(AuthError::Audience)?
    ))
}
fn covered(headers: &HeaderMap) -> Vec<String> {
    let mut names: Vec<_> = headers
        .keys()
        .map(|n| n.as_str())
        .filter(|n| {
            n.starts_with("s2-")
                || matches!(
                    *n,
                    "authorization"
                        | "content-digest"
                        | "content-type"
                        | "content-encoding"
                        | "idempotency-key"
                        | "range"
                        | "accept"
                        | "last-event-id"
                        | "if-match"
                        | "if-none-match"
                )
        })
        .map(str::to_owned)
        .collect();
    names.sort();
    let mut all = vec!["@method".into(), "@target-uri".into()];
    all.extend(names);
    all
}
fn base(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    params: &HttpSignatureParams,
) -> Result<HttpSignatureBase> {
    let mut components = Vec::new();
    for id in &params.covered_components {
        let name = id.to_string();
        let name = name
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .ok_or(AuthError::Signature)?;
        let value = match name {
            "@method" => method.as_str().to_owned(),
            "@target-uri" => uri.to_string(),
            n => single(headers, n)?.to_owned(),
        };
        components.push(HttpMessageComponent::try_from((id, [value].as_slice())).map_err(sigerr)?);
    }
    HttpSignatureBase::try_new(&components, params).map_err(sigerr)
}
fn digest(body: &[u8]) -> String {
    format!("sha-256=:{}:", Base64::encode_string(&Sha256::digest(body)))
}
fn insert(headers: &mut HeaderMap, name: &'static str, value: &str) -> Result<()> {
    let mut value = HeaderValue::from_str(value).map_err(sigerr)?;
    if matches!(name, "authorization" | "signature" | "signature-input") {
        value.set_sensitive(true)
    }
    headers.insert(name, value);
    Ok(())
}
pub fn sign_request(
    credentials: &PkiCredentials,
    method: &Method,
    uri: &Uri,
    headers: &mut HeaderMap,
    body: RequestBody<'_>,
    now: i64,
) -> Result<()> {
    if origin(uri)? != credentials.audience()
        || now < 0
        || now >= credentials.capability.expires_at()
    {
        return Err(AuthError::Audience);
    }
    insert(
        headers,
        "authorization",
        &format!("Biscuit {}", credentials.grant.to_base64()),
    )?;
    match body {
        RequestBody::Unary(bytes) => {
            insert(headers, "s2-pki-body", "unary")?;
            insert(headers, "content-digest", &digest(bytes))?;
        }
        RequestBody::Streaming => {
            insert(headers, "s2-pki-body", "streaming")?;
            headers.remove("content-digest");
        }
    }
    let ids = covered(headers)
        .iter()
        .map(|n| HttpMessageComponentId::try_from(n.as_str()).map_err(sigerr))
        .collect::<Result<Vec<_>>>()?;
    let mut params = HttpSignatureParams::try_new(&ids).map_err(sigerr)?;
    params
        .set_created(now as u64)
        .set_expires((now + PROOF_LIFETIME_SECONDS) as u64)
        .set_random_nonce()
        .set_keyid(credentials.key.public_key().to_base58())
        .set_alg(&AlgorithmName::EcdsaP256Sha256)
        .set_tag("s2-pki-v2");
    let key = SecretKey::from_bytes(
        &AlgorithmName::EcdsaP256Sha256,
        credentials.key.0.to_bytes().as_slice(),
    )
    .map_err(sigerr)?;
    let signature = base(method, uri, headers, &params)?
        .build_signature_headers(&key, Some("s2"))
        .map_err(sigerr)?;
    insert(headers, "signature", &signature.signature_header_value())?;
    insert(
        headers,
        "signature-input",
        &signature.signature_input_header_value(),
    )
}
pub fn verify_request(
    issuers: &TrustedIssuers,
    audience: &str,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: RequestBody<'_>,
    now: i64,
) -> Result<VerifiedRequest> {
    if origin(uri)? != audience {
        return Err(AuthError::Audience);
    }
    let token = single(headers, "authorization")?
        .strip_prefix("Biscuit ")
        .ok_or(AuthError::Signature)?;
    let capability = verify_biscuit(&decode_grant(token)?, issuers, audience)?;
    if now >= capability.expires_at() {
        return Err(AuthError::PermissionDenied);
    }
    let signatures = HttpSignatureHeaders::try_parse(
        single(headers, "signature")?,
        single(headers, "signature-input")?,
    )
    .map_err(sigerr)?;
    if signatures.len() != 1 {
        return Err(AuthError::Signature);
    }
    let signature = signatures.get("s2").ok_or(AuthError::Signature)?;
    // The v2 profile has exactly one canonical signature. This also rejects
    // extension parameters the signature library would otherwise discard.
    if single(headers, "signature-input")? != signature.signature_input_header_value()
        || single(headers, "signature")? != signature.signature_header_value()
    {
        return Err(AuthError::Signature);
    }
    let params = signature.signature_params();
    let created = params.created.ok_or(AuthError::Signature)?;
    let expires = params.expires.ok_or(AuthError::Signature)?;
    if now < 0
        || created > (now + 10) as u64
        || expires <= now as u64
        || expires <= created
        || expires - created > PROOF_LIFETIME_SECONDS as u64
        || created < now.saturating_sub(PROOF_LIFETIME_SECONDS) as u64
        || params.alg.as_deref() != Some("ecdsa-p256-sha256")
        || params.tag.as_deref() != Some("s2-pki-v2")
        || params.keyid.as_deref() != Some(capability.client_public_key().to_base58())
    {
        return Err(AuthError::Signature);
    }
    let nonce = params.nonce.as_ref().ok_or(AuthError::Signature)?;
    if Base64::decode_vec(nonce).map_err(sigerr)?.len() != 32 {
        return Err(AuthError::Signature);
    }
    let expected = covered(headers)
        .iter()
        .map(|n| HttpMessageComponentId::try_from(n.as_str()).map_err(sigerr))
        .collect::<Result<Vec<_>>>()?;
    if params.covered_components != expected {
        return Err(AuthError::Signature);
    }
    match body {
        RequestBody::Unary(bytes) => {
            if single(headers, "s2-pki-body")? != "unary"
                || single(headers, "content-digest")? != digest(bytes)
            {
                return Err(AuthError::Signature);
            }
        }
        RequestBody::Streaming => {
            if single(headers, "s2-pki-body")? != "streaming"
                || headers.contains_key("content-digest")
            {
                return Err(AuthError::Signature);
            }
        }
    }
    let key = httpsig::prelude::PublicKey::from_bytes(
        &AlgorithmName::EcdsaP256Sha256,
        capability
            .client_public_key()
            .verifying_key()?
            .to_encoded_point(false)
            .as_bytes(),
    )
    .map_err(sigerr)?;
    base(method, uri, headers, params)?
        .verify_signature_headers(&key, signature)
        .map_err(sigerr)?;
    let lease_expires = capability.expires_at().min(now + SESSION_LEASE_SECONDS);
    Ok(VerifiedRequest {
        capability,
        nonce: nonce.clone(),
        proof_expires: expires as i64,
        lease_expires,
    })
}
