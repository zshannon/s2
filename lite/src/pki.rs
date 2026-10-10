//! Exclusive PKI authentication at the HTTP boundary.
use std::{sync::Arc, time::Duration};

use axum::{
    body::{Body, to_bytes},
    extract::{FromRequestParts, OriginalUri, Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use futures::StreamExt;
use http::{Uri, request::Parts};
use s2_api::v1::error::{ErrorCode, ErrorInfo, ErrorResponse, StandardError};
use s2_pki_auth::{
    RequestBody, TrustedIssuers, VerifiedRequest, validate_audience, verify_request,
};

use crate::backend::Backend;
#[derive(Clone)]
pub struct PkiAuthState(Arc<Inner>);
struct Inner {
    backend: Backend,
    issuers: TrustedIssuers,
    audience: String,
}
impl PkiAuthState {
    pub fn new(
        backend: Backend,
        issuers: TrustedIssuers,
        audience: String,
    ) -> s2_pki_auth::Result<Self> {
        validate_audience(&audience)?;
        Ok(Self(Arc::new(Inner {
            backend,
            issuers,
            audience,
        })))
    }
    async fn active(&self, identity: &VerifiedRequest, policy: Option<&ReadPolicy>) -> bool {
        time::OffsetDateTime::now_utc().unix_timestamp() < identity.lease_expires_at()
            && policy.is_none_or(|p| p.authorize(identity).is_ok())
            && self
                .0
                .backend
                .pki_not_revoked(identity.capability().revocation_identifiers())
                .await
                .unwrap_or(false)
    }
}
#[derive(Clone)]
pub(crate) struct ReadPolicy {
    pub basin: String,
    pub stream: String,
}
impl ReadPolicy {
    fn authorize(&self, identity: &VerifiedRequest) -> s2_pki_auth::Result<()> {
        identity.authorize(
            s2_pki_auth::Operation::Read,
            Some(&self.basin),
            Some(&self.stream),
            time::OffsetDateTime::now_utc().unix_timestamp(),
        )
    }
}
#[derive(Clone)]
pub struct AuthContext(pub(crate) Option<VerifiedRequest>);
impl AuthContext {
    pub(crate) fn authorize(
        &self,
        op: s2_common::access::Operation,
        basin: Option<&str>,
        stream: Option<&str>,
    ) -> Result<(), crate::handlers::v1::error::ServiceError> {
        if let Some(identity) = &self.0 {
            identity
                .authorize(
                    op,
                    basin,
                    stream,
                    time::OffsetDateTime::now_utc().unix_timestamp(),
                )
                .map_err(|_| crate::handlers::v1::error::ServiceError::PermissionDenied)?;
        }
        Ok(())
    }
    pub(crate) fn scope(self, backend: Backend) -> Backend {
        backend.with_pki(self.0)
    }
}
impl<S: Send + Sync> FromRequestParts<S> for AuthContext {
    type Rejection = Response;
    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Response> {
        let context = parts
            .extensions
            .get::<Self>()
            .cloned()
            .ok_or_else(|| error(ErrorCode::Authn))?;
        if context.0.is_none() && parts.extensions.get::<PkiAuthState>().is_some() {
            return Err(error(ErrorCode::Authn));
        }
        Ok(context)
    }
}
fn error(code: ErrorCode) -> Response {
    ErrorResponse::Standard(StandardError {
        status: code.status(),
        info: ErrorInfo {
            code: code.into(),
            message: "PKI authentication or permission check failed".into(),
        },
    })
    .into_response()
}
pub(crate) async fn authenticate(
    State(state): State<PkiAuthState>,
    mut request: Request,
    next: Next,
) -> Response {
    let original = request
        .extensions()
        .get::<OriginalUri>()
        .map(|uri| uri.0.clone())
        .unwrap_or_else(|| request.uri().clone());
    if matches!(original.path(), "/health" | "/ping") {
        return next.run(request).await;
    }
    let target = match format!(
        "{}{}",
        state.0.audience,
        original.path_and_query().map(|p| p.as_str()).unwrap_or("/")
    )
    .parse::<Uri>()
    {
        Ok(uri) => uri,
        Err(_) => return error(ErrorCode::Authn),
    };
    if let Some(host) = request.headers().get("host")
        && host.to_str().ok() != target.authority().map(|a| a.as_str())
    {
        return error(ErrorCode::Authn);
    }
    let content_type = s2_api::mime::content_type(request.headers());
    let records = original.path().ends_with("/records");
    let proto = content_type
        .as_ref()
        .is_some_and(s2_api::mime::is_s2s_proto);
    let streaming = request.method() == http::Method::POST && records && proto;
    let (parts, body) = request.into_parts();
    let (identity, body) = if streaming {
        match verify_request(
            &state.0.issuers,
            &state.0.audience,
            &parts.method,
            &target,
            &parts.headers,
            RequestBody::Streaming,
            time::OffsetDateTime::now_utc().unix_timestamp(),
        ) {
            Ok(identity) => (identity, body),
            Err(_) => return error(ErrorCode::Authn),
        }
    } else {
        let bytes =
            match tokio::time::timeout(Duration::from_secs(10), to_bytes(body, 16 * 1024 * 1024))
                .await
            {
                Ok(Ok(bytes)) => bytes,
                _ => return error(ErrorCode::Authn),
            };
        match verify_request(
            &state.0.issuers,
            &state.0.audience,
            &parts.method,
            &target,
            &parts.headers,
            RequestBody::Unary(&bytes),
            time::OffsetDateTime::now_utc().unix_timestamp(),
        ) {
            Ok(identity) => (identity, Body::from(bytes)),
            Err(_) => return error(ErrorCode::Authn),
        }
    };
    if !state.active(&identity, None).await {
        return error(ErrorCode::Authn);
    }
    match state.0.backend.pki_accept_nonce(&identity).await {
        Ok(true) => {}
        Ok(false) => return error(ErrorCode::Authn),
        Err(_) => return error(ErrorCode::Unavailable),
    }
    if identity
        .validate_admission(time::OffsetDateTime::now_utc().unix_timestamp())
        .is_err()
    {
        return error(ErrorCode::Authn);
    }
    if original.path().starts_with("/v1/access-tokens") {
        return error(ErrorCode::PermissionDenied);
    }
    if original.path() == "/metrics"
        && identity
            .authorize(
                s2_common::access::Operation::AccountMetrics,
                None,
                None,
                time::OffsetDateTime::now_utc().unix_timestamp(),
            )
            .is_err()
    {
        return error(ErrorCode::PermissionDenied);
    }
    request = Request::from_parts(parts, body);
    request
        .extensions_mut()
        .insert(AuthContext(Some(identity.clone())));
    request.extensions_mut().insert(state.clone());
    // Revocation only removes authority. Let self-revocation finish its durable
    // acknowledgement after the caller's credential becomes revoked.
    if original.path() == "/v1/pki/revocations" {
        return next.run(request).await;
    }
    let execution = next.run(request);
    tokio::pin!(execution);
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let response = loop {
        tokio::select! {
            response=&mut execution=>break response,
            _=tick.tick()=>{if !state.active(&identity, None).await{return error(ErrorCode::Other)}}
        }
    };
    // Revalidate even idle streams; dropping the body cancels the underlying session.
    let policy = response.extensions().get::<ReadPolicy>().cloned();
    let (parts, body) = response.into_parts();
    let mut stream = body.into_data_stream();
    let output = async_stream::stream! {
        let mut tick=tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                biased;
                _=tick.tick()=>{if !state.active(&identity, policy.as_ref()).await{yield Err(std::io::Error::other("PKI session expired or revoked"));break}},
                data=stream.next()=>match data{Some(Ok(data))=>{
                    if policy.as_ref().is_some_and(|p| p.authorize(&identity).is_err()) {
                        yield Err(std::io::Error::other("PKI read policy denied")); break;
                    }
                    yield Ok(data)
                },Some(Err(e))=>{yield Err(std::io::Error::other(e));break},None=>break}
            }
        }
    };
    Response::from_parts(parts, Body::from_stream(output))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeRequest {
    grant: String,
}
pub(crate) fn router() -> axum::Router<Backend> {
    axum::Router::new()
        .route("/v1/pki/revocations", axum::routing::post(revoke))
        .layer(tower_http::decompression::RequestDecompressionLayer::new())
}
async fn revoke(
    axum::Extension(state): axum::Extension<PkiAuthState>,
    auth: AuthContext,
    body: Result<axum::Json<RevokeRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let request = match body {
        Ok(axum::Json(request)) => request,
        Err(_) => return error(ErrorCode::BadJson),
    };
    let Some(actor) = auth.0 else {
        return error(ErrorCode::Authn);
    };
    let target = match s2_pki_auth::decode_grant(&request.grant)
        .and_then(|bytes| s2_pki_auth::verify_biscuit(&bytes, &state.0.issuers, &state.0.audience))
    {
        Ok(target) => target,
        Err(_) => return error(ErrorCode::PermissionDenied),
    };
    let id =
        match s2_pki_auth::authorize_revocation(actor.capability().client_public_key(), &target) {
            Ok(id) => id,
            Err(_) => return error(ErrorCode::PermissionDenied),
        };
    match state.0.backend.pki_revoke(id).await {
        Ok(()) => http::StatusCode::NO_CONTENT.into_response(),
        Err(_) => error(ErrorCode::Unavailable),
    }
}
