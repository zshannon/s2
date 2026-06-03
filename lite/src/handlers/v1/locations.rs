use axum::extract::{Extension, FromRequest, State};
use s2_api::{data::Json, v1 as v1t};
use s2_common::types::access::Operation;

use crate::{
    auth::{self, AuthState},
    backend::Backend,
    handlers::v1::{AppState, error::ServiceError, middleware::AuthenticatedRequest},
};

fn authorize_op(
    auth_req: Option<&AuthenticatedRequest>,
    auth_state: &AuthState,
    operation: Operation,
) -> Result<(), ServiceError> {
    if let Some(auth) = auth_req {
        auth::authorize(
            &auth.token,
            &auth.client_public_key,
            auth_state.root_public_key(),
            None,
            None,
            None,
            operation,
        )?;
    }
    Ok(())
}

pub fn router() -> axum::Router<AppState> {
    use axum::routing::{get, put};
    axum::Router::new()
        .route(super::paths::locations::LIST, get(list_locations))
        .route(super::paths::locations::DEFAULT, get(get_default_location))
        .route(super::paths::locations::DEFAULT, put(set_default_location))
}

/// List locations.
#[cfg_attr(feature = "utoipa", utoipa::path(
    get,
    path = super::paths::locations::LIST,
    tag = super::paths::locations::TAG,
    responses(
        (status = 200, body = Vec<v1t::location::LocationInfo>),
        (status = 400, body = v1t::error::ErrorInfo),
        (status = 403, body = v1t::error::ErrorInfo),
        (status = 408, body = v1t::error::ErrorInfo),
    ),
))]
pub async fn list_locations(
    State(_backend): State<Backend>,
    State(auth_state): State<AuthState>,
    auth: Option<Extension<AuthenticatedRequest>>,
) -> Result<Json<Vec<v1t::location::LocationInfo>>, ServiceError> {
    authorize_op(
        auth.as_ref().map(|e| &e.0),
        &auth_state,
        Operation::ListLocations,
    )?;

    Err(ServiceError::NotImplemented)
}

/// Get the default location.
#[cfg_attr(feature = "utoipa", utoipa::path(
    get,
    path = super::paths::locations::DEFAULT,
    tag = super::paths::locations::TAG,
    responses(
        (status = 200, body = v1t::location::GetDefaultLocationResponse),
        (status = 403, body = v1t::error::ErrorInfo),
        (status = 408, body = v1t::error::ErrorInfo),
    ),
))]
pub async fn get_default_location(
    State(_backend): State<Backend>,
    State(auth_state): State<AuthState>,
    auth: Option<Extension<AuthenticatedRequest>>,
) -> Result<Json<v1t::location::GetDefaultLocationResponse>, ServiceError> {
    authorize_op(
        auth.as_ref().map(|e| &e.0),
        &auth_state,
        Operation::GetDefaultLocation,
    )?;

    Err(ServiceError::NotImplemented)
}

#[derive(FromRequest)]
#[from_request(rejection(ServiceError))]
pub struct SetDefaultArgs {
    #[from_request(via(Json))]
    _request: v1t::location::SetDefaultLocationRequest,
}

/// Set the default location.
#[cfg_attr(feature = "utoipa", utoipa::path(
    put,
    path = super::paths::locations::DEFAULT,
    tag = super::paths::locations::TAG,
    request_body = v1t::location::SetDefaultLocationRequest,
    responses(
        (status = 200, body = v1t::location::GetDefaultLocationResponse),
        (status = 400, body = v1t::error::ErrorInfo),
        (status = 403, body = v1t::error::ErrorInfo),
        (status = 408, body = v1t::error::ErrorInfo),
    ),
))]
pub async fn set_default_location(
    State(_backend): State<Backend>,
    State(auth_state): State<AuthState>,
    auth: Option<Extension<AuthenticatedRequest>>,
    SetDefaultArgs { .. }: SetDefaultArgs,
) -> Result<Json<v1t::location::GetDefaultLocationResponse>, ServiceError> {
    authorize_op(
        auth.as_ref().map(|e| &e.0),
        &auth_state,
        Operation::SetDefaultLocation,
    )?;

    Err(ServiceError::NotImplemented)
}
