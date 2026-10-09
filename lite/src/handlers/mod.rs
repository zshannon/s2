pub mod v1;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::backend::Backend;

pub fn router() -> axum::Router<Backend> {
    routes().layer(axum::Extension(crate::pki::AuthContext(None)))
}

pub fn router_with_pki(state: crate::pki::PkiAuthState) -> axum::Router<Backend> {
    routes()
        .merge(crate::pki::router())
        .layer(axum::middleware::from_fn_with_state(
            state,
            crate::pki::authenticate,
        ))
}

fn routes() -> axum::Router<Backend> {
    axum::Router::new()
        .route(/* bw compat */ "/ping", axum::routing::get(health))
        .route("/health", axum::routing::get(health))
        .route("/metrics", axum::routing::get(metrics))
        .nest("/v1", v1::router())
}

async fn health(State(backend): State<Backend>) -> Response {
    match backend.db_status() {
        Ok(()) => "OK".into_response(),
        Err(err) => (StatusCode::SERVICE_UNAVAILABLE, format!("{err:?}")).into_response(),
    }
}

async fn metrics(State(_backend): State<Backend>) -> Response {
    match crate::metrics::gather() {
        Ok(body) => (
            [(
                axum::http::header::CONTENT_TYPE,
                "text/plain; version=0.0.4",
            )],
            body,
        )
            .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
