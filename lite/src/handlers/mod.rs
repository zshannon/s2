use axum::{
    extract::State,
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use tower_http::set_header::SetResponseHeaderLayer;

pub mod v1;

/// Git SHA of the build, set at compile time via environment variable.
pub const GIT_SHA: &str = match option_env!("GIT_SHA") {
    Some(sha) => sha,
    None => "unknown",
};

pub fn router(app_state: &v1::AppState) -> axum::Router<v1::AppState> {
    axum::Router::new()
        .route(/* bw compat */ "/ping", axum::routing::get(health))
        .route("/health", axum::routing::get(health))
        .route("/metrics", axum::routing::get(metrics))
        .nest("/v1", v1::router(app_state))
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::HeaderName::from_static("x-git-sha"),
            HeaderValue::from_static(GIT_SHA),
        ))
}

async fn health(State(app_state): State<v1::AppState>) -> Response {
    match app_state.backend.db_status() {
        Ok(()) => "OK".into_response(),
        Err(err) => (StatusCode::SERVICE_UNAVAILABLE, format!("{err:?}")).into_response(),
    }
}

async fn metrics() -> impl axum::response::IntoResponse {
    let body = crate::metrics::gather();
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
}
