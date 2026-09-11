use tower_http::cors::{CorsLayer, AllowOrigin};
use axum::http::{HeaderValue, Method, header};

/// No permissive fallback: a missing/misconfigured `FRONTEND_ORIGIN` used to
/// silently open CORS to every origin. Failing fast here surfaces the
/// misconfiguration at startup instead of at request time in prod.
pub fn cors_layer() -> CorsLayer {
    let origin = std::env::var("FRONTEND_ORIGIN")
        .expect("FRONTEND_ORIGIN environment variable must be set (no permissive CORS fallback)");

    let header_val: HeaderValue = origin
        .parse()
        .expect("FRONTEND_ORIGIN must be a valid header value");

    CorsLayer::new()
        .allow_origin(AllowOrigin::exact(header_val))
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::PATCH, Method::DELETE])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .allow_credentials(true)
}