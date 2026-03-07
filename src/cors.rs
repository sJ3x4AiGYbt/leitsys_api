use tower_http::cors::{CorsLayer, AllowOrigin};
use axum::http::{HeaderValue, Method, header};

pub fn cors_layer() -> CorsLayer {
    match std::env::var("FRONTEND_ORIGIN") {
        Ok(origin) => {
            let header_val: HeaderValue = origin
                .parse()
                .expect("FRONTEND_ORIGIN must be a valid header value");

            CorsLayer::new()
                .allow_origin(AllowOrigin::exact(header_val))
                .allow_methods([Method::GET, Method::POST, Method::PUT, Method::PATCH, Method::DELETE])
                .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
                .allow_credentials(true)
        }
        Err(_) => CorsLayer::permissive(),
    }
}