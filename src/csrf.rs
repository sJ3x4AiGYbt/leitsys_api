use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
    Json,
};

use crate::models::ApiResponse;

/// Extracts the `scheme://host[:port]` origin out of a full URL, without
/// pulling in a URL-parsing crate just for this one fallback.
fn origin_from_url(url: &str) -> Option<String> {
    let scheme_end = url.find("://")?;
    let after_scheme = &url[scheme_end + 3..];
    let host_end = after_scheme.find('/').unwrap_or(after_scheme.len());
    Some(format!("{}{}", &url[..scheme_end + 3], &after_scheme[..host_end]))
}

/// The refresh/logout cookie is `SameSite=None` (required for a cross-origin
/// frontend), which by itself does not stop another site from triggering a
/// credentialed request against these endpoints. As defense in depth, this
/// checks that the request actually originates from `FRONTEND_ORIGIN`.
///
/// Fails closed: a missing/misconfigured `FRONTEND_ORIGIN`, a missing
/// Origin/Referer header, or a mismatch are all rejected — none of those
/// are legitimate for a real cross-origin fetch() call from the frontend.
pub async fn verify_origin(
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<ApiResponse<()>>)> {
    let expected = std::env::var("FRONTEND_ORIGIN").map_err(|_| {
        tracing::warn!("CSRF check failed: FRONTEND_ORIGIN is not configured");
        (
            StatusCode::FORBIDDEN,
            Json(ApiResponse::<()>::error("Request origin could not be verified")),
        )
    })?;

    let origin = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| {
            headers
                .get(axum::http::header::REFERER)
                .and_then(|v| v.to_str().ok())
                .and_then(origin_from_url)
        });

    match origin {
        Some(ref origin) if origin == &expected => Ok(next.run(req).await),
        Some(origin) => {
            tracing::warn!(%origin, expected = %expected, "CSRF check failed: origin mismatch");
            Err((
                StatusCode::FORBIDDEN,
                Json(ApiResponse::<()>::error("Request origin could not be verified")),
            ))
        }
        None => {
            tracing::warn!("CSRF check failed: no Origin or Referer header");
            Err((
                StatusCode::FORBIDDEN,
                Json(ApiResponse::<()>::error("Request origin could not be verified")),
            ))
        }
    }
}
