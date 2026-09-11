use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
    Json,
};

use crate::models::ApiResponse;

struct Window {
    count: u32,
    started_at: Instant,
}

/// Fixed-window rate limiter keyed by client IP. Cheap enough for a handful of
/// auth routes; not meant to replace a proper reverse-proxy-level limiter under
/// heavy multi-instance load.
#[derive(Clone)]
pub struct RateLimiter {
    windows: Arc<Mutex<HashMap<IpAddr, Window>>>,
    max_requests: u32,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            windows: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window,
        }
    }

    fn allow(&self, ip: IpAddr) -> bool {
        let mut windows = self.windows.lock().unwrap();
        let now = Instant::now();

        let entry = windows.entry(ip).or_insert_with(|| Window {
            count: 0,
            started_at: now,
        });

        if now.duration_since(entry.started_at) > self.window {
            entry.count = 0;
            entry.started_at = now;
        }

        entry.count += 1;
        entry.count <= self.max_requests
    }
}

pub async fn rate_limit(
    State(limiter): State<RateLimiter>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<ApiResponse<()>>)> {
    if !limiter.allow(addr.ip()) {
        tracing::warn!(ip = %addr.ip(), path = %req.uri(), "rate limit exceeded");
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ApiResponse::<()>::error("Too many requests, try again later.")),
        ));
    }

    Ok(next.run(req).await)
}
