mod auth;
mod routes;

use crate::assets::spa;
use crate::authz::{device_allows, has_role, is_admin};
use crate::db::DeviceRow;
use crate::error::ApiError;
use crate::state::AppState;
use crate::tls::{PeerAddr, PeerCert};
use crate::util::{cookie_value, sha256_hex};
use axum::body::Body;
use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::de::DeserializeOwned;
use std::time::Duration;
use x509_parser::prelude::*;

pub use auth::Op;

pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/meta", get(routes::meta))
        .route("/openapi.yaml", get(routes::openapi))
        .route("/auth/dev-login", post(auth::dev_login))
        .route("/auth/dev-operators", post(auth::dev_operator))
        .route(
            "/auth/passkey/register/options",
            post(auth::register_options),
        )
        .route("/auth/passkey/register/finish", post(auth::register_finish))
        .route("/auth/passkey/login/options", post(auth::login_options))
        .route("/auth/passkey/login/finish", post(auth::login_finish))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/me", get(auth::me))
        .route(
            "/enrollment-tokens",
            post(routes::create_token).get(routes::list_tokens),
        )
        .route("/enroll", post(routes::enroll))
        .route("/devices", get(routes::list_devices))
        .route("/devices/{id}", get(routes::device_detail))
        .route(
            "/devices/{id}/commands",
            post(routes::issue_command).get(routes::commands),
        )
        .route("/devices/{id}/commands/{command_id}/ack", post(routes::ack))
        .route("/devices/{id}/boot-policy", get(routes::boot_policy))
        .route("/devices/{id}/boot-targets", put(routes::put_targets))
        .route("/devices/{id}/inventory", put(routes::put_inventory))
        .route("/devices/{id}/heartbeat", post(routes::heartbeat))
        .route("/devices/{id}/policy", put(routes::put_policy))
        .route("/devices/{id}/revoke", post(routes::revoke))
        .route("/devices/{id}/rotate-key", post(routes::rotate_key))
        .route("/devices/{id}/grants", post(routes::grant))
        .route(
            "/devices/{id}/storage-plans",
            post(routes::storage_disabled),
        )
        .route(
            "/devices/{id}/os-install-plans",
            post(routes::install_disabled),
        )
        .route("/devices/{id}/pending", get(routes::pending))
        .route("/devices/{id}/boot-success", post(routes::boot_success))
        .route("/devices/{id}/recovery/tunnel", get(routes::device_tunnel))
        .route("/recovery-sessions", post(routes::open_recovery))
        .route("/recovery-sessions/{id}", get(routes::recovery_status))
        .route(
            "/recovery-sessions/{id}/close",
            post(routes::close_recovery),
        )
        .route("/recovery-sessions/{id}/vnc", get(routes::browser_vnc))
        .route(
            "/recovery-sessions/{id}/terminal",
            get(routes::browser_terminal),
        )
        .route("/audit", get(routes::audit))
        .route("/security", get(routes::security))
        .route(
            "/security/rotate-command-key",
            post(routes::rotate_server_key),
        )
        .fallback(api_not_found);
    Router::new()
        .route("/healthz", get(routes::health))
        .route("/readyz", get(routes::ready))
        .nest("/v1", api)
        .fallback(spa)
        .layer(from_fn_with_state(state.clone(), guard))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(256 * 1024))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

async fn api_not_found() -> ApiError {
    ApiError::not_found()
}

async fn guard(state: axum::extract::State<AppState>, req: Request, next: Next) -> Response {
    let ip = req
        .extensions()
        .get::<PeerAddr>()
        .map(|peer| peer.0.ip().to_string())
        .unwrap_or_else(|| "local".to_string());
    let path = req.uri().path();
    let (bucket, limit) = if path.starts_with("/v1/auth") {
        ("auth", 20)
    } else if path.starts_with("/v1/enroll") {
        ("enroll", 30)
    } else {
        ("all", 600)
    };
    if !state
        .limiter
        .allow(&format!("{bucket}:{ip}"), limit, Duration::from_secs(60))
    {
        return ApiError::rate_limited().into_response();
    }
    let api = path.starts_with("/v1") || path == "/healthz" || path == "/readyz";
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    insert(headers, "x-content-type-options", "nosniff");
    insert(headers, "x-frame-options", "DENY");
    insert(headers, "referrer-policy", "no-referrer");
    insert(
        headers,
        "permissions-policy",
        "camera=(), microphone=(), geolocation=()",
    );
    insert(headers, "cross-origin-opener-policy", "same-origin");
    insert(headers, "cross-origin-resource-policy", "same-origin");
    if let Ok(value) = crate::assets::content_security_policy().parse() {
        headers.insert("content-security-policy", value);
    }
    if !state.config.insecure_http {
        insert(
            headers,
            "strict-transport-security",
            "max-age=63072000; includeSubDomains",
        );
    }
    if api {
        insert(headers, "cache-control", "no-store");
    }
    response
}

fn insert(headers: &mut HeaderMap, name: &'static str, value: &'static str) {
    if let Ok(value) = value.parse() {
        headers.insert(name, value);
    }
}

pub struct In<T>(pub T);

impl<S, T> FromRequest<S> for In<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request<Body>, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(In(value)),
            Err(err) => Err(ApiError::invalid(err.to_string())),
        }
    }
}

pub struct Dev {
    pub id: String,
    pub status: String,
    pub public_key_hex: String,
    pub cert_sha256: String,
}

pub async fn require_operator(
    app: &AppState,
    headers: &HeaderMap,
    method: &Method,
) -> Result<Op, ApiError> {
    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let cookie_token = cookie_value(cookie_header, "sbm_session");
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let (token, from_cookie) = match (bearer, cookie_token) {
        (Some(token), _) if !token.is_empty() => (token, false),
        (_, Some(token)) => (token, true),
        _ => return Err(ApiError::unauthorized("sign in required")),
    };
    let session = app
        .db
        .session(&sha256_hex(token.as_bytes()))
        .await?
        .ok_or_else(|| ApiError::unauthorized("session expired"))?;
    let now = app.clock.unix();
    if session.expires_at < now {
        return Err(ApiError::unauthorized("session expired"));
    }
    if from_cookie && is_mutating(method) {
        let csrf = headers
            .get("x-csrf-token")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        if csrf.is_empty() || csrf != session.csrf_token {
            return Err(ApiError::forbidden("csrf", "missing or invalid CSRF token"));
        }
    }
    let operator = app
        .db
        .operator_by_id(&session.operator_id)
        .await?
        .ok_or_else(|| ApiError::unauthorized("sign in required"))?;
    if operator.disabled {
        return Err(ApiError::forbidden("forbidden", "operator is disabled"));
    }
    let roles = app.db.roles(&operator.id).await?;
    Ok(Op {
        id: operator.id,
        username: operator.username,
        display_name: operator.display_name,
        roles,
    })
}

pub struct CertDer(pub Vec<u8>);

impl<S> FromRequestParts<S> for CertDer
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<PeerCert>()
            .map(|peer| CertDer(peer.0.clone()))
            .ok_or_else(|| ApiError::unauthorized("device certificate required"))
    }
}

pub async fn require_device(app: &AppState, der: &[u8]) -> Result<Dev, ApiError> {
    let fingerprint = sha256_hex(der);
    let (device, cert_revoked) = app
        .db
        .device_by_cert(&fingerprint)
        .await?
        .ok_or_else(|| ApiError::unauthorized("device certificate is not enrolled"))?;
    if cert_revoked {
        return Err(ApiError::unauthorized(
            "device certificate has been revoked",
        ));
    }
    let uri_id = san_device_id(der)
        .ok_or_else(|| ApiError::unauthorized("device certificate is missing its identity URI"))?;
    if uri_id != device.id {
        return Err(ApiError::unauthorized(
            "device certificate identity does not match",
        ));
    }
    app.db.touch_device(&device.id, app.clock.unix()).await?;
    Ok(Dev {
        id: device.id,
        status: device.status,
        public_key_hex: device.public_key_hex,
        cert_sha256: device.cert_sha256,
    })
}

pub async fn authorize_device(
    app: &AppState,
    op: &Op,
    device: &DeviceRow,
    needed: &str,
) -> Result<(), ApiError> {
    if !has_role(&op.roles, needed) && !is_admin(&op.roles) {
        return Err(ApiError::forbidden("forbidden", "missing role"));
    }
    let grants = app.db.grants(&device.id, &op.id).await?;
    let owner = device.owner_id == op.id;
    if device_allows(&op.roles, owner, &grants, needed) {
        Ok(())
    } else {
        Err(ApiError::not_found())
    }
}

pub fn visible_admin(op: &Op) -> bool {
    is_admin(&op.roles)
}

fn is_mutating(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

fn san_device_id(der: &[u8]) -> Option<String> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let ext = cert.subject_alternative_name().ok().flatten()?;
    for name in &ext.value.general_names {
        if let GeneralName::URI(uri) = name
            && let Some(id) = uri.strip_prefix("urn:sbm:device:")
        {
            return Some(id.to_string());
        }
    }
    None
}

pub fn command_state_note() -> &'static str {
    "The command is queued. The device has not applied it, and no reboot has happened."
}

pub async fn load_device(app: &AppState, id: &str) -> Result<DeviceRow, ApiError> {
    app.db.device(id).await?.ok_or_else(ApiError::not_found)
}

pub fn online(last: Option<i64>, now: i64) -> bool {
    last.is_some_and(|seen| now.saturating_sub(seen) <= 30)
}
