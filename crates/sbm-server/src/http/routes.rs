use super::auth::Op;
use super::{
    CertDer, Dev, In, authorize_device, command_state_note, load_device, online, require_device,
    require_operator, visible_admin,
};
use crate::error::ApiError;
use crate::identity::cert_sha256_pem;
use crate::state::AppState;
use crate::util::{clean_text, new_id, random_token, scope_name, sha256_hex, valid_hostname};
use axum::Json;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, Query, State, WebSocketUpgrade};
use axum::response::IntoResponse;
use ed25519_dalek::{Signature, VerifyingKey};
use sbm_protocol::{
    AuthScope, BootCommand, BootPolicy, CommandEnvelope, CommandPayload, OfflineBehavior,
    OneShotBoot,
};
use sbm_types::{BootTarget, SCHEMA_VERSION_V1};
use sbm_wire::{decode_key_32, expected_scope, preset_allowed, sign};
use serde::Deserialize;
use serde_json::{Value, json};
use signature::Verifier;
use std::time::Duration;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

#[derive(Deserialize)]
pub(crate) struct TokenBody {
    #[serde(default)]
    note: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct IssueBody {
    command: BootCommand,
}

#[derive(Deserialize)]
pub(crate) struct AckBody {
    state: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct TargetsBody {
    targets: Vec<BootTarget>,
}

#[derive(Deserialize)]
pub(crate) struct InventoryBody {
    inventory: Value,
}

#[derive(Deserialize)]
pub(crate) struct HeartbeatBody {
    component: String,
    software_version: String,
    mode: String,
    #[serde(default)]
    detail: Value,
}

#[derive(Deserialize)]
pub(crate) struct PolicyBody {
    timeout_seconds: u16,
    offline_behavior: OfflineBehavior,
    allow_remote_boot_select: bool,
    max_failed_attempts: u8,
    network_policy_timeout_ms: u32,
}

#[derive(Deserialize)]
pub(crate) struct RevokeBody {
    reason: String,
}

#[derive(Deserialize)]
pub(crate) struct GrantBody {
    operator_id: String,
    role: String,
}

#[derive(Deserialize)]
pub(crate) struct RotateBody {
    new_public_key_ed25519_hex: String,
    signature_ed25519_hex: String,
}

#[derive(Deserialize)]
pub(crate) struct ConfirmBody {
    confirm: String,
}

#[derive(Deserialize)]
pub(crate) struct RecoveryBody {
    device_id: String,
}

#[derive(Deserialize)]
pub(crate) struct TunnelQuery {
    session: String,
    #[serde(default)]
    kind: Option<String>,
}

pub async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

pub async fn ready(State(app): State<AppState>) -> Result<Json<Value>, ApiError> {
    app.db.count_operators().await?;
    Ok(Json(json!({ "status": "ready" })))
}

pub async fn meta(State(app): State<AppState>) -> Json<Value> {
    let material = app.identity.read().await;
    Json(json!({
        "service": "sbm-server",
        "version": env!("CARGO_PKG_VERSION"),
        "protocol": { "major": 1, "minor": 0 },
        "ca_fingerprint_sha256": material.ca_fingerprint,
        "ca_pem": material.ca_cert_pem,
        "command_verify_key_ed25519_hex": material.command_public_hex,
        "issuer_key_id": material.issuer_key_id,
        "storage_destructive_enabled": false,
        "os_install_enabled": false,
        "dev_bootstrap": app.config.dev_bootstrap,
        "public_origin": app.config.public_origin,
        "local_boot_requires_server": false,
    }))
}

pub async fn openapi() -> impl IntoResponse {
    (
        [("content-type", "application/yaml; charset=utf-8")],
        include_str!("../../openapi.yaml"),
    )
}

pub async fn security(
    State(app): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let op = require_operator(&app, &headers, &axum::http::Method::GET).await?;
    let material = app.identity.read().await;
    Ok(Json(json!({
        "operator": { "id": op.id, "username": op.username, "roles": op.roles },
        "ca_fingerprint_sha256": material.ca_fingerprint,
        "issuer_key_id": material.issuer_key_id,
        "command_verify_key_ed25519_hex": material.command_public_hex,
        "storage_destructive_enabled": false,
        "os_install_enabled": false,
        "session_ttl_seconds": app.config.session_ttl.as_secs(),
        "boot_command_ttl_seconds": app.config.boot_command_ttl.as_secs(),
        "enrollment_ttl_seconds": app.config.enrollment_ttl.as_secs(),
        "uefi_remote_scopes": ["read_only", "boot_select"],
        "notes": [
            "A compromised management server can sign boot selections for known targets only.",
            "It cannot send a shell command or an arbitrary kernel command line to UEFI.",
            "Remote destructive storage is not enabled."
        ],
    })))
}

pub async fn create_token(
    State(app): State<AppState>,
    headers: axum::http::HeaderMap,
    In(body): In<TokenBody>,
) -> Result<Json<Value>, ApiError> {
    let op = require_operator(&app, &headers, &axum::http::Method::POST).await?;
    if !op.roles.iter().any(|role| role == "admin") {
        return Err(ApiError::forbidden("forbidden", "admin role required"));
    }
    let note = match body.note.as_deref() {
        None | Some("") => String::new(),
        Some(note) => clean_text(note, 200).ok_or_else(|| ApiError::invalid("note is too long"))?,
    };
    let token = random_token();
    let now = app.clock.unix();
    let expires = now + i64::try_from(app.config.enrollment_ttl.as_secs()).unwrap_or(600);
    let (fingerprint, ca_pem) = {
        let material = app.identity.read().await;
        (
            material.ca_fingerprint.clone(),
            material.ca_cert_pem.clone(),
        )
    };
    let id = new_id();
    app.db
        .insert_token(
            &id,
            &sha256_hex(token.as_bytes()),
            &op.id,
            now,
            expires,
            &fingerprint,
            &note,
        )
        .await?;
    app.db
        .audit(
            now,
            "operator",
            &op.id,
            "enrollment_token.create",
            None,
            &json!({ "token_id": id, "expires_at": expires }),
        )
        .await?;
    Ok(Json(json!({
        "id": id,
        "token": token,
        "expires_at_unix": expires,
        "ca_fingerprint_sha256": fingerprint,
        "ca_pem": ca_pem,
        "server": app.config.public_origin,
        "shown_once": true,
    })))
}

pub async fn list_tokens(
    State(app): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let op = require_operator(&app, &headers, &axum::http::Method::GET).await?;
    if !op.roles.iter().any(|role| role == "admin") {
        return Err(ApiError::forbidden("forbidden", "admin role required"));
    }
    Ok(Json(json!({ "tokens": app.db.list_tokens().await? })))
}

pub async fn enroll(
    State(app): State<AppState>,
    headers: axum::http::HeaderMap,
    In(body): In<sbm_protocol::EnrollmentRequest>,
) -> Result<Json<sbm_protocol::EnrollmentResponse>, ApiError> {
    if body.schema_version != SCHEMA_VERSION_V1 {
        return Err(ApiError::invalid("unsupported schema_version"));
    }
    if !valid_hostname(&body.hostname) {
        return Err(ApiError::invalid("hostname must be a short DNS label"));
    }
    let public = decode_key_32(&body.device_public_key_ed25519_hex)
        .map_err(|_| ApiError::invalid("device public key must be 32 bytes of hex"))?;
    let simulated = headers
        .get("x-sbm-client")
        .and_then(|value| value.to_str().ok())
        == Some("sbm-sim");
    let (fingerprint, verify, cert_pem, device_id, cert_sha) = {
        let material = app.identity.read().await;
        let fingerprint = material.ca_fingerprint.clone();
        let verify = material.command_public_hex.clone();
        let cert_pem = material.issue_device_cert(&new_id(), &public)?;
        let device_id = san_from_cert(&cert_pem)?;
        let cert_sha = cert_sha256_pem(&cert_pem)?;
        (fingerprint, verify, cert_pem, device_id, cert_sha)
    };
    let policy = serde_json::to_string(&fresh_policy()).map_err(|_| ApiError::internal())?;
    let platform = serde_json::to_string(&body.platform).map_err(|_| ApiError::internal())?;
    app.db
        .enroll(
            &sha256_hex(body.enrollment_token.as_bytes()),
            app.clock.unix(),
            &fingerprint,
            &device_id,
            &body.hostname,
            &hex::encode(public),
            &platform,
            &cert_pem,
            &cert_sha,
            simulated,
            &policy,
        )
        .await?;
    Ok(Json(sbm_protocol::EnrollmentResponse {
        schema_version: SCHEMA_VERSION_V1.to_string(),
        device_id,
        client_cert_pem: cert_pem,
        server_command_verify_key_ed25519_hex: verify,
        granted_scopes: vec![
            AuthScope::ReadOnly,
            AuthScope::BootSelect,
            AuthScope::RecoveryAccess,
        ],
    }))
}

pub async fn list_devices(
    State(app): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let op = require_operator(&app, &headers, &axum::http::Method::GET).await?;
    if !crate::authz::has_role(&op.roles, "read_only") {
        return Err(ApiError::forbidden("forbidden", "missing role"));
    }
    let now = app.clock.unix();
    let devices = app
        .db
        .list_devices(&op.id, visible_admin(&op))
        .await?
        .into_iter()
        .map(|device| device_summary(&device, now))
        .collect::<Vec<_>>();
    Ok(Json(json!({ "devices": devices })))
}

pub async fn device_detail(
    State(app): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let op = require_operator(&app, &headers, &axum::http::Method::GET).await?;
    let device = load_device(&app, &id).await?;
    authorize_device(&app, &op, &device, "read_only").await?;
    Ok(Json(device_detail_json(&app, &device).await?))
}

pub async fn issue_command(
    State(app): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    In(body): In<IssueBody>,
) -> Result<Json<Value>, ApiError> {
    let op = require_operator(&app, &headers, &axum::http::Method::POST).await?;
    let device = load_device(&app, &id).await?;
    if device.status != "enrolled" {
        return Err(ApiError::conflict("conflict", "device is revoked"));
    }
    let scope = expected_scope(&CommandPayload::Boot(body.command.clone()));
    let needed = scope_name(&scope);
    authorize_device(&app, &op, &device, &needed).await?;
    validate_boot(&app, &device.id, &body.command).await?;
    let now = app.clock.unix();
    let ttl = match &body.command {
        BootCommand::BootRecovery { .. } => app.config.recovery_command_ttl,
        _ => app.config.boot_command_ttl,
    };
    let sequence = app.db.reserve_sequence(&device.id).await?;
    let envelope = sign_boot(&app, &device.id, sequence, now, ttl, body.command).await?;
    let payload = serde_json::to_string(&envelope.payload).map_err(|_| ApiError::internal())?;
    let stored = serde_json::to_string(&envelope).map_err(|_| ApiError::internal())?;
    app.db
        .insert_command(
            &envelope.command_id,
            &device.id,
            sequence,
            &scope_name(&envelope.required_scope),
            &payload,
            &stored,
            Some(&op.id),
            envelope.issued_at_unix,
            envelope.expires_at_unix,
        )
        .await?;
    app.db
        .audit(
            now,
            "operator",
            &op.id,
            "command.issue",
            Some(&device.id),
            &json!({ "command_id": envelope.command_id, "state": "requested", "scope": scope_name(&envelope.required_scope) }),
        )
        .await?;
    Ok(Json(json!({
        "state": "requested",
        "note": command_state_note(),
        "command": envelope,
    })))
}

pub async fn commands(
    State(app): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let op = require_operator(&app, &headers, &axum::http::Method::GET).await?;
    let device = load_device(&app, &id).await?;
    authorize_device(&app, &op, &device, "read_only").await?;
    let rows = app.db.commands(&id).await?;
    Ok(Json(json!({
        "commands": rows.iter().map(command_json).collect::<Vec<_>>(),
    })))
}

pub async fn pending(
    State(app): State<AppState>,
    Path(id): Path<String>,
    CertDer(der): CertDer,
) -> Result<Json<Value>, ApiError> {
    let dev = require_device(&app, &der).await?;
    if dev.id != id {
        return Err(ApiError::not_found());
    }
    Ok(Json(
        json!({ "commands": pending_values(&app, &dev).await? }),
    ))
}

pub async fn boot_policy(
    State(app): State<AppState>,
    Path(id): Path<String>,
    CertDer(der): CertDer,
) -> Result<Json<Value>, ApiError> {
    let dev = require_device(&app, &der).await?;
    if dev.id != id {
        return Err(ApiError::not_found());
    }
    let now = app.clock.unix();
    let policy = load_policy(&app, &id).await?;
    let commands = app.db.pending(&id, now).await?;
    let mut envelopes = Vec::new();
    for row in commands {
        let Ok(envelope) = serde_json::from_str::<CommandEnvelope>(&row.envelope_json) else {
            continue;
        };
        if dev.status == "revoked" {
            continue;
        }
        if envelope.required_scope.is_allowed_in_uefi()
            && matches!(envelope.payload, CommandPayload::Boot(_))
            && envelope.required_scope == AuthScope::BootSelect
        {
            envelopes.push(envelope);
        }
    }
    Ok(Json(json!({
        "schema_version": SCHEMA_VERSION_V1,
        "device_id": id,
        "policy_is_advisory": true,
        "policy": policy,
        "commands": envelopes,
    })))
}

pub async fn ack(
    State(app): State<AppState>,
    Path((id, command_id)): Path<(String, String)>,
    CertDer(der): CertDer,
    In(body): In<AckBody>,
) -> Result<Json<Value>, ApiError> {
    let dev = require_device(&app, &der).await?;
    if dev.id != id {
        return Err(ApiError::not_found());
    }
    if !matches!(
        body.state.as_str(),
        "accepted" | "executed" | "failed" | "rejected"
    ) {
        return Err(ApiError::invalid("ack state is not recognized"));
    }
    let message = body
        .message
        .as_deref()
        .map(|value| clean_text(value, 400).unwrap_or_else(|| "device report".to_string()));
    let code = body.code.as_deref().and_then(|value| clean_text(value, 80));
    let state = app
        .db
        .apply_ack(
            &id,
            &command_id,
            &body.state,
            code.as_deref(),
            message.as_deref(),
            app.clock.unix(),
        )
        .await?;
    if state == "executed"
        && let Some(command) = app.db.command(&command_id).await?
    {
        record_execution(&app, &command).await?;
    }
    app.db
        .audit(
            app.clock.unix(),
            "device",
            &id,
            "command.ack",
            Some(&id),
            &json!({ "command_id": command_id, "state": state }),
        )
        .await?;
    Ok(Json(json!({ "command_id": command_id, "state": state })))
}

pub async fn put_targets(
    State(app): State<AppState>,
    Path(id): Path<String>,
    CertDer(der): CertDer,
    In(body): In<TargetsBody>,
) -> Result<Json<Value>, ApiError> {
    let dev = enrolled(&app, &der, &id).await?;
    if body.targets.len() > 64 {
        return Err(ApiError::invalid("too many boot targets"));
    }
    let mut rows = Vec::new();
    for target in &body.targets {
        if !target.id.is_valid() {
            return Err(ApiError::invalid("boot target id is not valid"));
        }
        let payload = serde_json::to_string(target).map_err(|_| ApiError::internal())?;
        rows.push((target.id.0.clone(), payload));
    }
    app.db
        .replace_targets(&dev.id, &rows, app.clock.unix())
        .await?;
    Ok(Json(json!({ "count": rows.len() })))
}

pub async fn put_inventory(
    State(app): State<AppState>,
    Path(id): Path<String>,
    CertDer(der): CertDer,
    In(body): In<InventoryBody>,
) -> Result<StatusCodeOk, ApiError> {
    let dev = enrolled(&app, &der, &id).await?;
    if !body.inventory.is_object() {
        return Err(ApiError::invalid("inventory must be a JSON object"));
    }
    let text = body.inventory.to_string();
    if text.len() > 65_536 {
        return Err(ApiError::invalid("inventory is too large"));
    }
    app.db
        .upsert_inventory(&dev.id, &text, app.clock.unix())
        .await?;
    Ok(StatusCodeOk)
}

pub async fn heartbeat(
    State(app): State<AppState>,
    Path(id): Path<String>,
    CertDer(der): CertDer,
    In(body): In<HeartbeatBody>,
) -> Result<Json<Value>, ApiError> {
    let dev = enrolled(&app, &der, &id).await?;
    let component =
        clean_text(&body.component, 40).ok_or_else(|| ApiError::invalid("component is invalid"))?;
    let version = clean_text(&body.software_version, 40)
        .ok_or_else(|| ApiError::invalid("version is invalid"))?;
    let mode = clean_text(&body.mode, 40).ok_or_else(|| ApiError::invalid("mode is invalid"))?;
    app.db
        .upsert_status(
            &dev.id,
            &component,
            &version,
            &mode,
            &body.detail.to_string(),
            app.clock.unix(),
        )
        .await?;
    Ok(Json(json!({ "ok": true })))
}

pub async fn put_policy(
    State(app): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    In(body): In<PolicyBody>,
) -> Result<Json<BootPolicy>, ApiError> {
    let op = require_operator(&app, &headers, &axum::http::Method::PUT).await?;
    let device = load_device(&app, &id).await?;
    authorize_device(&app, &op, &device, "boot_select").await?;
    if body.max_failed_attempts == 0 || body.max_failed_attempts > 10 {
        return Err(ApiError::invalid(
            "max_failed_attempts must be 1 through 10",
        ));
    }
    if body.network_policy_timeout_ms > 5_000 {
        return Err(ApiError::invalid(
            "network_policy_timeout_ms cannot exceed 5000",
        ));
    }
    let mut policy = load_policy(&app, &id).await?;
    policy.timeout_seconds = body.timeout_seconds;
    policy.offline_behavior = body.offline_behavior;
    policy.allow_remote_boot_select = body.allow_remote_boot_select;
    policy.max_failed_attempts = body.max_failed_attempts;
    policy.network_policy_timeout_ms = body.network_policy_timeout_ms;
    policy.policy_revision = policy.policy_revision.saturating_add(1);
    let text = serde_json::to_string(&policy).map_err(|_| ApiError::internal())?;
    app.db.save_policy(&id, &text, app.clock.unix()).await?;
    app.db
        .audit(
            app.clock.unix(),
            "operator",
            &op.id,
            "policy.update",
            Some(&id),
            &json!({ "policy_revision": policy.policy_revision }),
        )
        .await?;
    Ok(Json(policy))
}

pub async fn revoke(
    State(app): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    In(body): In<RevokeBody>,
) -> Result<Json<Value>, ApiError> {
    let op = require_operator(&app, &headers, &axum::http::Method::POST).await?;
    if !op.roles.iter().any(|role| role == "admin") {
        return Err(ApiError::forbidden("forbidden", "admin role required"));
    }
    let device = load_device(&app, &id).await?;
    let reason =
        clean_text(&body.reason, 200).ok_or_else(|| ApiError::invalid("reason is required"))?;
    let now = app.clock.unix();
    if device.status == "enrolled" {
        if let Ok(sequence) = app.db.reserve_sequence(&device.id).await {
            let envelope = sign_payload(
                &app,
                &device.id,
                sequence,
                now,
                Duration::from_secs(900),
                AuthScope::Admin,
                CommandPayload::RevokeEnrollment {
                    reason: reason.clone(),
                },
            )
            .await?;
            let payload =
                serde_json::to_string(&envelope.payload).unwrap_or_else(|_| "{}".to_string());
            let stored = serde_json::to_string(&envelope).unwrap_or_else(|_| "{}".to_string());
            app.db
                .insert_command(
                    &envelope.command_id,
                    &device.id,
                    sequence,
                    "admin",
                    &payload,
                    &stored,
                    Some(&op.id),
                    envelope.issued_at_unix,
                    envelope.expires_at_unix,
                )
                .await?;
        }
        app.db.revoke_device(&device.id, &reason, now).await?;
    }
    app.db
        .audit(
            now,
            "operator",
            &op.id,
            "device.revoke",
            Some(&id),
            &json!({ "reason": reason }),
        )
        .await?;
    Ok(Json(json!({ "status": "revoked" })))
}

pub async fn rotate_key(
    State(app): State<AppState>,
    Path(id): Path<String>,
    CertDer(der): CertDer,
    In(body): In<RotateBody>,
) -> Result<Json<Value>, ApiError> {
    let dev = enrolled(&app, &der, &id).await?;
    let current = decode_key_32(&dev.public_key_hex)
        .map_err(|_| ApiError::invalid("stored device key is corrupt"))?;
    let new_key = decode_key_32(&body.new_public_key_ed25519_hex)
        .map_err(|_| ApiError::invalid("new public key must be 32 bytes of hex"))?;
    let signature = hex::decode(body.signature_ed25519_hex.trim())
        .ok()
        .and_then(|bytes| Signature::from_slice(&bytes).ok())
        .ok_or_else(|| ApiError::invalid("rotation signature is invalid"))?;
    let verify = VerifyingKey::from_bytes(&current)
        .map_err(|_| ApiError::invalid("stored device key is corrupt"))?;
    let mut message = b"sbm-rotate-v1\0".to_vec();
    message.extend(dev.id.as_bytes());
    message.push(0);
    message.extend(new_key);
    verify
        .verify(&message, &signature)
        .map_err(|_| ApiError::forbidden("bad_signature", "rotation signature was rejected"))?;
    let cert_pem = {
        let material = app.identity.read().await;
        material.issue_device_cert(&dev.id, &new_key)?
    };
    let cert_sha = cert_sha256_pem(&cert_pem)?;
    app.db
        .rotate_cert(
            &dev.id,
            &dev.cert_sha256,
            &cert_sha,
            &cert_pem,
            &hex::encode(new_key),
            app.clock.unix(),
        )
        .await?;
    app.db
        .audit(
            app.clock.unix(),
            "device",
            &dev.id,
            "device.rotate_key",
            Some(&dev.id),
            &json!({}),
        )
        .await?;
    Ok(Json(
        json!({ "client_cert_pem": cert_pem, "cert_sha256": cert_sha }),
    ))
}

pub async fn grant(
    State(app): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    In(body): In<GrantBody>,
) -> Result<Json<Value>, ApiError> {
    let op = require_operator(&app, &headers, &axum::http::Method::POST).await?;
    if !op.roles.iter().any(|role| role == "admin") {
        return Err(ApiError::forbidden("forbidden", "admin role required"));
    }
    if !crate::authz::known_role(&body.role)
        || body.role == "storage_destructive"
        || body.role == "admin"
    {
        return Err(ApiError::invalid("that role cannot be granted on a device"));
    }
    let _device = load_device(&app, &id).await?;
    if app.db.operator_by_id(&body.operator_id).await?.is_none() {
        return Err(ApiError::not_found());
    }
    app.db.add_grant(&id, &body.operator_id, &body.role).await?;
    app.db
        .audit(
            app.clock.unix(),
            "operator",
            &op.id,
            "device.grant",
            Some(&id),
            &json!({ "operator_id": body.operator_id, "role": body.role }),
        )
        .await?;
    Ok(Json(json!({ "ok": true })))
}

pub async fn storage_disabled() -> Result<Json<Value>, ApiError> {
    Err(ApiError::destructive_disabled())
}

pub async fn install_disabled() -> Result<Json<Value>, ApiError> {
    Err(ApiError::os_install_disabled())
}

pub async fn open_recovery(
    State(app): State<AppState>,
    headers: axum::http::HeaderMap,
    In(body): In<RecoveryBody>,
) -> Result<Json<Value>, ApiError> {
    let op = require_operator(&app, &headers, &axum::http::Method::POST).await?;
    let device = load_device(&app, &body.device_id).await?;
    authorize_device(&app, &op, &device, "recovery_access").await?;
    let id = new_id();
    let now = app.clock.unix();
    let expires = now + 900;
    app.db
        .create_recovery(&id, &device.id, &op.id, "wayvnc", now, expires)
        .await?;
    app.hub.open(&format!("{id}:vnc"));
    app.hub.open(&format!("{id}:terminal"));
    app.db
        .audit(
            now,
            "operator",
            &op.id,
            "recovery.open",
            Some(&device.id),
            &json!({ "session_id": id }),
        )
        .await?;
    Ok(Json(json!({
        "id": id,
        "state": "authorized",
        "expires_at_unix": expires,
        "note": "The session is authorized. It is not connected until the device dials out. No VNC port is published.",
        "vnc_path": format!("/v1/recovery-sessions/{id}/vnc"),
        "terminal_path": format!("/v1/recovery-sessions/{id}/terminal"),
    })))
}

pub async fn recovery_status(
    State(app): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let op = require_operator(&app, &headers, &axum::http::Method::GET).await?;
    let Some(session) = app.db.recovery(&id).await? else {
        return Err(ApiError::not_found());
    };
    if session["operator_id"] != op.id && !op.roles.iter().any(|role| role == "admin") {
        return Err(ApiError::not_found());
    }
    Ok(Json(session))
}

pub async fn close_recovery(
    State(app): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let op = require_operator(&app, &headers, &axum::http::Method::POST).await?;
    let Some(session) = app.db.recovery(&id).await? else {
        return Err(ApiError::not_found());
    };
    if session["operator_id"] != op.id && !op.roles.iter().any(|role| role == "admin") {
        return Err(ApiError::not_found());
    }
    app.db
        .set_recovery_state(&id, "closed", app.clock.unix(), true)
        .await?;
    app.hub.close(&format!("{id}:vnc"));
    app.hub.close(&format!("{id}:terminal"));
    Ok(Json(json!({ "state": "closed" })))
}

pub async fn device_tunnel(
    State(app): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<TunnelQuery>,
    CertDer(der): CertDer,
    ws: WebSocketUpgrade,
) -> Result<axum::response::Response, ApiError> {
    let dev = enrolled(&app, &der, &id).await?;
    let kind = tunnel_kind(query.kind.as_deref())?;
    let session = open_session(&app, &query.session, &dev.id).await?;
    let Some((tx, rx)) = app.hub.take_device_end(&format!("{}:{kind}", session)) else {
        return Err(ApiError::conflict(
            "conflict",
            "device tunnel is already attached",
        ));
    };
    app.db
        .set_recovery_state(&session, "device_connected", app.clock.unix(), false)
        .await?;
    Ok(ws.on_upgrade(move |socket| relay(socket, tx, rx)))
}

pub async fn browser_vnc(
    State(app): State<AppState>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<axum::response::Response, ApiError> {
    browser_socket(&app, &headers, &id, "vnc", ws).await
}

pub async fn browser_terminal(
    State(app): State<AppState>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<axum::response::Response, ApiError> {
    browser_socket(&app, &headers, &id, "terminal", ws).await
}

pub async fn audit(
    State(app): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Result<Json<Value>, ApiError> {
    let op = require_operator(&app, &headers, &axum::http::Method::GET).await?;
    if !crate::authz::has_role(&op.roles, "read_only") {
        return Err(ApiError::forbidden("forbidden", "missing role"));
    }
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    Ok(Json(json!({
        "entries": app.db.list_audit(query.before, i64::from(limit)).await?,
    })))
}

pub async fn rotate_server_key(
    State(app): State<AppState>,
    headers: axum::http::HeaderMap,
    In(body): In<ConfirmBody>,
) -> Result<Json<Value>, ApiError> {
    let op = require_operator(&app, &headers, &axum::http::Method::POST).await?;
    if !op.roles.iter().any(|role| role == "admin") {
        return Err(ApiError::forbidden("forbidden", "admin role required"));
    }
    if body.confirm != "rotate" {
        return Err(ApiError::invalid("confirm must be the string rotate"));
    }
    let (previous, current, public) = {
        let mut material = app.identity.write().await;
        let previous = material.rotate_command_key(&app.config.data_dir)?;
        let current = material.issuer_key_id.clone();
        let public = material.command_public_hex.clone();
        (previous, current, public)
    };
    app.db
        .audit(
            app.clock.unix(),
            "operator",
            &op.id,
            "server.rotate_command_key",
            None,
            &json!({ "previous_public_hex": previous, "issuer_key_id": current }),
        )
        .await?;
    Ok(Json(json!({
        "issuer_key_id": current,
        "command_verify_key_ed25519_hex": public,
        "note": "Enrolled devices keep the previous verify key and will reject new commands until they enroll again.",
    })))
}

#[derive(Deserialize)]
pub struct AuditQuery {
    before: Option<i64>,
    limit: Option<u32>,
}

pub(crate) struct StatusCodeOk;

impl IntoResponse for StatusCodeOk {
    fn into_response(self) -> axum::response::Response {
        axum::http::StatusCode::NO_CONTENT.into_response()
    }
}

async fn browser_socket(
    app: &AppState,
    headers: &axum::http::HeaderMap,
    id: &str,
    kind: &str,
    ws: WebSocketUpgrade,
) -> Result<axum::response::Response, ApiError> {
    let op = require_operator(app, headers, &axum::http::Method::GET).await?;
    let session = open_session_for_operator(app, id, &op).await?;
    let Some((tx, rx)) = app.hub.take_browser_end(&format!("{session}:{kind}")) else {
        return Err(ApiError::conflict(
            "conflict",
            "browser tunnel is already attached",
        ));
    };
    app.db
        .set_recovery_state(&session, "live", app.clock.unix(), false)
        .await?;
    Ok(ws.on_upgrade(move |socket| relay(socket, tx, rx)))
}

async fn relay(
    mut socket: WebSocket,
    tx: UnboundedSender<Vec<u8>>,
    mut rx: UnboundedReceiver<Vec<u8>>,
) {
    loop {
        tokio::select! {
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Binary(bytes))) => {
                        if tx.send(bytes.to_vec()).is_err() { break; }
                    }
                    Some(Ok(Message::Text(text))) => {
                        if tx.send(text.as_bytes().to_vec()).is_err() { break; }
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    _ => {}
                }
            }
            outgoing = rx.recv() => {
                let Some(bytes) = outgoing else { break; };
                if socket.send(Message::Binary(bytes.into())).await.is_err() {
                    break;
                }
            }
        }
    }
}

async fn enrolled(app: &AppState, der: &[u8], id: &str) -> Result<Dev, ApiError> {
    let dev = require_device(app, der).await?;
    if dev.id != id || dev.status != "enrolled" {
        return Err(ApiError::not_found());
    }
    Ok(dev)
}

async fn pending_values(app: &AppState, dev: &Dev) -> Result<Vec<Value>, ApiError> {
    let now = app.clock.unix();
    let rows = app.db.pending(&dev.id, now).await?;
    let mut out = Vec::new();
    for row in rows {
        if dev.status == "revoked" && !row.payload_json.contains("revoke_enrollment") {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<Value>(&row.envelope_json) {
            out.push(value);
        }
    }
    Ok(out)
}

async fn validate_boot(
    app: &AppState,
    device_id: &str,
    command: &BootCommand,
) -> Result<(), ApiError> {
    if let BootCommand::BootTarget {
        target_id,
        extra_cmdline_preset,
        ..
    } = command
    {
        if !target_id.is_valid() {
            return Err(ApiError::invalid("boot target id is not valid"));
        }
        let targets = app.db.targets(device_id).await?;
        let known = targets
            .iter()
            .any(|target| target.get("id").and_then(Value::as_str) == Some(target_id.as_str()));
        if !known {
            return Err(ApiError::conflict(
                "target_not_found",
                "that boot target is not on the device",
            ));
        }
        if let Some(preset) = extra_cmdline_preset
            && !preset_allowed(preset)
        {
            return Err(ApiError::invalid("command line preset is not allowlisted"));
        }
    }
    Ok(())
}

async fn sign_boot(
    app: &AppState,
    device_id: &str,
    sequence: u64,
    now: i64,
    ttl: Duration,
    command: BootCommand,
) -> Result<CommandEnvelope, ApiError> {
    let payload = CommandPayload::Boot(command);
    let scope = expected_scope(&payload);
    sign_payload(app, device_id, sequence, now, ttl, scope, payload).await
}

async fn sign_payload(
    app: &AppState,
    device_id: &str,
    sequence: u64,
    now: i64,
    ttl: Duration,
    scope: AuthScope,
    payload: CommandPayload,
) -> Result<CommandEnvelope, ApiError> {
    let (key, issuer_key_id) = {
        let material = app.identity.read().await;
        (material.signing_key(), material.issuer_key_id.clone())
    };
    let mut envelope = CommandEnvelope {
        schema_version: SCHEMA_VERSION_V1.to_string(),
        command_id: new_id(),
        device_id: device_id.to_string(),
        sequence,
        issued_at_unix: now,
        expires_at_unix: now + i64::try_from(ttl.as_secs()).unwrap_or(900),
        required_scope: scope,
        issuer_key_id,
        payload,
        signature_ed25519_hex: String::new(),
    };
    sign(&key, &mut envelope);
    Ok(envelope)
}

fn fresh_policy() -> BootPolicy {
    BootPolicy {
        schema_version: SCHEMA_VERSION_V1.to_string(),
        policy_revision: 1,
        default_target: None,
        fallback_target: None,
        timeout_seconds: 5,
        one_shot: None,
        max_failed_attempts: 3,
        network_policy_timeout_ms: 3_000,
        allow_remote_boot_select: true,
        offline_behavior: OfflineBehavior::UseLocalPolicy,
    }
}

async fn load_policy(app: &AppState, device_id: &str) -> Result<BootPolicy, ApiError> {
    let text = app
        .db
        .policy(device_id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    serde_json::from_str(&text).map_err(|_| ApiError::internal())
}

async fn record_execution(app: &AppState, command: &crate::db::CommandRow) -> Result<(), ApiError> {
    let Ok(payload) = serde_json::from_str::<CommandPayload>(&command.payload_json) else {
        return Ok(());
    };
    let CommandPayload::Boot(BootCommand::BootTarget {
        target_id,
        one_shot,
        ..
    }) = payload
    else {
        return Ok(());
    };
    let mut policy = load_policy(app, &command.device_id).await?;
    if one_shot {
        policy.one_shot = Some(OneShotBoot {
            target_id,
            command_id: Some(command.command_id.clone()),
            expires_at_unix: Some(command.expires_at),
            consumed: true,
        });
    } else {
        policy.default_target = Some(target_id);
    }
    policy.policy_revision = policy.policy_revision.saturating_add(1);
    let text = serde_json::to_string(&policy).map_err(|_| ApiError::internal())?;
    app.db
        .save_policy(&command.device_id, &text, app.clock.unix())
        .await
}

fn device_summary(device: &crate::db::DeviceListItem, now: i64) -> Value {
    json!({
        "id": device.id,
        "hostname": device.hostname,
        "status": device.status,
        "simulated": device.simulated,
        "online": online(device.last_heartbeat_at, now),
        "last_seen_at": device.last_heartbeat_at,
        "mode": device.mode,
        "component": device.component,
        "software_version": device.software_version,
        "created_at": device.created_at,
        "owner_id": device.owner_id,
        "public_key_ed25519_hex": device.public_key_hex,
        "cert_sha256": device.cert_sha256,
    })
}

async fn device_detail_json(
    app: &AppState,
    device: &crate::db::DeviceRow,
) -> Result<Value, ApiError> {
    let now = app.clock.unix();
    let list = app
        .db
        .list_devices(&device.owner_id, true)
        .await?
        .into_iter()
        .find(|item| item.id == device.id);
    let summary = list
        .as_ref()
        .map(|item| device_summary(item, now))
        .unwrap_or_else(|| json!({ "id": device.id, "hostname": device.hostname }));
    let commands = app.db.commands(&device.id).await?;
    Ok(json!({
        "device": summary,
        "created_at": device.created_at,
        "last_seen_at": device.last_seen_at,
        "simulated": device.simulated,
        "cert_pem": device.cert_pem,
        "public_key_ed25519_hex": device.public_key_hex,
        "platform": serde_json::from_str::<Value>(&device.platform_json).unwrap_or(Value::Null),
        "targets": app.db.targets(&device.id).await?,
        "policy": load_policy(app, &device.id).await.ok(),
        "commands": commands.iter().map(command_json).collect::<Vec<_>>(),
        "inventory": app.db.inventory(&device.id).await?,
        "recovery_sessions": app.db.recovery_for_device(&device.id).await?,
    }))
}

fn command_json(row: &crate::db::CommandRow) -> Value {
    json!({
        "command_id": row.command_id,
        "device_id": row.device_id,
        "sequence": row.sequence,
        "state": row.state,
        "required_scope": row.required_scope,
        "payload": serde_json::from_str::<Value>(&row.payload_json).unwrap_or(Value::Null),
        "envelope": serde_json::from_str::<Value>(&row.envelope_json).unwrap_or(Value::Null),
        "issued_at": row.issued_at,
        "expires_at": row.expires_at,
        "delivered_at": row.delivered_at,
        "accepted_at": row.accepted_at,
        "finished_at": row.finished_at,
        "result_code": row.result_code,
        "result_message": row.result_message,
    })
}

fn san_from_cert(pem: &str) -> Result<String, ApiError> {
    let der = crate::identity::pem_first_der(pem)?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der).map_err(|_| ApiError::internal())?;
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for name in &ext.value.general_names {
            if let x509_parser::extensions::GeneralName::URI(uri) = name
                && let Some(id) = uri.strip_prefix("urn:sbm:device:")
            {
                return Ok(id.to_string());
            }
        }
    }
    Err(ApiError::internal())
}

fn tunnel_kind(kind: Option<&str>) -> Result<&'static str, ApiError> {
    match kind.unwrap_or("vnc") {
        "vnc" => Ok("vnc"),
        "terminal" => Ok("terminal"),
        _ => Err(ApiError::invalid("tunnel kind must be vnc or terminal")),
    }
}

async fn open_session(app: &AppState, id: &str, device_id: &str) -> Result<String, ApiError> {
    let Some(session) = app.db.recovery(id).await? else {
        return Err(ApiError::not_found());
    };
    if session["device_id"] != device_id || session["state"] == "closed" {
        return Err(ApiError::not_found());
    }
    if session["expires_at"].as_i64().unwrap_or(0) < app.clock.unix() {
        return Err(ApiError::conflict(
            "expired",
            "recovery session has expired",
        ));
    }
    Ok(id.to_string())
}

async fn open_session_for_operator(app: &AppState, id: &str, op: &Op) -> Result<String, ApiError> {
    let Some(session) = app.db.recovery(id).await? else {
        return Err(ApiError::not_found());
    };
    let owner = session["operator_id"].as_str() == Some(op.id.as_str());
    if !owner && !op.roles.iter().any(|role| role == "admin") {
        return Err(ApiError::not_found());
    }
    if session["state"] == "closed"
        || session["expires_at"].as_i64().unwrap_or(0) < app.clock.unix()
    {
        return Err(ApiError::conflict(
            "expired",
            "recovery session has expired",
        ));
    }
    Ok(id.to_string())
}
