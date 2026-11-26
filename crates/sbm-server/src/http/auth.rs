use super::{In, require_operator};
use crate::authz::known_role;
use crate::error::ApiError;
use crate::state::{AppState, Challenge};
use crate::util::{clean_text, random_token, secret_matches, set_cookie, sha256_hex};
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;
use webauthn_rs::prelude::{
    Passkey, PublicKeyCredential, RegisterPublicKeyCredential, WebauthnError,
};

#[derive(Clone)]
pub struct Op {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub roles: Vec<String>,
}

#[derive(Deserialize)]
pub(crate) struct DevLogin {
    secret: String,
}

#[derive(Deserialize)]
pub(crate) struct DevOperator {
    username: String,
    display_name: Option<String>,
    roles: Vec<String>,
}

#[derive(Deserialize)]
pub(crate) struct RegisterStart {
    username: String,
    display_name: String,
}

#[derive(Deserialize)]
pub(crate) struct CredentialBody {
    credential: Value,
}

#[derive(Deserialize)]
pub(crate) struct LoginStart {
    username: String,
}

pub async fn dev_login(
    State(app): State<AppState>,
    In(body): In<DevLogin>,
) -> Result<Response, ApiError> {
    if !app.config.dev_bootstrap {
        return Err(ApiError::not_found());
    }
    let Some(secret) = app.config.bootstrap_secret.as_deref() else {
        return Err(ApiError::not_found());
    };
    if !secret_matches(secret, &body.secret) {
        return Err(ApiError::unauthorized("bootstrap secret was rejected"));
    }
    let operator = app
        .db
        .operator_by_username("lab")
        .await?
        .ok_or_else(ApiError::internal)?;
    let (token, csrf, op) = issue_session(&app, &operator.id).await?;
    app.db
        .audit(
            app.clock.unix(),
            "operator",
            &op.id,
            "operator.dev_login",
            None,
            &json!({ "username": "lab" }),
        )
        .await?;
    Ok(session_response(&app, token, csrf, &op))
}

pub async fn dev_operator(
    State(app): State<AppState>,
    headers: HeaderMap,
    In(body): In<DevOperator>,
) -> Result<Response, ApiError> {
    if !app.config.dev_bootstrap {
        return Err(ApiError::not_found());
    }
    let caller = require_operator(&app, &headers, &axum::http::Method::POST).await?;
    if !caller.roles.iter().any(|role| role == "admin") {
        return Err(ApiError::forbidden("forbidden", "admin role required"));
    }
    let username = username(&body.username)?;
    if app.db.operator_by_username(&username).await?.is_some() {
        return Err(ApiError::conflict(
            "conflict",
            "username is already registered",
        ));
    }
    if body.roles.is_empty()
        || body
            .roles
            .iter()
            .any(|role| !known_role(role) || role == "storage_destructive")
    {
        return Err(ApiError::invalid(
            "roles must be known and cannot include storage_destructive",
        ));
    }
    let id = Uuid::now_v7().to_string();
    let display = body
        .display_name
        .as_deref()
        .and_then(|value| clean_text(value, 80))
        .unwrap_or_else(|| username.clone());
    let now = app.clock.unix();
    app.db
        .insert_operator(&id, &username, &display, now)
        .await?;
    for role in &body.roles {
        app.db.set_role(&id, role).await?;
    }
    app.db
        .audit(
            now,
            "operator",
            &caller.id,
            "operator.dev_create",
            None,
            &json!({ "username": username }),
        )
        .await?;
    let (token, csrf, op) = issue_session(&app, &id).await?;
    Ok(session_response(&app, token, csrf, &op))
}

pub async fn register_options(
    State(app): State<AppState>,
    headers: HeaderMap,
    In(body): In<RegisterStart>,
) -> Result<Response, ApiError> {
    let username = username(&body.username)?;
    let display = clean_text(&body.display_name, 80)
        .ok_or_else(|| ApiError::invalid("display name is empty or too long"))?;
    let count = app.db.count_operators().await?;
    let existing = if count == 0 {
        None
    } else {
        let op = require_operator(&app, &headers, &axum::http::Method::POST).await?;
        if !op.roles.iter().any(|role| role == "admin") {
            return Err(ApiError::forbidden(
                "forbidden",
                "an admin registers passkeys",
            ));
        }
        if op.username != username {
            return Err(ApiError::invalid(
                "a passkey can only be added to the signed-in admin",
            ));
        }
        Some(op.id)
    };
    if existing.is_none() && app.db.operator_by_username(&username).await?.is_some() {
        return Err(ApiError::conflict(
            "conflict",
            "username is already registered",
        ));
    }
    let user_id = existing
        .clone()
        .unwrap_or_else(|| Uuid::now_v7().to_string());
    let uuid = Uuid::parse_str(&user_id).map_err(|_| ApiError::internal())?;
    let (challenge, state) = app
        .webauthn
        .start_passkey_registration(uuid, &username, &display, None)
        .map_err(passkey_err)?;
    let id = random_token();
    app.challenges.insert(
        id.clone(),
        Challenge::Register {
            state,
            username,
            display_name: display,
            user_id,
            existing_operator: existing,
            expires_at: app.clock.unix() + 300,
        },
    );
    let mut response = Json(challenge).into_response();
    append_cookie(
        &mut response,
        "sbm_challenge",
        &id,
        300,
        true,
        !app.config.insecure_http,
    );
    Ok(response)
}

pub async fn register_finish(
    State(app): State<AppState>,
    headers: HeaderMap,
    In(body): In<CredentialBody>,
) -> Result<Response, ApiError> {
    let id = challenge_id(&headers)?;
    let Challenge::Register {
        state,
        username,
        display_name,
        user_id,
        existing_operator,
        expires_at,
    } = app
        .challenges
        .take(&id)
        .ok_or_else(|| ApiError::invalid("registration expired"))?
    else {
        return Err(ApiError::invalid("registration expired"));
    };
    if expires_at < app.clock.unix() {
        return Err(ApiError::invalid("registration expired"));
    }
    let credential: RegisterPublicKeyCredential = serde_json::from_value(body.credential)
        .map_err(|_| ApiError::invalid("passkey credential was not understood"))?;
    let passkey = app
        .webauthn
        .finish_passkey_registration(&credential, &state)
        .map_err(passkey_err)?;
    let now = app.clock.unix();
    let operator_id = if let Some(existing) = existing_operator {
        existing
    } else {
        app.db
            .insert_operator(&user_id, &username, &display_name, now)
            .await?;
        app.db.set_role(&user_id, "admin").await?;
        user_id
    };
    store_passkey(&app, &operator_id, &passkey, now).await?;
    app.db
        .audit(
            now,
            "operator",
            &operator_id,
            "operator.passkey_register",
            None,
            &json!({ "username": username }),
        )
        .await?;
    let (token, csrf, op) = issue_session(&app, &operator_id).await?;
    Ok(session_response(&app, token, csrf, &op))
}

pub async fn login_options(
    State(app): State<AppState>,
    In(body): In<LoginStart>,
) -> Result<Response, ApiError> {
    let username = username(&body.username)?;
    let operator = app
        .db
        .operator_by_username(&username)
        .await?
        .ok_or_else(|| ApiError::unauthorized("unknown account or passkey"))?;
    let passkeys = load_passkeys(&app, &operator.id).await?;
    if passkeys.is_empty() {
        return Err(ApiError::unauthorized("unknown account or passkey"));
    }
    let (challenge, state) = app
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(passkey_err)?;
    let id = random_token();
    app.challenges.insert(
        id.clone(),
        Challenge::Login {
            state,
            operator_id: operator.id,
            expires_at: app.clock.unix() + 300,
        },
    );
    let mut response = Json(challenge).into_response();
    append_cookie(
        &mut response,
        "sbm_challenge",
        &id,
        300,
        true,
        !app.config.insecure_http,
    );
    Ok(response)
}

pub async fn login_finish(
    State(app): State<AppState>,
    headers: HeaderMap,
    In(body): In<CredentialBody>,
) -> Result<Response, ApiError> {
    let id = challenge_id(&headers)?;
    let Challenge::Login {
        state,
        operator_id,
        expires_at,
    } = app
        .challenges
        .take(&id)
        .ok_or_else(|| ApiError::invalid("sign-in expired"))?
    else {
        return Err(ApiError::invalid("sign-in expired"));
    };
    if expires_at < app.clock.unix() {
        return Err(ApiError::invalid("sign-in expired"));
    }
    let credential: PublicKeyCredential = serde_json::from_value(body.credential)
        .map_err(|_| ApiError::invalid("passkey assertion was not understood"))?;
    let auth = app
        .webauthn
        .finish_passkey_authentication(&credential, &state)
        .map_err(passkey_err)?;
    let mut passkeys = load_passkeys(&app, &operator_id).await?;
    if let Some(passkey) = passkeys
        .iter_mut()
        .find(|passkey| passkey.cred_id() == auth.cred_id())
    {
        let _ = passkey.update_credential(&auth);
        let json = serde_json::to_string(passkey).map_err(|_| ApiError::internal())?;
        let id = URL_SAFE_NO_PAD.encode(passkey.cred_id());
        app.db
            .insert_passkey(&id, &operator_id, &json, app.clock.unix())
            .await
            .ok();
    }
    let (token, csrf, op) = issue_session(&app, &operator_id).await?;
    app.db
        .audit(
            app.clock.unix(),
            "operator",
            &op.id,
            "operator.login",
            None,
            &json!({}),
        )
        .await?;
    Ok(session_response(&app, token, csrf, &op))
}

pub async fn logout(State(app): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    let op = require_operator(&app, &headers, &axum::http::Method::POST).await?;
    if let Some(token) = bearer_or_cookie(&headers) {
        app.db.delete_session(&sha256_hex(token.as_bytes())).await?;
    }
    app.db
        .audit(
            app.clock.unix(),
            "operator",
            &op.id,
            "operator.logout",
            None,
            &json!({}),
        )
        .await?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    let secure = !app.config.insecure_http;
    append_raw(
        &mut response,
        &crate::util::clear_cookie("sbm_session", true, secure),
    );
    append_raw(
        &mut response,
        &crate::util::clear_cookie("sbm_csrf", false, secure),
    );
    Ok(response)
}

pub async fn me(State(app): State<AppState>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let op = require_operator(&app, &headers, &axum::http::Method::GET).await?;
    Ok(Json(operator_json(&op)))
}

pub async fn issue_session(
    app: &AppState,
    operator_id: &str,
) -> Result<(String, String, Op), ApiError> {
    let token = random_token();
    let csrf = random_token();
    let now = app.clock.unix();
    let expires = now + i64::try_from(app.config.session_ttl.as_secs()).unwrap_or(3_600);
    app.db
        .create_session(
            &sha256_hex(token.as_bytes()),
            operator_id,
            &csrf,
            now,
            expires,
        )
        .await?;
    let operator = app
        .db
        .operator_by_id(operator_id)
        .await?
        .ok_or_else(ApiError::internal)?;
    let roles = app.db.roles(operator_id).await?;
    Ok((
        token,
        csrf,
        Op {
            id: operator.id,
            username: operator.username,
            display_name: operator.display_name,
            roles,
        },
    ))
}

fn session_response(app: &AppState, token: String, csrf: String, op: &Op) -> Response {
    let mut response = Json(json!({
        "token": token,
        "csrf_token": csrf,
        "operator": operator_json(op),
    }))
    .into_response();
    let secure = !app.config.insecure_http;
    let max_age = i64::try_from(app.config.session_ttl.as_secs()).unwrap_or(3_600);
    append_cookie(&mut response, "sbm_session", &token, max_age, true, secure);
    append_cookie(&mut response, "sbm_csrf", &csrf, max_age, false, secure);
    response
}

fn operator_json(op: &Op) -> Value {
    json!({
        "id": op.id,
        "username": op.username,
        "display_name": op.display_name,
        "roles": op.roles,
    })
}

fn append_cookie(
    response: &mut Response,
    name: &str,
    value: &str,
    max_age: i64,
    http_only: bool,
    secure: bool,
) {
    append_raw(
        response,
        &set_cookie(name, value, max_age, http_only, secure),
    );
}

fn append_raw(response: &mut Response, cookie: &str) {
    if let Ok(cookie) = cookie.parse() {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
}

fn username(value: &str) -> Result<String, ApiError> {
    let value = value.trim().to_ascii_lowercase();
    let bytes = value.as_bytes();
    if (1..=32).contains(&bytes.len())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && bytes[0].is_ascii_alphanumeric()
    {
        Ok(value)
    } else {
        Err(ApiError::invalid(
            "username must be 1-32 lowercase letters, digits, or hyphens",
        ))
    }
}

fn challenge_id(headers: &HeaderMap) -> Result<String, ApiError> {
    let header = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    crate::util::cookie_value(header, "sbm_challenge")
        .map(str::to_string)
        .ok_or_else(|| ApiError::invalid("missing passkey challenge cookie"))
}

fn bearer_or_cookie(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        && let Some(token) = value.strip_prefix("Bearer ")
    {
        return Some(token.to_string());
    }
    let cookie = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    crate::util::cookie_value(cookie, "sbm_session").map(str::to_string)
}

async fn load_passkeys(app: &AppState, operator_id: &str) -> Result<Vec<Passkey>, ApiError> {
    let mut passkeys = Vec::new();
    for (_id, json) in app.db.passkeys_for(operator_id).await? {
        if let Ok(passkey) = serde_json::from_str::<Passkey>(&json) {
            passkeys.push(passkey);
        }
    }
    Ok(passkeys)
}

async fn store_passkey(
    app: &AppState,
    operator_id: &str,
    passkey: &Passkey,
    now: i64,
) -> Result<(), ApiError> {
    let id = URL_SAFE_NO_PAD.encode(passkey.cred_id());
    let json = serde_json::to_string(passkey).map_err(|_| ApiError::internal())?;
    app.db.insert_passkey(&id, operator_id, &json, now).await
}

fn passkey_err(err: WebauthnError) -> ApiError {
    tracing::info!(error = %err, "passkey ceremony rejected");
    ApiError::unauthorized("passkey ceremony was rejected")
}
