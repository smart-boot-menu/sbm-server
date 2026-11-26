use crate::error::ApiError;
use serde_json::{Value, json};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Row, SqlitePool};
use std::path::Path;
use std::time::Duration;

#[derive(Clone)]
pub struct Db {
    pool: SqlitePool,
}

#[derive(Clone, Debug)]
pub struct OperatorRow {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub disabled: bool,
}

#[derive(Clone, Debug)]
pub struct SessionRow {
    pub operator_id: String,
    pub csrf_token: String,
    pub expires_at: i64,
}

#[derive(Clone, Debug)]
pub struct DeviceRow {
    pub id: String,
    pub hostname: String,
    pub owner_id: String,
    pub public_key_hex: String,
    pub platform_json: String,
    pub status: String,
    pub created_at: i64,
    pub cert_pem: String,
    pub cert_sha256: String,
    pub last_seen_at: Option<i64>,
    pub simulated: bool,
}

#[derive(Clone, Debug)]
pub struct DeviceListItem {
    pub id: String,
    pub hostname: String,
    pub status: String,
    pub simulated: bool,
    pub created_at: i64,
    pub owner_id: String,
    pub public_key_hex: String,
    pub cert_sha256: String,
    pub last_heartbeat_at: Option<i64>,
    pub mode: Option<String>,
    pub component: Option<String>,
    pub software_version: Option<String>,
}

#[derive(Clone, Debug)]
pub struct CommandRow {
    pub command_id: String,
    pub device_id: String,
    pub sequence: i64,
    pub state: String,
    pub required_scope: String,
    pub payload_json: String,
    pub envelope_json: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub delivered_at: Option<i64>,
    pub accepted_at: Option<i64>,
    pub finished_at: Option<i64>,
    pub result_code: Option<String>,
    pub result_message: Option<String>,
}

impl Db {
    pub async fn connect(path: &Path) -> Result<Self, ApiError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|_| ApiError::internal())?;
        }
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(options)
            .await?;
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|err| {
                tracing::error!(error = %err, "migration failed");
                ApiError::internal()
            })?;
        Ok(Self { pool })
    }

    pub async fn count_operators(&self) -> Result<i64, ApiError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM operators")
            .fetch_one(&self.pool)
            .await?;
        Ok(count)
    }

    pub async fn insert_operator(
        &self,
        id: &str,
        username: &str,
        display_name: &str,
        now: i64,
    ) -> Result<(), ApiError> {
        sqlx::query(
            "INSERT INTO operators (id, username, display_name, created_at, disabled) VALUES (?, ?, ?, ?, 0)",
        )
        .bind(id)
        .bind(username)
        .bind(display_name)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_role(&self, operator_id: &str, role: &str) -> Result<(), ApiError> {
        sqlx::query(
            "INSERT INTO operator_roles (operator_id, role) VALUES (?, ?) ON CONFLICT DO NOTHING",
        )
        .bind(operator_id)
        .bind(role)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn roles(&self, operator_id: &str) -> Result<Vec<String>, ApiError> {
        let rows =
            sqlx::query("SELECT role FROM operator_roles WHERE operator_id = ? ORDER BY role")
                .bind(operator_id)
                .fetch_all(&self.pool)
                .await?;
        Ok(rows.into_iter().map(|row| row.get("role")).collect())
    }

    pub async fn operator_by_username(
        &self,
        username: &str,
    ) -> Result<Option<OperatorRow>, ApiError> {
        let row = sqlx::query(
            "SELECT id, username, display_name, disabled FROM operators WHERE username = ?",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(operator_from))
    }

    pub async fn operator_by_id(&self, id: &str) -> Result<Option<OperatorRow>, ApiError> {
        let row =
            sqlx::query("SELECT id, username, display_name, disabled FROM operators WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(operator_from))
    }

    pub async fn insert_passkey(
        &self,
        credential_id: &str,
        operator_id: &str,
        passkey_json: &str,
        now: i64,
    ) -> Result<(), ApiError> {
        sqlx::query(
            "INSERT INTO webauthn_credentials (credential_id, operator_id, passkey_json, created_at) VALUES (?, ?, ?, ?)",
        )
        .bind(credential_id)
        .bind(operator_id)
        .bind(passkey_json)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn passkeys_for(&self, operator_id: &str) -> Result<Vec<(String, String)>, ApiError> {
        let rows = sqlx::query(
            "SELECT credential_id, passkey_json FROM webauthn_credentials WHERE operator_id = ?",
        )
        .bind(operator_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| (row.get("credential_id"), row.get("passkey_json")))
            .collect())
    }

    pub async fn create_session(
        &self,
        token_hash: &str,
        operator_id: &str,
        csrf: &str,
        now: i64,
        expires_at: i64,
    ) -> Result<(), ApiError> {
        sqlx::query(
            "INSERT INTO sessions (token_hash, operator_id, csrf_token, created_at, expires_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(token_hash)
        .bind(operator_id)
        .bind(csrf)
        .bind(now)
        .bind(expires_at)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn session(&self, token_hash: &str) -> Result<Option<SessionRow>, ApiError> {
        let row = sqlx::query(
            "SELECT operator_id, csrf_token, expires_at FROM sessions WHERE token_hash = ?",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| SessionRow {
            operator_id: row.get("operator_id"),
            csrf_token: row.get("csrf_token"),
            expires_at: row.get("expires_at"),
        }))
    }

    pub async fn delete_session(&self, token_hash: &str) -> Result<(), ApiError> {
        sqlx::query("DELETE FROM sessions WHERE token_hash = ?")
            .bind(token_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn purge_expired_sessions(&self, now: i64) -> Result<(), ApiError> {
        sqlx::query("DELETE FROM sessions WHERE expires_at < ?")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn insert_token(
        &self,
        id: &str,
        token_hash: &str,
        created_by: &str,
        now: i64,
        expires_at: i64,
        fingerprint: &str,
        note: &str,
    ) -> Result<(), ApiError> {
        sqlx::query(
            "INSERT INTO enrollment_tokens (id, token_hash, created_by, created_at, expires_at, ca_fingerprint, note) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(token_hash)
        .bind(created_by)
        .bind(now)
        .bind(expires_at)
        .bind(fingerprint)
        .bind(note)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_tokens(&self) -> Result<Vec<Value>, ApiError> {
        let rows = sqlx::query(
            "SELECT id, created_by, created_at, expires_at, used_at, used_by_device, note FROM enrollment_tokens ORDER BY created_at DESC LIMIT 100",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                json!({
                    "id": row.get::<String, _>("id"),
                    "created_by": row.get::<String, _>("created_by"),
                    "created_at": row.get::<i64, _>("created_at"),
                    "expires_at": row.get::<i64, _>("expires_at"),
                    "used_at": row.get::<Option<i64>, _>("used_at"),
                    "used_by_device": row.get::<Option<String>, _>("used_by_device"),
                    "note": row.get::<String, _>("note"),
                })
            })
            .collect())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn enroll(
        &self,
        token_hash: &str,
        now: i64,
        fingerprint: &str,
        device_id: &str,
        hostname: &str,
        public_key_hex: &str,
        platform_json: &str,
        cert_pem: &str,
        cert_sha256: &str,
        simulated: bool,
        policy_json: &str,
    ) -> Result<String, ApiError> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            "SELECT id, created_by, expires_at, used_at, ca_fingerprint FROM enrollment_tokens WHERE token_hash = ?",
        )
        .bind(token_hash)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            return Err(ApiError::invalid("enrollment token is not valid"));
        };
        if row.get::<Option<i64>, _>("used_at").is_some() {
            return Err(ApiError::conflict(
                "enrollment_used",
                "enrollment token was already used",
            ));
        }
        if row.get::<i64, _>("expires_at") < now {
            return Err(ApiError::conflict(
                "enrollment_expired",
                "enrollment token has expired",
            ));
        }
        if row.get::<String, _>("ca_fingerprint") != fingerprint {
            return Err(ApiError::invalid(
                "enrollment token is not bound to this server CA",
            ));
        }
        let owner_id: String = row.get("created_by");
        let token_id: String = row.get("id");
        let updated = sqlx::query(
            "UPDATE enrollment_tokens SET used_at = ?, used_by_device = ? WHERE id = ? AND used_at IS NULL",
        )
        .bind(now)
        .bind(device_id)
        .bind(&token_id)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(ApiError::conflict(
                "enrollment_used",
                "enrollment token was already used",
            ));
        }
        sqlx::query(
            "INSERT INTO devices (id, hostname, owner_id, public_key_hex, platform_json, status, created_at, cert_pem, cert_sha256, last_sequence_issued, simulated) VALUES (?, ?, ?, ?, ?, 'enrolled', ?, ?, ?, 0, ?)",
        )
        .bind(device_id)
        .bind(hostname)
        .bind(&owner_id)
        .bind(public_key_hex)
        .bind(platform_json)
        .bind(now)
        .bind(cert_pem)
        .bind(cert_sha256)
        .bind(i64::from(simulated))
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO device_certs (cert_sha256, device_id, public_key_hex, cert_pem, created_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(cert_sha256)
        .bind(device_id)
        .bind(public_key_hex)
        .bind(cert_pem)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO boot_policies (device_id, policy_json, updated_at) VALUES (?, ?, ?)",
        )
        .bind(device_id)
        .bind(policy_json)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        audit_tx(
            &mut tx,
            now,
            "device",
            device_id,
            "device.enroll",
            Some(device_id),
            &json!({ "owner_id": owner_id, "hostname": hostname, "simulated": simulated }),
        )
        .await?;
        tx.commit().await?;
        Ok(owner_id)
    }

    pub async fn device(&self, id: &str) -> Result<Option<DeviceRow>, ApiError> {
        let row = sqlx::query(
            "SELECT id, hostname, owner_id, public_key_hex, platform_json, status, created_at, cert_pem, cert_sha256, last_seen_at, simulated FROM devices WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(device_from))
    }

    pub async fn device_by_cert(
        &self,
        cert_sha256: &str,
    ) -> Result<Option<(DeviceRow, bool)>, ApiError> {
        let row = sqlx::query(
            "SELECT d.id, d.hostname, d.owner_id, d.public_key_hex, d.platform_json, d.status, d.created_at, d.cert_pem, d.cert_sha256, d.last_seen_at, d.simulated, c.revoked_at AS cert_revoked FROM device_certs c JOIN devices d ON d.id = c.device_id WHERE c.cert_sha256 = ?",
        )
        .bind(cert_sha256)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| {
            let revoked = row.get::<Option<i64>, _>("cert_revoked").is_some();
            (device_from(row), revoked)
        }))
    }

    pub async fn touch_device(&self, id: &str, now: i64) -> Result<(), ApiError> {
        sqlx::query("UPDATE devices SET last_seen_at = ? WHERE id = ?")
            .bind(now)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_devices(
        &self,
        operator_id: &str,
        admin: bool,
    ) -> Result<Vec<DeviceListItem>, ApiError> {
        let rows = sqlx::query(
            "SELECT d.id, d.hostname, d.status, d.simulated, d.created_at, d.owner_id, d.public_key_hex, d.cert_sha256, s.last_heartbeat_at, s.mode, s.component, s.software_version FROM devices d LEFT JOIN device_status s ON s.device_id = d.id WHERE (? = 1) OR d.owner_id = ? OR EXISTS (SELECT 1 FROM device_grants g WHERE g.device_id = d.id AND g.operator_id = ?) ORDER BY d.created_at DESC",
        )
        .bind(i64::from(admin))
        .bind(operator_id)
        .bind(operator_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(list_from).collect())
    }

    pub async fn grants(
        &self,
        device_id: &str,
        operator_id: &str,
    ) -> Result<Vec<String>, ApiError> {
        let rows =
            sqlx::query("SELECT role FROM device_grants WHERE device_id = ? AND operator_id = ?")
                .bind(device_id)
                .bind(operator_id)
                .fetch_all(&self.pool)
                .await?;
        Ok(rows.into_iter().map(|row| row.get("role")).collect())
    }

    pub async fn add_grant(
        &self,
        device_id: &str,
        operator_id: &str,
        role: &str,
    ) -> Result<(), ApiError> {
        sqlx::query(
            "INSERT INTO device_grants (device_id, operator_id, role) VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
        )
        .bind(device_id)
        .bind(operator_id)
        .bind(role)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn replace_targets(
        &self,
        device_id: &str,
        targets: &[(String, String)],
        now: i64,
    ) -> Result<(), ApiError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM boot_targets WHERE device_id = ?")
            .bind(device_id)
            .execute(&mut *tx)
            .await?;
        for (id, payload) in targets {
            sqlx::query(
                "INSERT INTO boot_targets (device_id, target_id, payload_json, reported_at) VALUES (?, ?, ?, ?)",
            )
            .bind(device_id)
            .bind(id)
            .bind(payload)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn targets(&self, device_id: &str) -> Result<Vec<Value>, ApiError> {
        let rows = sqlx::query(
            "SELECT payload_json FROM boot_targets WHERE device_id = ? ORDER BY target_id",
        )
        .bind(device_id)
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::new();
        for row in rows {
            let text: String = row.get("payload_json");
            if let Ok(value) = serde_json::from_str(&text) {
                out.push(value);
            }
        }
        Ok(out)
    }

    pub async fn policy(&self, device_id: &str) -> Result<Option<String>, ApiError> {
        let row = sqlx::query("SELECT policy_json FROM boot_policies WHERE device_id = ?")
            .bind(device_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|row| row.get("policy_json")))
    }

    pub async fn save_policy(
        &self,
        device_id: &str,
        policy_json: &str,
        now: i64,
    ) -> Result<(), ApiError> {
        sqlx::query("UPDATE boot_policies SET policy_json = ?, updated_at = ? WHERE device_id = ?")
            .bind(policy_json)
            .bind(now)
            .bind(device_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn upsert_status(
        &self,
        device_id: &str,
        component: &str,
        version: &str,
        mode: &str,
        detail: &str,
        now: i64,
    ) -> Result<(), ApiError> {
        sqlx::query(
            "INSERT INTO device_status (device_id, component, software_version, mode, last_heartbeat_at, detail_json) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(device_id) DO UPDATE SET component = excluded.component, software_version = excluded.software_version, mode = excluded.mode, last_heartbeat_at = excluded.last_heartbeat_at, detail_json = excluded.detail_json",
        )
        .bind(device_id)
        .bind(component)
        .bind(version)
        .bind(mode)
        .bind(now)
        .bind(detail)
        .execute(&self.pool)
        .await?;
        self.touch_device(device_id, now).await
    }

    pub async fn upsert_inventory(
        &self,
        device_id: &str,
        inventory: &str,
        now: i64,
    ) -> Result<(), ApiError> {
        sqlx::query(
            "INSERT INTO hardware_inventory (device_id, inventory_json, reported_at) VALUES (?, ?, ?) ON CONFLICT(device_id) DO UPDATE SET inventory_json = excluded.inventory_json, reported_at = excluded.reported_at",
        )
        .bind(device_id)
        .bind(inventory)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn inventory(&self, device_id: &str) -> Result<Option<Value>, ApiError> {
        let row = sqlx::query("SELECT inventory_json FROM hardware_inventory WHERE device_id = ?")
            .bind(device_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.and_then(|row| {
            let text: String = row.get("inventory_json");
            serde_json::from_str(&text).ok()
        }))
    }

    pub async fn reserve_sequence(&self, device_id: &str) -> Result<u64, ApiError> {
        for _ in 0..8 {
            let mut tx = self.pool.begin().await?;
            let current: Option<i64> = sqlx::query_scalar(
                "SELECT last_sequence_issued FROM devices WHERE id = ? AND status = 'enrolled'",
            )
            .bind(device_id)
            .fetch_optional(&mut *tx)
            .await?;
            let Some(current) = current else {
                return Err(ApiError::conflict("conflict", "device is not enrolled"));
            };
            let next = current.saturating_add(1);
            let updated = sqlx::query(
                "UPDATE devices SET last_sequence_issued = ? WHERE id = ? AND last_sequence_issued = ?",
            )
            .bind(next)
            .bind(device_id)
            .bind(current)
            .execute(&mut *tx)
            .await?;
            if updated.rows_affected() == 1 {
                tx.commit().await?;
                return Ok(u64::try_from(next).unwrap_or(u64::MAX));
            }
        }
        Err(ApiError::conflict(
            "conflict",
            "could not allocate a command sequence",
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn insert_command(
        &self,
        command_id: &str,
        device_id: &str,
        sequence: u64,
        scope: &str,
        payload_json: &str,
        envelope_json: &str,
        requested_by: Option<&str>,
        issued_at: i64,
        expires_at: i64,
    ) -> Result<(), ApiError> {
        sqlx::query(
            "INSERT INTO commands (command_id, device_id, sequence, state, required_scope, payload_json, envelope_json, requested_by, issued_at, expires_at) VALUES (?, ?, ?, 'requested', ?, ?, ?, ?, ?, ?)",
        )
        .bind(command_id)
        .bind(device_id)
        .bind(i64::try_from(sequence).unwrap_or(i64::MAX))
        .bind(scope)
        .bind(payload_json)
        .bind(envelope_json)
        .bind(requested_by)
        .bind(issued_at)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn commands(&self, device_id: &str) -> Result<Vec<CommandRow>, ApiError> {
        let rows = sqlx::query(
            "SELECT command_id, device_id, sequence, state, required_scope, payload_json, envelope_json, issued_at, expires_at, delivered_at, accepted_at, finished_at, result_code, result_message FROM commands WHERE device_id = ? ORDER BY sequence DESC LIMIT 100",
        )
        .bind(device_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(command_from).collect())
    }

    pub async fn command(&self, command_id: &str) -> Result<Option<CommandRow>, ApiError> {
        let row = sqlx::query(
            "SELECT command_id, device_id, sequence, state, required_scope, payload_json, envelope_json, issued_at, expires_at, delivered_at, accepted_at, finished_at, result_code, result_message FROM commands WHERE command_id = ?",
        )
        .bind(command_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(command_from))
    }

    pub async fn expire_commands(&self, device_id: &str, now: i64) -> Result<(), ApiError> {
        sqlx::query(
            "UPDATE commands SET state = 'expired', finished_at = ?, result_code = 'command_expired', result_message = 'expired before the device executed it' WHERE device_id = ? AND state IN ('requested', 'delivered') AND expires_at < ?",
        )
        .bind(now)
        .bind(device_id)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn pending(&self, device_id: &str, now: i64) -> Result<Vec<CommandRow>, ApiError> {
        self.expire_commands(device_id, now).await?;
        let rows = sqlx::query(
            "SELECT command_id, device_id, sequence, state, required_scope, payload_json, envelope_json, issued_at, expires_at, delivered_at, accepted_at, finished_at, result_code, result_message FROM commands WHERE device_id = ? AND state IN ('requested', 'delivered') ORDER BY sequence ASC",
        )
        .bind(device_id)
        .fetch_all(&self.pool)
        .await?;
        let commands: Vec<_> = rows.into_iter().map(command_from).collect();
        for command in &commands {
            if command.state == "requested" {
                sqlx::query(
                    "UPDATE commands SET state = 'delivered', delivered_at = ? WHERE command_id = ? AND state = 'requested'",
                )
                .bind(now)
                .bind(&command.command_id)
                .execute(&self.pool)
                .await?;
            }
        }
        Ok(commands)
    }

    pub async fn apply_ack(
        &self,
        device_id: &str,
        command_id: &str,
        new_state: &str,
        code: Option<&str>,
        message: Option<&str>,
        now: i64,
    ) -> Result<String, ApiError> {
        let Some(current) = self.command(command_id).await? else {
            return Err(ApiError::not_found());
        };
        if current.device_id != device_id {
            return Err(ApiError::not_found());
        }
        if current.state == new_state
            && matches!(new_state, "accepted" | "executed" | "failed" | "rejected")
        {
            return Ok(current.state);
        }
        let allowed = matches!(
            (current.state.as_str(), new_state),
            (
                "requested" | "delivered",
                "accepted" | "rejected" | "failed"
            ) | ("accepted", "executed" | "failed")
        );
        if !allowed {
            return Err(ApiError::conflict(
                "conflict",
                format!("cannot move {} to {new_state}", current.state),
            ));
        }
        let finished = matches!(new_state, "executed" | "failed" | "rejected");
        sqlx::query(
            "UPDATE commands SET state = ?, result_code = ?, result_message = ?, accepted_at = CASE WHEN ? = 'accepted' THEN ? ELSE accepted_at END, finished_at = CASE WHEN ? = 1 THEN ? ELSE finished_at END, delivered_at = COALESCE(delivered_at, ?) WHERE command_id = ?",
        )
        .bind(new_state)
        .bind(code)
        .bind(message)
        .bind(new_state)
        .bind(now)
        .bind(i64::from(finished))
        .bind(now)
        .bind(now)
        .bind(command_id)
        .execute(&self.pool)
        .await?;
        Ok(new_state.to_string())
    }

    pub async fn revoke_device(
        &self,
        device_id: &str,
        reason: &str,
        now: i64,
    ) -> Result<(), ApiError> {
        sqlx::query(
            "UPDATE devices SET status = 'revoked', revoked_at = ?, revoke_reason = ? WHERE id = ? AND status = 'enrolled'",
        )
        .bind(now)
        .bind(reason)
        .bind(device_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn rotate_cert(
        &self,
        device_id: &str,
        old_sha: &str,
        new_sha: &str,
        new_pem: &str,
        new_public: &str,
        now: i64,
    ) -> Result<(), ApiError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE device_certs SET revoked_at = ? WHERE cert_sha256 = ?")
            .bind(now)
            .bind(old_sha)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO device_certs (cert_sha256, device_id, public_key_hex, cert_pem, created_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(new_sha)
        .bind(device_id)
        .bind(new_public)
        .bind(new_pem)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE devices SET public_key_hex = ?, cert_pem = ?, cert_sha256 = ? WHERE id = ?",
        )
        .bind(new_public)
        .bind(new_pem)
        .bind(new_sha)
        .bind(device_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn create_recovery(
        &self,
        id: &str,
        device_id: &str,
        operator_id: &str,
        kind: &str,
        now: i64,
        expires_at: i64,
    ) -> Result<(), ApiError> {
        sqlx::query(
            "INSERT INTO recovery_sessions (id, device_id, operator_id, kind, state, created_at, expires_at) VALUES (?, ?, ?, ?, 'authorized', ?, ?)",
        )
        .bind(id)
        .bind(device_id)
        .bind(operator_id)
        .bind(kind)
        .bind(now)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn recovery(&self, id: &str) -> Result<Option<Value>, ApiError> {
        let row = sqlx::query(
            "SELECT id, device_id, operator_id, kind, state, created_at, expires_at, closed_at FROM recovery_sessions WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(recovery_json))
    }

    pub async fn recovery_for_device(&self, device_id: &str) -> Result<Vec<Value>, ApiError> {
        let rows = sqlx::query(
            "SELECT id, device_id, operator_id, kind, state, created_at, expires_at, closed_at FROM recovery_sessions WHERE device_id = ? ORDER BY created_at DESC LIMIT 20",
        )
        .bind(device_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(recovery_json).collect())
    }

    pub async fn set_recovery_state(
        &self,
        id: &str,
        state: &str,
        now: i64,
        close: bool,
    ) -> Result<(), ApiError> {
        if close {
            sqlx::query("UPDATE recovery_sessions SET state = ?, closed_at = ? WHERE id = ?")
                .bind(state)
                .bind(now)
                .bind(id)
                .execute(&self.pool)
                .await?;
        } else {
            sqlx::query("UPDATE recovery_sessions SET state = ? WHERE id = ?")
                .bind(state)
                .bind(id)
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }

    pub async fn audit(
        &self,
        now: i64,
        actor_type: &str,
        actor_id: &str,
        action: &str,
        device_id: Option<&str>,
        detail: &Value,
    ) -> Result<(), ApiError> {
        sqlx::query(
            "INSERT INTO audit_log (at_unix, actor_type, actor_id, action, device_id, detail_json) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(now)
        .bind(actor_type)
        .bind(actor_id)
        .bind(action)
        .bind(device_id)
        .bind(detail.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_audit(
        &self,
        before: Option<i64>,
        limit: i64,
    ) -> Result<Vec<Value>, ApiError> {
        let rows = if let Some(before) = before {
            sqlx::query(
                "SELECT id, at_unix, actor_type, actor_id, action, device_id, detail_json FROM audit_log WHERE id < ? ORDER BY id DESC LIMIT ?",
            )
            .bind(before)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                "SELECT id, at_unix, actor_type, actor_id, action, device_id, detail_json FROM audit_log ORDER BY id DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        };
        Ok(rows
            .into_iter()
            .map(|row| {
                let detail: String = row.get("detail_json");
                json!({
                    "id": row.get::<i64, _>("id"),
                    "at_unix": row.get::<i64, _>("at_unix"),
                    "actor_type": row.get::<String, _>("actor_type"),
                    "actor_id": row.get::<String, _>("actor_id"),
                    "action": row.get::<String, _>("action"),
                    "device_id": row.get::<Option<String>, _>("device_id"),
                    "detail": serde_json::from_str::<Value>(&detail).unwrap_or(Value::Null),
                })
            })
            .collect())
    }
}

async fn audit_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    now: i64,
    actor_type: &str,
    actor_id: &str,
    action: &str,
    device_id: Option<&str>,
    detail: &Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_log (at_unix, actor_type, actor_id, action, device_id, detail_json) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(now)
    .bind(actor_type)
    .bind(actor_id)
    .bind(action)
    .bind(device_id)
    .bind(detail.to_string())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn operator_from(row: sqlx::sqlite::SqliteRow) -> OperatorRow {
    OperatorRow {
        id: row.get("id"),
        username: row.get("username"),
        display_name: row.get("display_name"),
        disabled: row.get::<i64, _>("disabled") != 0,
    }
}

fn device_from(row: sqlx::sqlite::SqliteRow) -> DeviceRow {
    DeviceRow {
        id: row.get("id"),
        hostname: row.get("hostname"),
        owner_id: row.get("owner_id"),
        public_key_hex: row.get("public_key_hex"),
        platform_json: row.get("platform_json"),
        status: row.get("status"),
        created_at: row.get("created_at"),
        cert_pem: row.get("cert_pem"),
        cert_sha256: row.get("cert_sha256"),
        last_seen_at: row.get("last_seen_at"),
        simulated: row.get::<i64, _>("simulated") != 0,
    }
}

fn list_from(row: sqlx::sqlite::SqliteRow) -> DeviceListItem {
    DeviceListItem {
        id: row.get("id"),
        hostname: row.get("hostname"),
        status: row.get("status"),
        simulated: row.get::<i64, _>("simulated") != 0,
        created_at: row.get("created_at"),
        owner_id: row.get("owner_id"),
        public_key_hex: row.get("public_key_hex"),
        cert_sha256: row.get("cert_sha256"),
        last_heartbeat_at: row.get("last_heartbeat_at"),
        mode: row.get("mode"),
        component: row.get("component"),
        software_version: row.get("software_version"),
    }
}

fn command_from(row: sqlx::sqlite::SqliteRow) -> CommandRow {
    CommandRow {
        command_id: row.get("command_id"),
        device_id: row.get("device_id"),
        sequence: row.get("sequence"),
        state: row.get("state"),
        required_scope: row.get("required_scope"),
        payload_json: row.get("payload_json"),
        envelope_json: row.get("envelope_json"),
        issued_at: row.get("issued_at"),
        expires_at: row.get("expires_at"),
        delivered_at: row.get("delivered_at"),
        accepted_at: row.get("accepted_at"),
        finished_at: row.get("finished_at"),
        result_code: row.get("result_code"),
        result_message: row.get("result_message"),
    }
}

fn recovery_json(row: sqlx::sqlite::SqliteRow) -> Value {
    json!({
        "id": row.get::<String, _>("id"),
        "device_id": row.get::<String, _>("device_id"),
        "operator_id": row.get::<String, _>("operator_id"),
        "kind": row.get::<String, _>("kind"),
        "state": row.get::<String, _>("state"),
        "created_at": row.get::<i64, _>("created_at"),
        "expires_at": row.get::<i64, _>("expires_at"),
        "closed_at": row.get::<Option<i64>, _>("closed_at"),
    })
}
