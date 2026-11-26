use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sbm_protocol::CommandEnvelope;
use sbm_server::{Clock, Config, ServerHandle};
use sbm_sim::{Device, Mode, http_client, read_binary_frame, sample_platform};
use sbm_types::SbmErrorCode;
use serde_json::{Value, json};

const SECRET: &str = "lab-bootstrap-secret";

struct Lab {
    server: ServerHandle,
    http: reqwest::Client,
    token: String,
    _dir: tempfile::TempDir,
}

impl Lab {
    async fn start() -> Self {
        Self::open(Clock::system()).await
    }

    async fn open(clock: Clock) -> Self {
        Self::open_with(clock, |_| {}).await
    }

    async fn open_with(clock: Clock, tune: impl FnOnce(&mut Config)) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = Config::for_test(dir.path(), "127.0.0.1:0".parse().unwrap(), SECRET);
        tune(&mut config);
        let server = sbm_server::serve_with(config, clock).await.expect("server");
        let http = http_client(&server.ca_pem, None).expect("client");
        let login = http
            .post(format!("{}/v1/auth/dev-login", server.base_url))
            .json(&json!({ "secret": SECRET }))
            .send()
            .await
            .expect("login send");
        let body = json_ok(login).await;
        let token = body["token"].as_str().unwrap().to_string();
        Self {
            server,
            http,
            token,
            _dir: dir,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.server.base_url)
    }

    async fn post(&self, path: &str, token: &str, body: Value) -> Value {
        let response = self
            .http
            .post(self.url(path))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .expect("post");
        json_ok(response).await
    }

    async fn get(&self, path: &str, token: &str) -> Value {
        let response = self
            .http
            .get(self.url(path))
            .bearer_auth(token)
            .send()
            .await
            .expect("get");
        json_ok(response).await
    }

    async fn status(
        &self,
        method: &str,
        path: &str,
        token: &str,
        body: Option<Value>,
    ) -> (u16, Value) {
        let request = match method {
            "POST" => self.http.post(self.url(path)),
            "PUT" => self.http.put(self.url(path)),
            _ => self.http.get(self.url(path)),
        };
        let request = request.bearer_auth(token);
        let request = if let Some(body) = body {
            request.json(&body)
        } else {
            request
        };
        let response = request.send().await.expect("request");
        let status = response.status().as_u16();
        let text = response.text().await.unwrap_or_default();
        let value = serde_json::from_str(&text).unwrap_or(Value::Null);
        (status, value)
    }

    async fn enroll(&self, hostname: &str) -> Device {
        let bundle = self
            .post("/v1/enrollment-tokens", &self.token, json!({}))
            .await;
        let mut device = Device::fresh(hostname);
        device
            .enroll(
                &self.server.base_url,
                bundle["token"].as_str().unwrap(),
                bundle["ca_pem"].as_str().unwrap(),
                bundle["ca_fingerprint_sha256"].as_str().unwrap(),
            )
            .await
            .expect("enroll");
        device
    }
}

async fn json_ok(response: reqwest::Response) -> Value {
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    assert!(status.is_success(), "{status}: {text}");
    if text.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text).unwrap_or_else(|err| panic!("{err}: {text}"))
    }
}

fn command_state(detail: &Value, command_id: &str) -> String {
    detail["commands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["command_id"] == command_id)
        .unwrap()["state"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn simulated_next_boot_stays_queued_until_the_device_reports_it() {
    let lab = Lab::start().await;
    let mut device = lab.enroll("lab-vm").await;
    device.sync_once(Mode::Uefi).await.expect("publish targets");

    let issued = lab
        .post(
            &format!("/v1/devices/{}/commands", device.device_id),
            &lab.token,
            json!({
                "command": { "action": "boot_target", "target_id": "linux:fedora", "one_shot": true }
            }),
        )
        .await;
    assert_eq!(issued["state"], "requested");
    assert!(
        issued["note"].as_str().unwrap().contains("no reboot"),
        "{}",
        issued["note"]
    );
    let command_id = issued["command"]["command_id"]
        .as_str()
        .unwrap()
        .to_string();
    let before = lab
        .get(&format!("/v1/devices/{}", device.device_id), &lab.token)
        .await;
    assert_eq!(command_state(&before, &command_id), "requested");
    assert!(before["policy"]["one_shot"].is_null());

    let report = device.sync_once(Mode::Uefi).await.expect("apply");
    assert_eq!(report.executed, vec![command_id.clone()]);
    let after = lab
        .get(&format!("/v1/devices/{}", device.device_id), &lab.token)
        .await;
    assert_eq!(command_state(&after, &command_id), "executed");
    let row = after["commands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["command_id"] == command_id)
        .unwrap();
    assert!(
        row["result_message"]
            .as_str()
            .unwrap()
            .contains("No machine rebooted"),
        "{}",
        row["result_message"]
    );
    assert_eq!(after["policy"]["one_shot"]["consumed"], true);
    assert_eq!(after["policy"]["one_shot"]["target_id"], "linux:fedora");
    assert_eq!(after["device"]["simulated"], true);

    let envelope: CommandEnvelope = serde_json::from_value(issued["command"].clone()).unwrap();
    let replay = device.evaluate(&envelope, Mode::Uefi).unwrap();
    assert_eq!(replay.code, Some(SbmErrorCode::ReplayDetected));
    assert_eq!(replay.advance_to, None);
    let mut tampered = envelope.clone();
    tampered.signature_ed25519_hex.replace_range(0..2, "ff");
    let bad = device.evaluate(&tampered, Mode::Uefi).unwrap();
    assert_eq!(bad.code, Some(SbmErrorCode::SignatureInvalid));
    assert_eq!(bad.advance_to, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn uefi_rejects_recovery_scope_without_blocking_a_later_boot() {
    let lab = Lab::start().await;
    let mut device = lab.enroll("lab-vm").await;
    device.sync_once(Mode::Uefi).await.unwrap();
    let issued = lab
        .post(
            &format!("/v1/devices/{}/commands", device.device_id),
            &lab.token,
            json!({
                "command": {
                    "action": "boot_recovery",
                    "slot": "auto",
                    "launch_mode": { "mode": "remote_assist" }
                }
            }),
        )
        .await;
    let report = device.sync_once(Mode::Uefi).await.unwrap();
    assert_eq!(report.rejected.len(), 1);
    assert_eq!(report.rejected[0].1, "unauthorized_scope");
    assert_eq!(device.last_sequence, 1);
    let boot = lab
        .post(
            &format!("/v1/devices/{}/commands", device.device_id),
            &lab.token,
            json!({
                "command": { "action": "boot_target", "target_id": "sbm-core:slot-a", "one_shot": true }
            }),
        )
        .await;
    let applied = device.sync_once(Mode::Uefi).await.unwrap();
    assert_eq!(
        applied.executed,
        vec![boot["command"]["command_id"].as_str().unwrap().to_string()]
    );
    assert_eq!(device.last_sequence, 2);
    let _ = issued;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bad_verify_key_does_not_advance_and_expiry_is_rejected() {
    let tick = Arc::new(AtomicI64::new(unix_now()));
    let lab = Lab::open_with(Clock::manual(tick.clone()), |config| {
        config.session_ttl = Duration::from_secs(86_400);
    })
    .await;
    let mut device = lab.enroll("lab-vm").await;
    device.set_clock(tick.clone());
    device.sync_once(Mode::Uefi).await.unwrap();
    let good_key = device.verify_key_hex.clone();

    let issued = lab
        .post(
            &format!("/v1/devices/{}/commands", device.device_id),
            &lab.token,
            json!({
                "command": { "action": "boot_target", "target_id": "windows:11", "one_shot": true }
            }),
        )
        .await;
    device.verify_key_hex = Device::fresh("wrong-key").public_hex().unwrap();
    let report = device.sync_once(Mode::Uefi).await.unwrap();
    assert_eq!(report.rejected[0].1, "signature_invalid");
    assert_eq!(device.last_sequence, 0);
    let command_id = issued["command"]["command_id"].as_str().unwrap();
    let detail = lab
        .get(&format!("/v1/devices/{}", device.device_id), &lab.token)
        .await;
    assert_eq!(command_state(&detail, command_id), "rejected");

    device.verify_key_hex = good_key;
    let second = lab
        .post(
            &format!("/v1/devices/{}/commands", device.device_id),
            &lab.token,
            json!({
                "command": { "action": "boot_target", "target_id": "linux:fedora", "one_shot": false }
            }),
        )
        .await;
    tick.store(unix_now() + 10_000, Ordering::SeqCst);
    let envelope: CommandEnvelope = serde_json::from_value(second["command"].clone()).unwrap();
    let expired = device.evaluate(&envelope, Mode::Uefi).unwrap();
    assert_eq!(expired.code, Some(SbmErrorCode::CommandExpired));
    assert_eq!(expired.advance_to, None);
    device.sync_once(Mode::Uefi).await.unwrap();
    assert_eq!(device.last_sequence, 0);
    let after = lab
        .get(&format!("/v1/devices/{}", device.device_id), &lab.token)
        .await;
    assert_eq!(
        command_state(&after, second["command"]["command_id"].as_str().unwrap()),
        "expired"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_cannot_ack_another_device_and_roles_are_scoped() {
    let lab = Lab::start().await;
    let device_a = lab.enroll("lab-a").await;
    let mut device_b = lab.enroll("lab-b").await;
    device_a_sync(&mut device_b).await;
    let mut owner = device_a;
    owner.sync_once(Mode::Uefi).await.unwrap();
    let issued = lab
        .post(
            &format!("/v1/devices/{}/commands", owner.device_id),
            &lab.token,
            json!({
                "command": { "action": "boot_target", "target_id": "linux:fedora", "one_shot": true }
            }),
        )
        .await;
    let command_id = issued["command"]["command_id"].as_str().unwrap();
    let http_b = sbm_sim::http_client(&device_b.ca_pem, Some(&device_b.identity_pem())).unwrap();
    let crossed = http_b
        .post(format!(
            "{}/v1/devices/{}/commands/{command_id}/ack",
            lab.server.base_url, owner.device_id
        ))
        .json(&json!({ "state": "accepted" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        crossed.status(),
        404,
        "{}",
        crossed.text().await.unwrap_or_default()
    );

    let reader = lab
        .post(
            "/v1/auth/dev-operators",
            &lab.token,
            json!({ "username": "reader", "display_name": "Reader", "roles": ["read_only"] }),
        )
        .await;
    let (status, body) = lab
        .status(
            "POST",
            &format!("/v1/devices/{}/commands", owner.device_id),
            reader["token"].as_str().unwrap(),
            Some(json!({
                "command": { "action": "boot_target", "target_id": "linux:fedora", "one_shot": true }
            })),
        )
        .await;
    assert_eq!(status, 403, "{body}");

    let outsider = lab
        .post(
            "/v1/auth/dev-operators",
            &lab.token,
            json!({ "username": "outsider", "display_name": "Outsider", "roles": ["boot_select"] }),
        )
        .await;
    let (status, body) = lab
        .status(
            "POST",
            &format!("/v1/devices/{}/commands", owner.device_id),
            outsider["token"].as_str().unwrap(),
            Some(json!({
                "command": { "action": "boot_target", "target_id": "linux:fedora", "one_shot": true }
            })),
        )
        .await;
    assert_eq!(status, 404, "{body}");

    let (status, body) = lab
        .status(
            "POST",
            &format!("/v1/devices/{}/storage-plans", owner.device_id),
            &lab.token,
            Some(json!({})),
        )
        .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error"]["code"], "destructive_disabled");
    let (status, body) = lab
        .status(
            "POST",
            &format!("/v1/devices/{}/os-install-plans", owner.device_id),
            &lab.token,
            Some(json!({})),
        )
        .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error"]["code"], "os_install_disabled");
}

async fn device_a_sync(device: &mut Device) {
    device.sync_once(Mode::Uefi).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cookie_post_without_csrf_is_rejected_and_bootstrap_can_be_off() {
    let dir = tempfile::tempdir().unwrap();
    let config = Config::for_test(dir.path(), "127.0.0.1:0".parse().unwrap(), SECRET);
    let server = sbm_server::serve_with(config, Clock::system())
        .await
        .unwrap();
    let http = http_client(&server.ca_pem, None).unwrap();
    let login = http
        .post(format!("{}/v1/auth/dev-login", server.base_url))
        .json(&json!({ "secret": SECRET }))
        .send()
        .await
        .unwrap();
    let cookie = login
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("sbm_session="))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    assert!(login.status().is_success());
    let denied = http
        .post(format!("{}/v1/enrollment-tokens", server.base_url))
        .header("cookie", cookie)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    let status = denied.status();
    let text = denied.text().await.unwrap_or_default();
    assert_eq!(status, 403, "{text}");
    assert!(text.contains("csrf"), "{text}");
    drop(server);

    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::for_test(dir.path(), "127.0.0.1:0".parse().unwrap(), SECRET);
    config.dev_bootstrap = false;
    let server = sbm_server::serve_with(config, Clock::system())
        .await
        .unwrap();
    let http = http_client(&server.ca_pem, None).unwrap();
    let missing = http
        .post(format!("{}/v1/auth/dev-login", server.base_url))
        .json(&json!({ "secret": SECRET }))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_log_rejects_mutation_and_mac_is_not_identity() {
    let lab = Lab::start().await;
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect_with(
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename(lab.server.data_dir.join("sbm.db"))
                .busy_timeout(Duration::from_secs(5)),
        )
        .await
        .unwrap();
    let update = sqlx::query("UPDATE audit_log SET action = 'tampered'")
        .execute(&pool)
        .await
        .expect_err("update must abort");
    assert!(update.to_string().contains("immutable"), "{update}");
    let delete = sqlx::query("DELETE FROM audit_log")
        .execute(&pool)
        .await
        .expect_err("delete");
    assert!(delete.to_string().contains("immutable"), "{delete}");

    let bundle = lab
        .post("/v1/enrollment-tokens", &lab.token, json!({}))
        .await;
    let response = lab
        .http
        .post(lab.url("/v1/enroll"))
        .json(&json!({
            "schema_version": "1.0",
            "enrollment_token": bundle["token"],
            "device_public_key_ed25519_hex": "11".repeat(32),
            "hostname": "mac-host",
            "platform": sample_platform(),
            "mac": "aa:bb:cc:dd:ee:ff"
        }))
        .send()
        .await
        .unwrap();
    let body = json_ok(response).await;
    let id = body["device_id"].as_str().unwrap();
    assert_eq!(id.len(), 36);
    assert!(!id.contains("aa:bb"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_tunnel_is_authenticated_and_labeled() {
    let lab = Lab::start().await;
    let device = lab.enroll("lab-vm").await;
    let opened = lab
        .post(
            "/v1/recovery-sessions",
            &lab.token,
            json!({ "device_id": device.device_id }),
        )
        .await;
    assert_eq!(opened["state"], "authorized");
    let session = opened["id"].as_str().unwrap().to_string();
    let login = lab
        .http
        .post(lab.url("/v1/auth/dev-login"))
        .json(&json!({ "secret": SECRET }))
        .send()
        .await
        .unwrap();
    let cookie = login
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("sbm_session="))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    assert!(login.status().is_success());

    let device_task = {
        let device = device.clone();
        let session = session.clone();
        tokio::spawn(async move { device.recovery(&session, "vnc").await })
    };
    let browser_url = lab
        .url(&format!("/v1/recovery-sessions/{session}/vnc"))
        .replace("https://", "wss://");
    let bytes = tokio::time::timeout(
        Duration::from_secs(5),
        read_binary_frame(&browser_url, &lab.server.ca_pem, &cookie),
    )
    .await
    .expect("banner timed out")
    .expect("banner");
    assert!(bytes.starts_with(b"RFB 003.008\n"), "{bytes:?}");
    let _ = tokio::time::timeout(Duration::from_secs(5), device_task).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dashboard_shell_is_served_with_a_script_hash() {
    let lab = Lab::start().await;
    let response = lab.http.get(lab.url("/")).send().await.unwrap();
    let csp = response
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(response.status().is_success());
    let text = response.text().await.unwrap();
    assert!(text.contains("Smart Boot Menu"), "{text}");
    assert!(text.contains("<script>"));
    assert!(csp.contains("'sha256-"), "{csp}");
    assert!(!csp.contains("unsafe-inline"), "{csp}");
    assert!(!csp.contains("unsafe-eval"), "{csp}");
}

fn unix_now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}
