//! A labeled stand-in for `sbm-uefi` and `sbm-core`.
//!
//! It speaks the real enrollment and command APIs. Applying a boot command
//! records the selection in this process. It does not reboot a machine.

mod rfb;
mod ws;

use ed25519_dalek::SigningKey;
use sbm_protocol::{
    BootCommand, CommandEnvelope, CommandPayload, EnrollmentRequest, EnrollmentResponse,
};
use sbm_types::{
    BootTarget, BootTargetId, BootTargetKind, CpuArch, FirmwarePlatform, OsFamily,
    PlatformCapabilities, SCHEMA_VERSION_V1, SbmErrorCode, SecureBootState,
};
use sbm_wire::{
    CheckOutcome, check_envelope, decode_key_32, ed25519_pkcs8_der, fingerprint_sha256, pem_block,
    random_bytes,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub use rfb::serve_vnc;
pub use ws::{connect as connect_websocket, read_binary_frame, serve_terminal};

const EXECUTED_MESSAGE: &str = "The simulator recorded the selection. No machine rebooted.";

#[derive(Debug)]
pub struct SimError(pub String);

impl std::fmt::Display for SimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SimError {}

pub type SimResult<T> = Result<T, SimError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Uefi,
    Core,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Uefi => "uefi",
            Self::Core => "core",
        }
    }

    fn uefi(self) -> bool {
        matches!(self, Self::Uefi)
    }

    pub fn parse(value: &str) -> SimResult<Self> {
        match value {
            "uefi" => Ok(Self::Uefi),
            "core" => Ok(Self::Core),
            _ => Err(SimError("mode must be uefi or core".to_string())),
        }
    }
}

#[derive(Debug, Default)]
pub struct SyncReport {
    pub executed: Vec<String>,
    pub rejected: Vec<(String, String)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Device {
    pub base_url: String,
    pub ca_pem: String,
    pub hostname: String,
    pub device_id: String,
    pub seed_hex: String,
    pub cert_pem: String,
    pub verify_key_hex: String,
    pub last_sequence: u64,
    pub applied: Vec<String>,
    #[serde(skip)]
    clock: Option<Arc<AtomicI64>>,
}

impl Device {
    pub fn fresh(hostname: &str) -> Self {
        let seed: [u8; 32] = random_bytes();
        Self {
            base_url: String::new(),
            ca_pem: String::new(),
            hostname: hostname.to_string(),
            device_id: String::new(),
            seed_hex: hex::encode(seed),
            cert_pem: String::new(),
            verify_key_hex: String::new(),
            last_sequence: 0,
            applied: Vec::new(),
            clock: None,
        }
    }

    pub fn set_clock(&mut self, clock: Arc<AtomicI64>) {
        self.clock = Some(clock);
    }

    pub fn public_hex(&self) -> SimResult<String> {
        let key = self.signing_key()?;
        Ok(hex::encode(key.verifying_key().to_bytes()))
    }

    pub fn save(&self, path: &Path) -> SimResult<()> {
        let text = serde_json::to_string_pretty(self).map_err(|err| SimError(err.to_string()))?;
        write_private(path, text.as_bytes())
    }

    pub fn load(path: &Path) -> SimResult<Self> {
        let text = std::fs::read_to_string(path).map_err(|err| SimError(err.to_string()))?;
        serde_json::from_str(&text).map_err(|err| SimError(err.to_string()))
    }

    pub async fn enroll(
        &mut self,
        server: &str,
        token: &str,
        ca_pem: &str,
        fingerprint: &str,
    ) -> SimResult<EnrollmentResponse> {
        let der = pem_der(ca_pem)?;
        let got = fingerprint_sha256(&der);
        if got != fingerprint {
            return Err(SimError(format!(
                "CA fingerprint {got} does not match the enrollment bundle ({fingerprint})"
            )));
        }
        let request = EnrollmentRequest {
            schema_version: SCHEMA_VERSION_V1.to_string(),
            enrollment_token: token.to_string(),
            device_public_key_ed25519_hex: self.public_hex()?,
            hostname: self.hostname.clone(),
            platform: sample_platform(),
            tpm_attestation_b64: None,
        };
        let http = http_client(ca_pem, None)?;
        let url = format!("{server}/v1/enroll");
        let response = http
            .post(&url)
            .header("x-sbm-client", "sbm-sim")
            .json(&request)
            .send()
            .await
            .map_err(|err| SimError(err.to_string()))?;
        let body = read_json(&url, response).await?;
        let parsed: EnrollmentResponse =
            serde_json::from_value(body).map_err(|err| SimError(err.to_string()))?;
        self.base_url = server.trim_end_matches('/').to_string();
        self.ca_pem = ca_pem.to_string();
        self.device_id = parsed.device_id.clone();
        self.cert_pem = parsed.client_cert_pem.clone();
        self.verify_key_hex = parsed.server_command_verify_key_ed25519_hex.clone();
        Ok(parsed)
    }

    pub async fn sync_once(&mut self, mode: Mode) -> SimResult<SyncReport> {
        self.report_inventory(mode).await?;
        let http = self.client()?;
        let url = format!("{}/v1/devices/{}/pending", self.base_url, self.device_id);
        let response = http
            .get(&url)
            .send()
            .await
            .map_err(|err| SimError(err.to_string()))?;
        let body = read_json(&url, response).await?;
        let envelopes = body
            .get("commands")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut report = SyncReport::default();
        for value in envelopes {
            let envelope: CommandEnvelope =
                serde_json::from_value(value).map_err(|err| SimError(err.to_string()))?;
            self.handle_envelope(envelope, mode, &mut report).await?;
        }
        Ok(report)
    }

    pub fn evaluate(&self, envelope: &CommandEnvelope, mode: Mode) -> SimResult<CheckOutcome> {
        let bytes = decode_key_32(&self.verify_key_hex)
            .map_err(|_| SimError("stored verify key is not 32 bytes of hex".to_string()))?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
            .map_err(|_| SimError("stored verify key is not an Ed25519 key".to_string()))?;
        let targets: Vec<BootTargetId> = sample_targets()
            .into_iter()
            .map(|target| target.id)
            .collect();
        Ok(check_envelope(
            &key,
            envelope,
            &self.device_id,
            self.last_sequence,
            Some(self.now()),
            mode.uefi(),
            &targets,
        ))
    }

    pub async fn recovery(&self, session_id: &str, kind: &str) -> SimResult<()> {
        let url = format!(
            "{}/v1/devices/{}/recovery/tunnel?session={session_id}&kind={kind}",
            self.base_url
                .replace("https://", "wss://")
                .replace("http://", "ws://"),
            self.device_id
        );
        let socket = ws::connect(&url, &self.ca_pem, Some(self.identity_pem()), None).await?;
        match kind {
            "terminal" => serve_terminal(socket).await,
            _ => serve_vnc(socket).await,
        }
    }

    async fn handle_envelope(
        &mut self,
        envelope: CommandEnvelope,
        mode: Mode,
        report: &mut SyncReport,
    ) -> SimResult<()> {
        if self.applied.iter().any(|id| id == &envelope.command_id) {
            self.ack(
                &envelope.command_id,
                "executed",
                Some("simulated"),
                Some(EXECUTED_MESSAGE),
            )
            .await?;
            report.executed.push(envelope.command_id);
            return Ok(());
        }
        let outcome = self.evaluate(&envelope, mode)?;
        if let Some(code) = outcome.code {
            if let Some(sequence) = outcome.advance_to {
                self.last_sequence = sequence;
            }
            let name = error_name(code);
            self.ack(
                &envelope.command_id,
                "rejected",
                Some(&name),
                Some("the simulator rejected the command"),
            )
            .await?;
            report.rejected.push((envelope.command_id, name));
            return Ok(());
        }
        self.ack(&envelope.command_id, "accepted", None, None)
            .await?;
        let message = match &envelope.payload {
            CommandPayload::Boot(BootCommand::BootTarget { .. }) => EXECUTED_MESSAGE,
            _ => "The simulator accepted the command. No machine rebooted.",
        };
        self.ack(
            &envelope.command_id,
            "executed",
            Some("simulated"),
            Some(message),
        )
        .await?;
        if let Some(sequence) = outcome.advance_to {
            self.last_sequence = sequence;
        }
        self.applied.push(envelope.command_id.clone());
        report.executed.push(envelope.command_id);
        Ok(())
    }

    async fn report_inventory(&self, mode: Mode) -> SimResult<()> {
        let http = self.client()?;
        let base = format!("{}/v1/devices/{}", self.base_url, self.device_id);
        let targets = json!({ "targets": sample_targets() });
        let targets_url = format!("{base}/boot-targets");
        read_json(
            &targets_url,
            http.put(&targets_url)
                .json(&targets)
                .send()
                .await
                .map_err(|err| SimError(err.to_string()))?,
        )
        .await?;
        let inventory = json!({
            "inventory": {
                "simulated": true,
                "firmware": "uefi",
                "arch": "x86_64",
                "memory_mib": 8192,
                "note": "QEMU-like profile. No hardware serials."
            }
        });
        let inventory_url = format!("{base}/inventory");
        let inventory_response = http
            .put(&inventory_url)
            .json(&inventory)
            .send()
            .await
            .map_err(|err| SimError(err.to_string()))?;
        if !inventory_response.status().is_success() {
            let status = inventory_response.status();
            let text = inventory_response.text().await.unwrap_or_default();
            return Err(SimError(format!("{inventory_url} {status}: {text}")));
        }
        let heartbeat_url = format!("{base}/heartbeat");
        read_json(
            &heartbeat_url,
            http.post(&heartbeat_url)
                .json(&json!({
                    "component": "sbm-sim",
                    "software_version": env!("CARGO_PKG_VERSION"),
                    "mode": mode.as_str(),
                    "detail": {
                        "simulated": true,
                        "message": "No hardware reboot is performed."
                    }
                }))
                .send()
                .await
                .map_err(|err| SimError(err.to_string()))?,
        )
        .await?;
        Ok(())
    }

    async fn ack(
        &self,
        command_id: &str,
        state: &str,
        code: Option<&str>,
        message: Option<&str>,
    ) -> SimResult<()> {
        let http = self.client()?;
        let url = format!(
            "{}/v1/devices/{}/commands/{command_id}/ack",
            self.base_url, self.device_id
        );
        let response = http
            .post(&url)
            .json(&json!({ "state": state, "code": code, "message": message }))
            .send()
            .await
            .map_err(|err| SimError(err.to_string()))?;
        read_json(&url, response).await?;
        Ok(())
    }

    fn client(&self) -> SimResult<reqwest::Client> {
        http_client(&self.ca_pem, Some(&self.identity_pem()))
    }

    pub fn identity_pem(&self) -> String {
        let seed = decode_key_32(&self.seed_hex).expect("device seed");
        let key = pem_block("PRIVATE KEY", &ed25519_pkcs8_der(&seed));
        format!("{key}{}", self.cert_pem)
    }

    fn signing_key(&self) -> SimResult<SigningKey> {
        let seed = decode_key_32(&self.seed_hex)
            .map_err(|_| SimError("device seed is not 32 bytes of hex".to_string()))?;
        Ok(SigningKey::from_bytes(&seed))
    }

    fn now(&self) -> i64 {
        self.clock
            .as_ref()
            .map(|clock| clock.load(Ordering::SeqCst))
            .unwrap_or_else(|| {
                i64::try_from(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                )
                .unwrap_or(i64::MAX)
            })
    }
}

pub fn sample_platform() -> PlatformCapabilities {
    PlatformCapabilities {
        arch: CpuArch::X86_64,
        firmware: FirmwarePlatform::UefiNative,
        page_size_bytes: 4096,
        secure_boot_state: SecureBootState::Disabled,
        tpm_present: false,
        nvram_writable: true,
        gop_framebuffer: true,
        uefi_networking: true,
        can_chainload_efi: true,
        can_direct_chainload_macos: false,
        external_usb_boot_supported: true,
        ram_total_mib: Some(8192),
    }
}

pub fn sample_targets() -> Vec<BootTarget> {
    vec![
        target(
            "linux:fedora",
            "Fedora",
            OsFamily::Linux,
            BootTargetKind::EfiBinary,
            r"\EFI\fedora\shimx64.efi",
        ),
        target(
            "sbm-core:slot-a",
            "Smart Boot Menu recovery",
            OsFamily::Recovery,
            BootTargetKind::SbmCore,
            r"\EFI\sbm\sbm-core.efi",
        ),
        target(
            "windows:11",
            "Windows 11",
            OsFamily::Windows,
            BootTargetKind::EfiBinary,
            r"\EFI\Microsoft\Boot\bootmgfw.efi",
        ),
    ]
}

fn target(id: &str, name: &str, family: OsFamily, kind: BootTargetKind, path: &str) -> BootTarget {
    BootTarget {
        id: BootTargetId(id.to_string()),
        display_name: name.to_string(),
        os_family: family,
        kind,
        arch: CpuArch::X86_64,
        partition_guid: None,
        efi_path: Some(path.to_string()),
        kernel_cmdline: None,
        icon_hint: None,
        removable_media: false,
        hidden: false,
        verified_signature: None,
    }
}

pub fn http_client(ca_pem: &str, identity_pem: Option<&str>) -> SimResult<reqwest::Client> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let ca = reqwest::Certificate::from_pem(ca_pem.as_bytes())
        .map_err(|err| SimError(err.to_string()))?;
    let mut builder = reqwest::Client::builder()
        .http1_only()
        .tls_certs_only(std::iter::once(ca))
        .timeout(Duration::from_secs(20));
    if let Some(pem) = identity_pem {
        let identity =
            reqwest::Identity::from_pem(pem.as_bytes()).map_err(|err| SimError(err.to_string()))?;
        builder = builder.identity(identity);
    }
    builder.build().map_err(|err| SimError(err.to_string()))
}

pub fn pem_der(pem: &str) -> SimResult<Vec<u8>> {
    let mut b64 = String::new();
    let mut inside = false;
    for line in pem.lines() {
        if line.starts_with("-----BEGIN ") {
            inside = true;
            b64.clear();
            continue;
        }
        if line.starts_with("-----END ") {
            let engine = base64_decode(&b64)?;
            return Ok(engine);
        }
        if inside {
            b64.push_str(line.trim());
        }
    }
    Err(SimError("certificate PEM was empty".to_string()))
}

fn base64_decode(text: &str) -> SimResult<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|_| SimError("certificate PEM is not valid base64".to_string()))
}

async fn read_json(url: &str, response: reqwest::Response) -> SimResult<Value> {
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|err| SimError(err.to_string()))?;
    if !status.is_success() {
        return Err(SimError(format!("{url} {status}: {text}")));
    }
    if text.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(&text).map_err(|err| SimError(format!("{err}: {text}")))
}

fn error_name(code: SbmErrorCode) -> String {
    serde_json::to_value(code)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "rejected".to_string())
}

fn write_private(path: &Path, bytes: &[u8]) -> SimResult<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| SimError(err.to_string()))?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| SimError(err.to_string()))?;
    file.write_all(bytes)
        .map_err(|err| SimError(err.to_string()))?;
    Ok(())
}
