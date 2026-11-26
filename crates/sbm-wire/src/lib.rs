//! Command Signing Profile v1.
//!
//! The signature input is `b"sbm-cmd-v1\0" || canonical_json`, where `canonical_json`
//! is the compact JSON object of every [`sbm_protocol::CommandEnvelope`] field except
//! `signature_ed25519_hex`. Key order is the order in Spec 06 §16.1. Nested `payload`
//! objects use the `sbm-protocol` 0.1 serde representation.
//!
//! This crate does not define a second copy of the protocol structs.

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sbm_protocol::{AuthScope, BootCommand, CommandEnvelope, CommandPayload};
use sbm_types::{BootTargetId, SbmErrorCode};
use sha2::{Digest, Sha256};
use signature::{Signer, Verifier};

/// Preset names a remote boot command may name. Anything else, including raw
/// kernel command lines, is rejected.
pub const CMDLINE_PRESETS: &[&str] = &["quiet", "verbose", "nomodeset"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckOutcome {
    /// When set, the device must persist this sequence before acting on the result.
    /// Invalid signatures, wrong device ids, replays, and expired commands do not advance it.
    pub advance_to: Option<u64>,
    pub code: Option<SbmErrorCode>,
}

impl CheckOutcome {
    pub fn accepted(sequence: u64) -> Self {
        Self {
            advance_to: Some(sequence),
            code: None,
        }
    }

    pub fn rejected(advance_to: Option<u64>, code: SbmErrorCode) -> Self {
        Self {
            advance_to,
            code: Some(code),
        }
    }

    pub fn is_accepted(&self) -> bool {
        self.code.is_none()
    }
}

pub fn signing_preimage(envelope: &CommandEnvelope) -> Vec<u8> {
    sbm_protocol::command_signing_preimage(envelope).expect("command envelope serializes")
}

pub fn canonical_json(envelope: &CommandEnvelope) -> Vec<u8> {
    sbm_protocol::command_canonical_json(envelope).expect("command envelope serializes")
}

pub fn sign(key: &SigningKey, envelope: &mut CommandEnvelope) {
    envelope.signature_ed25519_hex.clear();
    let sig = key.sign(&signing_preimage(envelope));
    envelope.signature_ed25519_hex = hex::encode(sig.to_bytes());
}

pub fn verify(key: &VerifyingKey, envelope: &CommandEnvelope) -> Result<(), SbmErrorCode> {
    let bytes = hex::decode(envelope.signature_ed25519_hex.trim())
        .map_err(|_| SbmErrorCode::SignatureInvalid)?;
    if bytes.len() != 64 {
        return Err(SbmErrorCode::SignatureInvalid);
    }
    let signature = Signature::from_slice(&bytes).map_err(|_| SbmErrorCode::SignatureInvalid)?;
    key.verify(&signing_preimage(envelope), &signature)
        .map_err(|_| SbmErrorCode::SignatureInvalid)
}

pub fn expected_scope(payload: &CommandPayload) -> AuthScope {
    match payload {
        CommandPayload::Boot(BootCommand::BootRecovery { .. }) => AuthScope::RecoveryAccess,
        CommandPayload::Boot(_) => AuthScope::BootSelect,
        CommandPayload::RunStoragePlan(_) => AuthScope::StorageDestructive,
        CommandPayload::RunOsInstall(_) => AuthScope::OsInstall,
        CommandPayload::RevokeEnrollment { .. } => AuthScope::Admin,
    }
}

/// Device-side checks shared by `sbm-sim` and the server's own tests.
///
/// `uefi` selects the pre-OS rules: only `read_only` and `boot_select` boot
/// commands, and only known targets plus allowlisted command-line presets.
/// Storage plans and OS install plans are refused in both modes in this release.
pub fn check_envelope(
    key: &VerifyingKey,
    envelope: &CommandEnvelope,
    device_id: &str,
    last_sequence: u64,
    now_unix: Option<i64>,
    uefi: bool,
    known_targets: &[BootTargetId],
) -> CheckOutcome {
    if verify(key, envelope).is_err() {
        return CheckOutcome::rejected(None, SbmErrorCode::SignatureInvalid);
    }
    if envelope.device_id != device_id {
        return CheckOutcome::rejected(None, SbmErrorCode::UnauthorizedScope);
    }
    if envelope.sequence <= last_sequence {
        return CheckOutcome::rejected(None, SbmErrorCode::ReplayDetected);
    }
    if envelope.expires_at_unix <= envelope.issued_at_unix {
        return CheckOutcome::rejected(None, SbmErrorCode::InvalidSchema);
    }
    if let Some(now) = now_unix
        && now > envelope.expires_at_unix
    {
        return CheckOutcome::rejected(None, SbmErrorCode::CommandExpired);
    }

    let advance = Some(envelope.sequence);
    if envelope.required_scope != expected_scope(&envelope.payload) {
        return CheckOutcome::rejected(advance, SbmErrorCode::UnauthorizedScope);
    }
    if uefi {
        match envelope.validate_metadata(device_id, last_sequence, now_unix, true) {
            Ok(()) => {}
            Err(code) => return CheckOutcome::rejected(advance, code),
        }
    }
    match &envelope.payload {
        CommandPayload::Boot(BootCommand::BootTarget {
            target_id,
            extra_cmdline_preset,
            ..
        }) => {
            if !target_id.is_valid() || !known_targets.iter().any(|id| id == target_id) {
                return CheckOutcome::rejected(advance, SbmErrorCode::TargetNotFound);
            }
            if let Some(preset) = extra_cmdline_preset
                && !CMDLINE_PRESETS.contains(&preset.as_str())
            {
                return CheckOutcome::rejected(advance, SbmErrorCode::UnauthorizedScope);
            }
        }
        CommandPayload::Boot(BootCommand::BootRecovery { .. }) => {
            if uefi {
                return CheckOutcome::rejected(advance, SbmErrorCode::UnauthorizedScope);
            }
        }
        CommandPayload::Boot(_) => {}
        CommandPayload::RunStoragePlan(_) | CommandPayload::RunOsInstall(_) => {
            return CheckOutcome::rejected(advance, SbmErrorCode::UnauthorizedScope);
        }
        CommandPayload::RevokeEnrollment { .. } => {
            if uefi {
                return CheckOutcome::rejected(advance, SbmErrorCode::UnauthorizedScope);
            }
        }
    }
    CheckOutcome::accepted(envelope.sequence)
}

pub fn preset_allowed(preset: &str) -> bool {
    CMDLINE_PRESETS.contains(&preset)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn fingerprint_sha256(der: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(der))
}

pub fn decode_key_32(hex_key: &str) -> Result<[u8; 32], SbmErrorCode> {
    let bytes = hex::decode(hex_key.trim()).map_err(|_| SbmErrorCode::InvalidSchema)?;
    bytes.try_into().map_err(|_| SbmErrorCode::InvalidSchema)
}

pub fn ed25519_spki_der(public: &[u8; 32]) -> Vec<u8> {
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend_from_slice(public);
    der
}

pub fn ed25519_pkcs8_der(seed: &[u8; 32]) -> Vec<u8> {
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(seed);
    der
}

pub fn pem_block(label: &str, der: &[u8]) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    let encoded = STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is utf-8"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

pub fn issuer_key_id(public_hex: &str) -> String {
    let prefix: String = public_hex.chars().take(16).collect();
    format!("ed25519:{prefix}")
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("os random");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbm_protocol::BootCommand;
    use sbm_types::SCHEMA_VERSION_V1;

    const GOLDEN_JSON: &str = concat!(
        r#"{"schema_version":"1.0","command_id":"019a0000-0000-7000-8000-000000000101","#,
        r#""device_id":"dev-qemu-01","sequence":1,"issued_at_unix":1795000000,"#,
        r#""expires_at_unix":1795003600,"required_scope":"boot_select","#,
        r#""issuer_key_id":"sbm-server-ed25519-01","payload":{"kind":"boot","#,
        r#""action":"boot_target","target_id":"sbm-core:slot-a","one_shot":true}}"#
    );

    fn sample() -> CommandEnvelope {
        CommandEnvelope {
            schema_version: SCHEMA_VERSION_V1.to_string(),
            command_id: "019a0000-0000-7000-8000-000000000101".to_string(),
            device_id: "dev-qemu-01".to_string(),
            sequence: 1,
            issued_at_unix: 1_795_000_000,
            expires_at_unix: 1_795_003_600,
            required_scope: AuthScope::BootSelect,
            issuer_key_id: "sbm-server-ed25519-01".to_string(),
            payload: CommandPayload::Boot(BootCommand::BootTarget {
                target_id: BootTargetId("sbm-core:slot-a".to_string()),
                one_shot: true,
                extra_cmdline_preset: None,
            }),
            signature_ed25519_hex: "00".repeat(64),
        }
    }

    #[test]
    fn canonical_json_matches_signing_profile() {
        let env = sample();
        let json = canonical_json(&env);
        assert_eq!(std::str::from_utf8(&json).unwrap(), GOLDEN_JSON);
        let preimage = signing_preimage(&env);
        assert!(preimage.starts_with(sbm_protocol::COMMAND_SIGNING_DOMAIN_V1));
        assert_eq!(
            preimage,
            sbm_protocol::command_signing_preimage(&env).unwrap()
        );
    }

    #[test]
    fn canonical_json_matches_serde_json_for_every_payload_kind() {
        let cases = vec![
            sample(),
            boot_with_preset(),
            recovery_command(),
            unit_boot(BootCommand::Reboot),
            unit_boot(BootCommand::Shutdown),
            unit_boot(BootCommand::RebootToFirmwareSetup),
            revoke_command(),
            storage_command(),
            install_command(),
        ];
        for envelope in cases {
            assert_eq!(
                canonical_json(&envelope),
                serde_json::to_vec(&Signable::from(&envelope)).unwrap(),
                "{}",
                envelope.command_id
            );
        }
    }

    #[derive(serde::Serialize)]
    struct Signable<'a> {
        schema_version: &'a str,
        command_id: &'a str,
        device_id: &'a str,
        sequence: u64,
        issued_at_unix: i64,
        expires_at_unix: i64,
        required_scope: &'a AuthScope,
        issuer_key_id: &'a str,
        payload: &'a CommandPayload,
    }

    impl<'a> From<&'a CommandEnvelope> for Signable<'a> {
        fn from(envelope: &'a CommandEnvelope) -> Self {
            Self {
                schema_version: &envelope.schema_version,
                command_id: &envelope.command_id,
                device_id: &envelope.device_id,
                sequence: envelope.sequence,
                issued_at_unix: envelope.issued_at_unix,
                expires_at_unix: envelope.expires_at_unix,
                required_scope: &envelope.required_scope,
                issuer_key_id: &envelope.issuer_key_id,
                payload: &envelope.payload,
            }
        }
    }

    fn boot_with_preset() -> CommandEnvelope {
        let mut envelope = sample();
        envelope.command_id = "preset".to_string();
        envelope.payload = CommandPayload::Boot(BootCommand::BootTarget {
            target_id: BootTargetId("linux:fedora".to_string()),
            one_shot: false,
            extra_cmdline_preset: Some("quiet".to_string()),
        });
        envelope
    }

    fn recovery_command() -> CommandEnvelope {
        let mut envelope = sample();
        envelope.command_id = "recovery".to_string();
        envelope.required_scope = AuthScope::RecoveryAccess;
        envelope.payload = CommandPayload::Boot(BootCommand::BootRecovery {
            slot: sbm_protocol::RecoverySlotPreference::SlotA,
            launch_mode: sbm_protocol::RecoveryLaunchMode::PlannedOperation {
                plan_id: "plan \"a\"\n\u{0001}β".to_string(),
            },
        });
        envelope
    }

    fn unit_boot(command: BootCommand) -> CommandEnvelope {
        let mut envelope = sample();
        envelope.command_id = "unit".to_string();
        envelope.payload = CommandPayload::Boot(command);
        envelope
    }

    fn revoke_command() -> CommandEnvelope {
        let mut envelope = sample();
        envelope.command_id = "revoke".to_string();
        envelope.required_scope = AuthScope::Admin;
        envelope.payload = CommandPayload::RevokeEnrollment {
            reason: "operator said \"stop\"".to_string(),
        };
        envelope
    }

    fn storage_command() -> CommandEnvelope {
        use sbm_types::{DiskBus, DiskIdentity, StorageOp, StorageOperationPlan};
        let mut envelope = sample();
        envelope.command_id = "storage".to_string();
        envelope.required_scope = AuthScope::StorageDestructive;
        envelope.payload = CommandPayload::RunStoragePlan(StorageOperationPlan {
            schema_version: "1.0".to_string(),
            plan_id: "plan-1".to_string(),
            target_disk: DiskIdentity {
                stable_id: "disk-1".to_string(),
                gpt_disk_guid: None,
                wwn_or_eui64: None,
                model: "virt".to_string(),
                serial_hash: None,
                size_bytes: 1024,
                logical_sector_size: 512,
                bus: DiskBus::Virtio,
                removable: false,
                read_only: false,
            },
            expected_partition_table_sha256: "abc".to_string(),
            operations: vec![StorageOp::DeletePartition {
                partition_guid: "guid".to_string(),
            }],
            destructive: true,
            reversible: false,
            touched_protected_classes: vec![],
            dry_run_summary: vec!["delete".to_string()],
        });
        envelope
    }

    fn install_command() -> CommandEnvelope {
        use sbm_types::{
            BootRegistrationPlan, CpuArch, InstallStrategy, OsInstallPlan, VerifiedArtifactRef,
        };
        let CommandPayload::RunStoragePlan(storage) = storage_command().payload else {
            unreachable!();
        };
        let mut envelope = sample();
        envelope.command_id = "install".to_string();
        envelope.required_scope = AuthScope::OsInstall;
        envelope.payload = CommandPayload::RunOsInstall(OsInstallPlan {
            schema_version: "1.0".to_string(),
            plan_id: "install-1".to_string(),
            catalog_entry_id: "fedora".to_string(),
            catalog_release_version: "45".to_string(),
            target_arch: CpuArch::X86_64,
            strategy: InstallStrategy::RootfsImageExtract,
            artifact_verification: vec![VerifiedArtifactRef {
                filename: "root.img".to_string(),
                size_bytes: 10,
                sha256: "aa".to_string(),
                source_url_or_path: "file://root.img".to_string(),
            }],
            storage_plan: storage,
            boot_registration: BootRegistrationPlan {
                register_bls_or_efi: true,
                set_as_default: false,
                display_name: None,
            },
            offline_media_only: true,
        });
        envelope
    }

    #[test]
    fn published_signing_vectors_verify() {
        let document: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../sbm-common/test-vectors/command-signing.v1.json"
        ))
        .unwrap();
        let seed = hex::decode(document["seed_hex"].as_str().unwrap()).unwrap();
        let key = SigningKey::from_bytes(&seed.try_into().unwrap());
        assert_eq!(
            hex::encode(key.verifying_key().to_bytes()),
            document["public_key_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(sbm_protocol::COMMAND_SIGNING_DOMAIN_V1),
            document["domain_hex"].as_str().unwrap()
        );
        let envelopes = [
            ("boot_target", sample()),
            ("boot_recovery", recovery_command()),
            ("revoke_enrollment", revoke_command()),
        ];
        for case in document["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let (_, envelope) = envelopes
                .iter()
                .find(|(label, _)| *label == name)
                .unwrap_or_else(|| panic!("missing case {name}"));
            let json = canonical_json(envelope);
            assert_eq!(
                std::str::from_utf8(&json).unwrap(),
                case["canonical_json"].as_str().unwrap()
            );
            let mut signed = envelope.clone();
            sign(&key, &mut signed);
            assert_eq!(
                signed.signature_ed25519_hex,
                case["signature_ed25519_hex"].as_str().unwrap()
            );
            assert!(verify(&key.verifying_key(), &signed).is_ok());
        }
    }

    #[test]
    fn round_trip_and_tamper_and_cross_device() {
        let key = SigningKey::from_bytes(&random_bytes());
        let verify = key.verifying_key();
        let mut env = sample();
        env.device_id = "device-a".to_string();
        sign(&key, &mut env);
        let targets = [BootTargetId("sbm-core:slot-a".to_string())];
        let ok = check_envelope(
            &verify,
            &env,
            "device-a",
            0,
            Some(1_795_000_100),
            true,
            &targets,
        );
        assert!(ok.is_accepted());

        let mut tampered = env.clone();
        tampered.signature_ed25519_hex.replace_range(0..2, "ff");
        let bad = check_envelope(
            &verify,
            &tampered,
            "device-a",
            0,
            Some(1_795_000_100),
            true,
            &targets,
        );
        assert_eq!(bad.code, Some(SbmErrorCode::SignatureInvalid));
        assert_eq!(bad.advance_to, None);

        let other = check_envelope(
            &verify,
            &env,
            "device-b",
            0,
            Some(1_795_000_100),
            true,
            &targets,
        );
        assert_eq!(other.code, Some(SbmErrorCode::UnauthorizedScope));
        assert_eq!(other.advance_to, None);

        let replay = check_envelope(
            &verify,
            &env,
            "device-a",
            1,
            Some(1_795_000_100),
            true,
            &targets,
        );
        assert_eq!(replay.code, Some(SbmErrorCode::ReplayDetected));

        let expired = check_envelope(
            &verify,
            &env,
            "device-a",
            0,
            Some(1_795_009_999),
            true,
            &targets,
        );
        assert_eq!(expired.code, Some(SbmErrorCode::CommandExpired));
        assert_eq!(expired.advance_to, None);
    }

    #[test]
    fn uefi_rejects_recovery_scope_destructive_payload_and_raw_cmdline() {
        let key = SigningKey::from_bytes(&random_bytes());
        let verify = key.verifying_key();
        let targets = [BootTargetId("sbm-core:slot-a".to_string())];

        let mut recovery = sample();
        recovery.device_id = "device-a".to_string();
        recovery.required_scope = AuthScope::RecoveryAccess;
        recovery.payload = CommandPayload::Boot(BootCommand::BootRecovery {
            slot: sbm_protocol::RecoverySlotPreference::Auto,
            launch_mode: sbm_protocol::RecoveryLaunchMode::RemoteAssist,
        });
        sign(&key, &mut recovery);
        let uefi = check_envelope(
            &verify,
            &recovery,
            "device-a",
            0,
            Some(1_795_000_100),
            true,
            &targets,
        );
        assert_eq!(uefi.code, Some(SbmErrorCode::UnauthorizedScope));
        assert_eq!(uefi.advance_to, Some(1));
        let core = check_envelope(
            &verify,
            &recovery,
            "device-a",
            0,
            Some(1_795_000_100),
            false,
            &targets,
        );
        assert!(core.is_accepted());

        let mut cmdline = sample();
        cmdline.device_id = "device-a".to_string();
        cmdline.payload = CommandPayload::Boot(BootCommand::BootTarget {
            target_id: BootTargetId("sbm-core:slot-a".to_string()),
            one_shot: true,
            extra_cmdline_preset: Some("init=/bin/sh".to_string()),
        });
        sign(&key, &mut cmdline);
        let rejected = check_envelope(
            &verify,
            &cmdline,
            "device-a",
            0,
            Some(1_795_000_100),
            true,
            &targets,
        );
        assert_eq!(rejected.code, Some(SbmErrorCode::UnauthorizedScope));
    }
}
