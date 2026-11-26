use crate::error::ApiError;
use crate::util::sha256_hex;
use ed25519_dalek::SigningKey;
use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SanType,
};
use sbm_wire::{ed25519_spki_der, fingerprint_sha256, issuer_key_id, random_bytes};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use time::{Duration, OffsetDateTime};

pub struct Material {
    pub ca_cert_pem: String,
    pub ca_key_pem: String,
    pub ca_fingerprint: String,
    pub server_cert_pem: String,
    pub server_key_pem: String,
    pub command_seed: [u8; 32],
    pub command_public_hex: String,
    pub issuer_key_id: String,
}

impl Material {
    pub fn load_or_create(dir: &Path) -> Result<Self, ApiError> {
        fs::create_dir_all(dir).map_err(|err| {
            tracing::error!(error = %err, "create data dir");
            ApiError::internal()
        })?;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
        let ca_cert = dir.join("ca.cert.pem");
        if ca_cert.exists() {
            return Self::load(dir);
        }
        Self::generate(dir)
    }

    fn load(dir: &Path) -> Result<Self, ApiError> {
        let ca_cert_pem = read_string(&dir.join("ca.cert.pem"))?;
        let ca_key_pem = read_string(&dir.join("ca.key.pem"))?;
        let server_cert_pem = read_string(&dir.join("server.cert.pem"))?;
        let server_key_pem = read_string(&dir.join("server.key.pem"))?;
        let seed_bytes = fs::read(dir.join("command.key.bin")).map_err(|err| {
            tracing::error!(error = %err, "read command key");
            ApiError::internal()
        })?;
        let command_seed: [u8; 32] = seed_bytes
            .try_into()
            .map_err(|_| ApiError::invalid("command key has the wrong length"))?;
        let public_hex = public_hex(&command_seed);
        let ca_der = pem_first_der(&ca_cert_pem)?;
        Ok(Self {
            ca_fingerprint: fingerprint_sha256(&ca_der),
            ca_cert_pem,
            ca_key_pem,
            server_cert_pem,
            server_key_pem,
            issuer_key_id: issuer_key_id(&public_hex),
            command_public_hex: public_hex,
            command_seed,
        })
    }

    fn generate(dir: &Path) -> Result<Self, ApiError> {
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(cert_err)?;
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Smart Boot Menu CA");
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        ca_params.not_before = OffsetDateTime::now_utc() - Duration::minutes(5);
        ca_params.not_after = OffsetDateTime::now_utc() + Duration::days(3650);
        let ca_cert = ca_params.self_signed(&ca_key).map_err(cert_err)?;
        let ca_cert_pem = ca_cert.pem();
        let ca_key_pem = ca_key.serialize_pem();

        let server_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(cert_err)?;
        let mut server_params = CertificateParams::default();
        server_params
            .distinguished_name
            .push(DnType::CommonName, "Smart Boot Menu");
        server_params.subject_alt_names = vec![
            SanType::DnsName(Ia5String::try_from("localhost").map_err(cert_err)?),
            SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ];
        server_params.use_authority_key_identifier_extension = true;
        server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        server_params.not_before = OffsetDateTime::now_utc() - Duration::minutes(5);
        server_params.not_after = OffsetDateTime::now_utc() + Duration::days(825);
        let issuer = Issuer::from_ca_cert_pem(&ca_cert_pem, ca_key).map_err(cert_err)?;
        let server_cert = server_params
            .signed_by(&server_key, &issuer)
            .map_err(cert_err)?;
        let server_cert_pem = server_cert.pem();
        let server_key_pem = server_key.serialize_pem();

        let command_seed: [u8; 32] = random_bytes();
        let public_hex = public_hex(&command_seed);
        let ca_der = pem_first_der(&ca_cert_pem)?;
        write_secret(&dir.join("ca.key.pem"), ca_key_pem.as_bytes())?;
        write_public(&dir.join("ca.cert.pem"), ca_cert_pem.as_bytes())?;
        write_secret(&dir.join("server.key.pem"), server_key_pem.as_bytes())?;
        write_public(&dir.join("server.cert.pem"), server_cert_pem.as_bytes())?;
        write_secret(&dir.join("command.key.bin"), &command_seed)?;
        write_public(
            &dir.join("command.pub"),
            format!("{public_hex}\n").as_bytes(),
        )?;
        Ok(Self {
            ca_fingerprint: fingerprint_sha256(&ca_der),
            ca_cert_pem,
            ca_key_pem,
            server_cert_pem,
            server_key_pem,
            issuer_key_id: issuer_key_id(&public_hex),
            command_public_hex: public_hex,
            command_seed,
        })
    }

    pub fn rotate_command_key(&mut self, dir: &Path) -> Result<String, ApiError> {
        let previous = self.command_public_hex.clone();
        let command_seed: [u8; 32] = random_bytes();
        let public_hex = public_hex(&command_seed);
        write_secret(&dir.join("command.key.bin"), &command_seed)?;
        write_public(
            &dir.join("command.pub"),
            format!("{public_hex}\n").as_bytes(),
        )?;
        let _ = fs::write(dir.join("command.previous.pub"), format!("{previous}\n"));
        self.command_seed = command_seed;
        self.issuer_key_id = issuer_key_id(&public_hex);
        self.command_public_hex = public_hex;
        Ok(previous)
    }

    pub fn issue_device_cert(
        &self,
        device_id: &str,
        public: &[u8; 32],
    ) -> Result<String, ApiError> {
        let spki =
            rcgen::SubjectPublicKeyInfo::from_der(&ed25519_spki_der(public)).map_err(cert_err)?;
        let mut params = CertificateParams::default();
        let common_name = format!("sbm-{device_id}");
        params
            .distinguished_name
            .push(DnType::CommonName, &common_name);
        let uri = Ia5String::try_from(format!("urn:sbm:device:{device_id}")).map_err(cert_err)?;
        params.subject_alt_names = vec![SanType::URI(uri)];
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.not_before = OffsetDateTime::now_utc() - Duration::minutes(5);
        params.not_after = OffsetDateTime::now_utc() + Duration::days(90);
        let ca_key = KeyPair::from_pem(&self.ca_key_pem).map_err(cert_err)?;
        let issuer = Issuer::from_ca_cert_pem(&self.ca_cert_pem, ca_key).map_err(cert_err)?;
        let cert = params.signed_by(&spki, &issuer).map_err(cert_err)?;
        Ok(cert.pem())
    }

    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.command_seed)
    }
}

fn public_hex(seed: &[u8; 32]) -> String {
    hex::encode(SigningKey::from_bytes(seed).verifying_key().to_bytes())
}

fn cert_err(err: impl std::fmt::Display) -> ApiError {
    tracing::error!(error = %err, "certificate");
    ApiError::internal()
}

fn read_string(path: &Path) -> Result<String, ApiError> {
    fs::read_to_string(path).map_err(|err| {
        tracing::error!(error = %err, path = %path.display(), "read identity file");
        ApiError::internal()
    })
}

fn write_secret(path: &Path, bytes: &[u8]) -> Result<(), ApiError> {
    write_mode(path, bytes, 0o600)
}

fn write_public(path: &Path, bytes: &[u8]) -> Result<(), ApiError> {
    write_mode(path, bytes, 0o644)
}

fn write_mode(path: &Path, bytes: &[u8], mode: u32) -> Result<(), ApiError> {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(mode)
        .open(path)
        .map_err(|err| {
            tracing::error!(error = %err, "write identity file");
            ApiError::internal()
        })?;
    file.write_all(bytes).map_err(|_| ApiError::internal())?;
    Ok(())
}

pub fn pem_first_der(pem: &str) -> Result<Vec<u8>, ApiError> {
    let mut der = Vec::new();
    let mut collecting = false;
    let mut b64 = String::new();
    for line in pem.lines() {
        if line.starts_with("-----BEGIN ") {
            collecting = true;
            b64.clear();
            continue;
        }
        if line.starts_with("-----END ") {
            let bytes = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                b64.replace('\n', ""),
            )
            .map_err(|_| ApiError::invalid("certificate PEM is not valid base64"))?;
            der = bytes;
            break;
        }
        if collecting {
            b64.push_str(line.trim());
        }
    }
    if der.is_empty() {
        return Err(ApiError::invalid("certificate PEM was empty"));
    }
    Ok(der)
}

pub fn cert_sha256_pem(pem: &str) -> Result<String, ApiError> {
    Ok(sha256_hex(&pem_first_der(pem)?))
}
