use crate::error::ApiError;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Config {
    pub bind: SocketAddr,
    pub data_dir: PathBuf,
    pub public_origin: String,
    pub rp_id: String,
    pub database_path: PathBuf,
    pub dev_bootstrap: bool,
    pub bootstrap_secret: Option<String>,
    pub enrollment_ttl: Duration,
    pub boot_command_ttl: Duration,
    pub recovery_command_ttl: Duration,
    pub session_ttl: Duration,
    pub log_json: bool,
    pub insecure_http: bool,
}

#[derive(serde::Deserialize, Default)]
struct FileConfig {
    bind: Option<String>,
    data_dir: Option<String>,
    public_origin: Option<String>,
    rp_id: Option<String>,
    dev_bootstrap: Option<bool>,
    bootstrap_secret: Option<String>,
    enrollment_ttl_seconds: Option<u64>,
    boot_command_ttl_seconds: Option<u64>,
    recovery_command_ttl_seconds: Option<u64>,
    session_ttl_seconds: Option<u64>,
    log_format: Option<String>,
    insecure_http: Option<bool>,
}

impl Config {
    pub fn from_env() -> Result<Self, ApiError> {
        let mut file = FileConfig::default();
        if let Ok(path) = std::env::var("SBM_CONFIG") {
            let text = fs::read_to_string(&path)
                .map_err(|_| ApiError::invalid(format!("cannot read config file {path}")))?;
            file = toml::from_str(&text).map_err(|err| ApiError::invalid(err.to_string()))?;
        }
        let data_dir = PathBuf::from(env_or(file.data_dir, "SBM_DATA_DIR", "./data"));
        let bind: SocketAddr = env_or(file.bind, "SBM_BIND", "127.0.0.1:8443")
            .parse()
            .map_err(|_| ApiError::invalid("SBM_BIND is not a socket address"))?;
        let public_origin = env_or(
            file.public_origin,
            "SBM_PUBLIC_ORIGIN",
            "https://localhost:8443",
        );
        let rp_id = env_or(file.rp_id, "SBM_RP_ID", "localhost");
        let dev_bootstrap = flag(file.dev_bootstrap, "SBM_DEV_BOOTSTRAP");
        let bootstrap_secret = std::env::var("SBM_BOOTSTRAP_SECRET")
            .ok()
            .or(file.bootstrap_secret)
            .filter(|s| !s.is_empty());
        if dev_bootstrap {
            match &bootstrap_secret {
                Some(secret) if secret.len() >= 16 => {}
                _ => {
                    return Err(ApiError::invalid(
                        "SBM_DEV_BOOTSTRAP requires SBM_BOOTSTRAP_SECRET of at least 16 characters",
                    ));
                }
            }
        }
        let enrollment_ttl = duration(
            file.enrollment_ttl_seconds,
            "SBM_ENROLLMENT_TTL_SECONDS",
            600,
            30,
            900,
        )?;
        let boot_command_ttl = duration(
            file.boot_command_ttl_seconds,
            "SBM_BOOT_COMMAND_TTL_SECONDS",
            43_200,
            30,
            86_400,
        )?;
        let recovery_command_ttl = duration(
            file.recovery_command_ttl_seconds,
            "SBM_RECOVERY_COMMAND_TTL_SECONDS",
            1_800,
            30,
            86_400,
        )?;
        let session_ttl = duration(
            file.session_ttl_seconds,
            "SBM_SESSION_TTL_SECONDS",
            43_200,
            300,
            86_400,
        )?;
        let log_format = env_or(file.log_format, "SBM_LOG_FORMAT", "text");
        let insecure_http = flag(file.insecure_http, "SBM_INSECURE_HTTP");
        if !insecure_http && !public_origin.starts_with("https://") {
            return Err(ApiError::invalid(
                "SBM_PUBLIC_ORIGIN must be https unless SBM_INSECURE_HTTP=1",
            ));
        }
        Ok(Self {
            bind,
            database_path: data_dir.join("sbm.db"),
            data_dir,
            public_origin,
            rp_id,
            dev_bootstrap,
            bootstrap_secret,
            enrollment_ttl,
            boot_command_ttl,
            recovery_command_ttl,
            session_ttl,
            log_json: log_format == "json",
            insecure_http,
        })
    }

    pub fn for_test(data_dir: &Path, bind: SocketAddr, secret: &str) -> Self {
        Self {
            bind,
            database_path: data_dir.join("sbm.db"),
            data_dir: data_dir.to_path_buf(),
            public_origin: "https://localhost:8443".to_string(),
            rp_id: "localhost".to_string(),
            dev_bootstrap: true,
            bootstrap_secret: Some(secret.to_string()),
            enrollment_ttl: Duration::from_secs(600),
            boot_command_ttl: Duration::from_secs(3_600),
            recovery_command_ttl: Duration::from_secs(1_800),
            session_ttl: Duration::from_secs(3_600),
            log_json: false,
            insecure_http: false,
        }
    }
}

fn env_or(file: Option<String>, key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .or(file)
        .unwrap_or_else(|| default.to_string())
}

fn flag(file: Option<bool>, key: &str) -> bool {
    match std::env::var(key) {
        Ok(value) => matches!(value.as_str(), "1" | "true" | "TRUE" | "yes"),
        Err(_) => file.unwrap_or(false),
    }
}

fn duration(
    file: Option<u64>,
    key: &str,
    default: u64,
    min: u64,
    max: u64,
) -> Result<Duration, ApiError> {
    let raw = match std::env::var(key) {
        Ok(value) => value
            .parse::<u64>()
            .map_err(|_| ApiError::invalid(format!("{key} must be a number of seconds")))?,
        Err(_) => file.unwrap_or(default),
    };
    if !(min..=max).contains(&raw) {
        return Err(ApiError::invalid(format!(
            "{key} must be between {min} and {max} seconds"
        )));
    }
    Ok(Duration::from_secs(raw))
}
