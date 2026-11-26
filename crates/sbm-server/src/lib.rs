mod assets;
mod authz;
mod clock;
mod config;
mod db;
mod error;
mod http;
mod hub;
mod identity;
mod rate;
mod state;
mod tls;
mod util;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::watch;
use webauthn_rs::prelude::WebauthnBuilder;

pub use clock::Clock;
pub use config::Config;
pub use error::ApiError;

use state::AppState;

pub struct ServerHandle {
    pub addr: SocketAddr,
    pub base_url: String,
    pub ca_pem: String,
    pub ca_fingerprint: String,
    pub data_dir: PathBuf,
    shutdown: watch::Sender<bool>,
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

pub async fn serve(config: Config) -> Result<ServerHandle, ApiError> {
    serve_with(config, Clock::system()).await
}

pub async fn serve_with(config: Config, clock: Clock) -> Result<ServerHandle, ApiError> {
    install_crypto();
    let data_dir = config.data_dir.clone();
    let material = identity::Material::load_or_create(&data_dir)?;
    let ca_pem = material.ca_cert_pem.clone();
    let ca_fingerprint = material.ca_fingerprint.clone();
    let db = db::Db::connect(&config.database_path).await?;
    if config.dev_bootstrap {
        ensure_lab(&db, clock.unix()).await?;
    }
    let origin = url::Url::parse(&config.public_origin)
        .map_err(|_| ApiError::invalid("SBM_PUBLIC_ORIGIN is not a URL"))?;
    let webauthn = WebauthnBuilder::new(&config.rp_id, &origin)
        .map_err(|err| {
            tracing::error!(error = %err, "webauthn configuration");
            ApiError::invalid("relying party id or origin was rejected")
        })?
        .rp_name("Smart Boot Menu")
        .allow_any_port(true)
        .build()
        .map_err(|err| {
            tracing::error!(error = %err, "webauthn build");
            ApiError::internal()
        })?;
    let state = AppState {
        config: Arc::new(config),
        db: db.clone(),
        identity: Arc::new(tokio::sync::RwLock::new(material)),
        clock: clock.clone(),
        webauthn: Arc::new(webauthn),
        challenges: state::ChallengeStore::default(),
        limiter: rate::Limiter::new(),
        hub: hub::Hub::default(),
    };
    let insecure_http = state.config.insecure_http;
    let tls = if insecure_http {
        None
    } else {
        Some(tls::acceptor(&state).await?)
    };
    let listener = TcpListener::bind(state.config.bind).await.map_err(|err| {
        tracing::error!(error = %err, "bind");
        ApiError::invalid(format!("cannot bind {}", state.config.bind))
    })?;
    let addr = listener.local_addr().map_err(|_| ApiError::internal())?;
    let (shutdown, shutdown_rx) = watch::channel(false);
    let app = http::router(state);
    tokio::spawn(tls::listen(listener, app, tls, shutdown_rx));
    let purge_db = db.clone();
    let purge_clock = clock;
    let mut purge_stop = shutdown.subscribe();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                changed = purge_stop.changed() => {
                    if changed.is_err() || *purge_stop.borrow() {
                        break;
                    }
                }
                () = tokio::time::sleep(Duration::from_secs(60)) => {
                    if let Err(err) = purge_db.purge_expired_sessions(purge_clock.unix()).await {
                        tracing::warn!(error = %err, "session purge");
                    }
                }
            }
        }
    });
    let scheme = if insecure_http { "http" } else { "https" };
    Ok(ServerHandle {
        base_url: format!("{scheme}://{}:{}", display_ip(addr.ip()), addr.port()),
        addr,
        ca_pem,
        ca_fingerprint,
        data_dir,
        shutdown,
    })
}

fn display_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) if ip.is_unspecified() => Ipv4Addr::LOCALHOST.to_string(),
        IpAddr::V6(ip) if ip.is_unspecified() => Ipv4Addr::LOCALHOST.to_string(),
        other => other.to_string(),
    }
}

fn install_crypto() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

async fn ensure_lab(db: &db::Db, now: i64) -> Result<(), ApiError> {
    if db.operator_by_username("lab").await?.is_some() {
        return Ok(());
    }
    let id = util::new_id();
    db.insert_operator(&id, "lab", "Lab Bootstrap", now).await?;
    db.set_role(&id, "admin").await?;
    db.audit(
        now,
        "system",
        "startup",
        "operator.bootstrap",
        None,
        &serde_json::json!({ "username": "lab" }),
    )
    .await?;
    Ok(())
}
