use crate::error::ApiError;
use crate::identity::pem_first_der;
use crate::state::AppState;
use axum::Router;
use axum::extract::Request;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use rustls::pki_types::CertificateDer;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tower::Service;

#[derive(Clone)]
pub struct PeerCert(pub Vec<u8>);

#[derive(Clone, Copy)]
pub struct PeerAddr(pub SocketAddr);

pub async fn acceptor(state: &AppState) -> Result<TlsAcceptor, ApiError> {
    let material = state.identity.read().await;
    let ca_der = pem_first_der(&material.ca_cert_pem)?;
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_der))
        .map_err(|_| ApiError::internal())?;
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .allow_unauthenticated()
        .build()
        .map_err(|err| {
            tracing::error!(error = %err, "client verifier");
            ApiError::internal()
        })?;
    let certs = rustls_pemfile::certs(&mut material.server_cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ApiError::internal())?;
    let key = rustls_pemfile::private_key(&mut material.server_key_pem.as_bytes())
        .map_err(|_| ApiError::internal())?
        .ok_or_else(ApiError::internal)?;
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![
        rustls::crypto::aws_lc_rs::kx_group::X25519,
        rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
    ];
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|err| {
            tracing::error!(error = %err, "tls versions");
            ApiError::internal()
        })?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|err| {
            tracing::error!(error = %err, "server certificate");
            ApiError::internal()
        })?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    drop(material);
    Ok(TlsAcceptor::from(Arc::new(config)))
}

pub async fn listen(
    listener: TcpListener,
    app: Router,
    tls: Option<TlsAcceptor>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let Ok((tcp, addr)) = accepted else { continue; };
                let app = app.clone();
                let tls = tls.clone();
                tokio::spawn(async move {
                    if let Some(tls) = tls {
                        match tls.accept(tcp).await {
                            Ok(stream) => {
                                let der = stream
                                    .get_ref()
                                    .1
                                    .peer_certificates()
                                    .and_then(|chain| chain.first())
                                    .map(|cert| cert.as_ref().to_vec());
                                serve_io(stream, app, addr, der).await;
                            }
                            Err(err) => tracing::debug!(error = %err, "tls handshake failed"),
                        }
                    } else {
                        serve_io(tcp, app, addr, None).await;
                    }
                });
            }
        }
    }
}

async fn serve_io<I>(io: I, app: Router, addr: SocketAddr, cert: Option<Vec<u8>>)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(io);
    let service = hyper::service::service_fn(move |mut request: Request<Incoming>| {
        if let Some(der) = cert.clone() {
            request.extensions_mut().insert(PeerCert(der));
        }
        request.extensions_mut().insert(PeerAddr(addr));
        app.clone().call(request)
    });
    let connection = hyper::server::conn::http1::Builder::new().serve_connection(io, service);
    if let Err(err) = connection.with_upgrades().await {
        tracing::debug!(error = %err, "http connection closed");
    }
}
