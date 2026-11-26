use crate::{SimError, SimResult, pem_der};
use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
};

pub type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

pub async fn connect(
    url: &str,
    ca_pem: &str,
    identity_pem: Option<String>,
    cookie: Option<&str>,
) -> SimResult<Socket> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let config = client_config(ca_pem, identity_pem.as_deref())?;
    let mut request = url
        .into_client_request()
        .map_err(|err| SimError(err.to_string()))?;
    if let Some(cookie) = cookie {
        let value = cookie
            .parse()
            .map_err(|_| SimError("session cookie is not a valid header".to_string()))?;
        request.headers_mut().insert("cookie", value);
    }
    let (socket, _response) = connect_async_tls_with_config(
        request,
        None,
        false,
        Some(Connector::Rustls(Arc::new(config))),
    )
    .await
    .map_err(|err| SimError(err.to_string()))?;
    Ok(socket)
}

pub async fn read_binary_frame(url: &str, ca_pem: &str, cookie: &str) -> SimResult<Vec<u8>> {
    let mut socket = connect(url, ca_pem, None, Some(cookie)).await?;
    match socket.next().await {
        Some(Ok(Message::Binary(bytes))) => Ok(bytes.to_vec()),
        Some(Ok(message)) => Err(SimError(format!("unexpected tunnel message: {message:?}"))),
        Some(Err(err)) => Err(SimError(err.to_string())),
        None => Err(SimError("tunnel closed before a frame arrived".to_string())),
    }
}

pub async fn serve_terminal(mut socket: Socket) -> SimResult<()> {
    let banner = b"sbm-sim terminal. This is not a real PTY. No hardware session is attached.\r\n";
    socket
        .send(Message::Binary(banner.to_vec().into()))
        .await
        .map_err(|err| SimError(err.to_string()))?;
    while let Some(message) = socket.next().await {
        match message {
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(_) => {}
        }
    }
    Ok(())
}

fn client_config(ca_pem: &str, identity_pem: Option<&str>) -> SimResult<ClientConfig> {
    let mut roots = RootCertStore::empty();
    let ca = pem_der(ca_pem)?;
    roots
        .add(CertificateDer::from(ca))
        .map_err(|err| SimError(format!("CA was rejected: {err}")))?;
    let builder = ClientConfig::builder().with_root_certificates(roots);
    let mut config = if let Some(pem) = identity_pem {
        let (cert, key) = split_identity(pem)?;
        builder
            .with_client_auth_cert(
                vec![CertificateDer::from(cert)],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
            )
            .map_err(|err| SimError(err.to_string()))?
    } else {
        builder.with_no_client_auth()
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

fn split_identity(pem: &str) -> SimResult<(Vec<u8>, Vec<u8>)> {
    let mut cert = None;
    let mut key = None;
    let mut label = String::new();
    let mut b64 = String::new();
    let mut inside = false;
    for line in pem.lines() {
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            label = rest.trim_end_matches("-----").to_string();
            b64.clear();
            inside = true;
            continue;
        }
        if line.starts_with("-----END ") {
            let der = super::pem_der(&format!(
                "-----BEGIN {label}-----\n{b64}\n-----END {label}-----\n"
            ))?;
            if label.contains("CERTIFICATE") {
                cert = Some(der);
            } else {
                key = Some(der);
            }
            inside = false;
            continue;
        }
        if inside {
            b64.push_str(line.trim());
        }
    }
    Ok((
        cert.ok_or_else(|| SimError("client certificate PEM is missing".to_string()))?,
        key.ok_or_else(|| SimError("client private key PEM is missing".to_string()))?,
    ))
}
