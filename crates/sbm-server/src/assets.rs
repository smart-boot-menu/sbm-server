use axum::body::Body;
use axum::http::{StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use rust_embed::RustEmbed;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

#[derive(RustEmbed)]
#[folder = "assets"]
struct Assets;

pub fn content_security_policy() -> &'static str {
    static POLICY: OnceLock<String> = OnceLock::new();
    POLICY.get_or_init(|| {
        let hashes = Assets::get("index.html")
            .map(|file| script_hashes(std::str::from_utf8(file.data.as_ref()).unwrap_or("")))
            .unwrap_or_default();
        format!(
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'{hashes}; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'"
        )
    })
}

fn script_hashes(html: &str) -> String {
    let mut rest = html;
    let mut hashes = String::new();
    while let Some(start) = rest.find("<script") {
        let after = &rest[start..];
        let Some(tag_end) = after.find('>') else {
            break;
        };
        let tag = &after[..tag_end];
        rest = &after[tag_end + 1..];
        let Some(end) = rest.find("</script>") else {
            break;
        };
        if !tag.contains("src=") {
            let digest = Sha256::digest(&rest.as_bytes()[..end]);
            let encoded = base64::engine::general_purpose::STANDARD.encode(digest);
            hashes.push_str(" 'sha256-");
            hashes.push_str(&encoded);
            hashes.push('\'');
        }
        rest = &rest[end + "</script>".len()..];
    }
    hashes
}

pub async fn spa(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    if let Some(file) = Assets::get(path) {
        return file_response(path, file.data.as_ref(), false);
    }
    if let Some(file) = Assets::get("index.html") {
        return file_response("index.html", file.data.as_ref(), true);
    }
    StatusCode::NOT_FOUND.into_response()
}

fn file_response(path: &str, bytes: &[u8], html_fallback: bool) -> Response {
    let mime = match path.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("json") => "application/json",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("png") => "image/png",
        Some("wasm") => "application/wasm",
        Some("map") => "application/json",
        _ => "application/octet-stream",
    };
    let cache = if path.ends_with(".html") || html_fallback {
        "no-store"
    } else {
        "public, max-age=3600"
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CACHE_CONTROL, cache)
        .body(Body::from(bytes.to_vec()))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
