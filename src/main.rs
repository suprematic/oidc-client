use std::io::IsTerminal;
use std::net::{SocketAddr, ToSocketAddrs};
use std::process::Command;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use base64::prelude::*;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1 as http1_server;
use hyper::service::service_fn;
use hyper::{Request, Response, Uri};
use hyper_util::rt::TokioIo;
use rand::Rng;
use serde::Deserialize;
use serde_urlencoded as urlencoded;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

mod config;

async fn handle_auth_response(
    endpoints: &OidcEndpoints,
    request: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>> {
    let config = config::app_config();
    let request_uri = request.uri();
    trace!("request_uri: {:?}", request_uri.path());
    let redirect_uri = &config.redirect_uri;
    trace!("redirect_uri: {:?}", redirect_uri.path());

    if request_uri.path() == redirect_uri.path() {
        let query = request_uri
            .query()
            .expect("no query component in the request URI");
        let query = urlencoded::from_str::<Vec<(&str, &str)>>(query)?;
        let code = query
            .into_iter()
            .find(|i| i.0 == "code")
            .expect("request does not contain an auth code")
            .1;
        let (_, verifier) = code_challenge();
        let body = urlencoded::to_string([
            ("client_id", config.client_id.as_str()),
            ("scope", config.token_scopes.as_str()),
            ("code", code),
            ("redirect_uri", &config.redirect_uri.to_string().as_str()),
            ("grant_type", "authorization_code"),
            ("code_verifier", verifier.as_str()),
        ])
        .unwrap();
        let response = reqwest::Client::new()
            .post(endpoints.token_endpoint.as_ref().unwrap())
            .body(body)
            .header(
                "Origin",
                redirect_uri.scheme_str().unwrap().to_string()
                    + "://"
                    + redirect_uri.authority().unwrap().as_str(),
            )
            .send()
            .await?;
        let status = response.status();
        let body_bytes = response.bytes().await?;
        let json = String::from_utf8(body_bytes.to_vec())?;
        debug!("token response: {status} {json}");
        println!("{}", json);
        Ok(Response::builder()
            .status(200)
            .body(Full::new(Bytes::from(json)))
            .unwrap())
    } else {
        Ok(Response::builder()
            .status(404)
            .body(Full::new(Bytes::from(format!(
                "unrecognized request {request_uri}"
            ))))
            .unwrap())
    }
}

fn start_auth_code_flow(endpoints: &OidcEndpoints) {
    let state = flow_state();
    let (code_challenge, _verifier) = code_challenge();
    let auth_result = authenticate(endpoints, code_challenge, state);
    debug!("auth_code_flow: {auth_result:?}");
}

#[cfg(target_os = "linux")]
fn open_browser(uri: &str) -> Result<()> {
    let _ = Command::new("xdg-open").arg(uri).spawn()?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn open_browser(uri: &str) -> Result<()> {
    let _ = Command::new("rundll32")
        .arg("url.dll,FileProtocolHandler")
        .arg(uri)
        .spawn()?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn open_browser(uri: &str) -> Result<()> {
    let _ = Command::new("open").arg(uri).spawn()?;
    Ok(())
}

fn authenticate(endpoints: &OidcEndpoints, code_challenge: &str, state: &str) -> Result<()> {
    let config = config::app_config();
    let client_id = &config.client_id;
    let redirect_uri = &config.redirect_uri.to_string();
    let scopes = &config.token_scopes;
    let mut query = vec![
        ("response_type", "code"),
        ("code_challenge", code_challenge),
        ("code_challenge_method", "S256"),
        ("client_id", &client_id),
        ("redirect_uri", redirect_uri.as_str()),
        ("scope", &scopes),
        ("state", state),
    ];
    if let Some(hint) = config.login_hint.as_ref() {
        query.push(("login_hint", hint))
    }
    if let Some(prompt) = config.login_prompt.as_ref() {
        query.push(("prompt", prompt))
    }
    let query_string = urlencoded::to_string(query)?;
    let auth_endpoint = endpoints.authorization_endpoint.as_ref().unwrap();
    let uri = format!("{auth_endpoint}?{query_string}");
    debug!("auth URL: {uri}");
    open_browser(&uri)?;
    Ok(())
}

fn gen_flow_state() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .to_string()
}

fn flow_state() -> &'static str {
    static FLOW_STATE: OnceLock<String> = OnceLock::new();
    FLOW_STATE.get_or_init(gen_flow_state)
}

fn gen_code_verifier() -> String {
    let bytes = rand::thread_rng().gen::<u32>().to_ne_bytes();
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}

fn gen_code_challenge() -> (String, String) {
    let verifier = gen_code_verifier();
    let bytes = verifier.bytes().collect::<Vec<u8>>();
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let sha_bytes = hasher.finalize();
    let challenge = BASE64_URL_SAFE_NO_PAD.encode(sha_bytes);
    (challenge, verifier)
}

fn code_challenge() -> &'static (String, String) {
    static CODE_CHALLENGE: OnceLock<(String, String)> = OnceLock::new();
    CODE_CHALLENGE.get_or_init(gen_code_challenge)
}

fn default_port(uri: &Uri) -> u16 {
    match uri.scheme().map(|s| s.as_str()) {
        Some("http") => 80,
        Some("https") => 443,
        _ => unreachable!(),
    }
}

fn http_uri_socket_addr(uri: &Uri) -> Result<SocketAddr> {
    let port = uri.port_u16().unwrap_or_else(|| default_port(uri));
    let host = uri.host().unwrap_or("127.0.0.1");
    let host_port = host.to_string() + ":" + &port.to_string();
    if let Some(addr) = host_port.to_socket_addrs()?.next() {
        Ok(addr)
    } else {
        Err(anyhow::anyhow!(
            "cannot resolve socket address {}",
            host_port
        ))
    }
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct OidcEndpoints {
    // "https://server.example.com"
    pub issuer: Option<String>,

    // "https://server.example.com/connect/authorize"
    pub authorization_endpoint: Option<String>,

    // "https://server.example.com/connect/token"
    pub token_endpoint: Option<String>,

    // ["client_secret_basic", "private_key_jwt"]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,

    // ["RS256", "ES256"]
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,

    // "https://server.example.com/connect/userinfo"
    pub userinfo_endpoint: Option<String>,

    // "https://server.example.com/connect/check_session"
    pub check_session_iframe: Option<String>,

    // "https://server.example.com/connect/end_session"
    pub end_session_endpoint: Option<String>,

    // "https://server.example.com/jwks.json"
    pub jwks_uri: Option<String>,

    // "https://server.example.com/connect/register"
    pub registration_endpoint: Option<String>,

    // ["openid", "profile", "email", "address", phone, "offline_access"]
    pub scopes_supported: Option<Vec<String>>,

    // ["code", "code id_token", "id_token", "id_token token"]
    pub response_types_supported: Option<Vec<String>>,

    // ["urn:mace:incommon:iap:silver", urnmace:incommon:iap:bronze"]
    pub acr_values_supported: Option<Vec<String>>,

    // ["public", "pairwise"]
    pub subject_types_supported: Option<Vec<String>>,

    // ["RS256", "ES256", "HS256"]
    pub userinfo_signing_alg_values_supported: Option<Vec<String>>,

    // ["RSA-OAEP-256", "A128KW"]
    pub userinfo_encryption_alg_values_supported: Option<Vec<String>>,

    // ["A128CBC-HS256", "A128GCM"]
    pub userinfo_encryption_enc_values_supported: Option<Vec<String>>,

    // ["RS256", "ES256", "HS256"]
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,

    // ["RSA-OAEP-256", "A128KW"]
    pub id_token_encryption_alg_values_supported: Option<Vec<String>>,

    // ["A128CBC-HS256", "A128GCM"]
    pub id_token_encryption_enc_values_supported: Option<Vec<String>>,

    // ["none", "RS256", "ES256"]
    pub request_object_signing_alg_values_supported: Option<Vec<String>>,

    // ["page", "popup"]
    pub display_values_supported: Option<Vec<String>>,

    // ["normal", "distributed"]
    pub claim_types_supported: Option<Vec<String>>,

    // ["sub", "iss", "auth_time", "acr", name, "given_name", "family_name", "nickname", profile, "picture", "website", email, "email_verified", "locale", "zoneinfo", http//example.info/claims/groups"]
    pub claims_supported: Option<Vec<String>>,

    // true
    pub claims_parameter_supported: Option<bool>,

    // "http://server.example.com/connect/service_documentation.html"
    pub service_documentation: Option<String>,

    // ["en-US", "en-GB", "en-CA", "fr-FR", "fr-CA"]
    pub ui_locales_supported: Option<Vec<String>>,
}

async fn discover_oidc_endpoints() -> Result<OidcEndpoints> {
    let config = config::app_config();
    let uri = &config.discovery_endpoint;
    let endpoints = reqwest::get(uri.to_string())
        .await?
        .json::<OidcEndpoints>()
        .await?;
    debug!("OIDC endpoints: {endpoints:#?}");
    Ok(endpoints)
}

fn setup_logging(config: &config::Config) {
    use tracing_subscriber::prelude::*;
    let filter = tracing_subscriber::filter::targets::Targets::default()
        .with_targets(vec![
            ("rustls", tracing::Level::WARN),
            ("polling", tracing::Level::WARN),
            ("async_io", tracing::Level::WARN),
            ("hyper", tracing::Level::INFO),
            ("tokio_util", tracing::Level::DEBUG),
        ])
        .with_default(config.log_level);

    let ansi_colors_enabled = !cfg!(windows) && std::io::stdout().is_terminal();
    let format = tracing_subscriber::fmt::layer()
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .with_ansi(ansi_colors_enabled);

    tracing_subscriber::registry()
        .with(filter)
        .with(format)
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = config::parse_args();
    let config = config::app_config();

    setup_logging(&config);

    let addr = http_uri_socket_addr(&config.redirect_uri)?;
    let listener = TcpListener::bind(addr).await?;

    let endpoints = discover_oidc_endpoints().await?;

    start_auth_code_flow(&endpoints);

    let (stream, _) = listener.accept().await?;

    // Use an adapter to access something implementing `tokio::io` traits as if they implement
    // `hyper::rt` IO traits.
    let io = TokioIo::new(stream);

    http1_server::Builder::new()
        .serve_connection(io, service_fn(|r| handle_auth_response(&endpoints, r)))
        .await?;
    Ok(())
}
