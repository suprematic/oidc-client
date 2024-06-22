use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use base64::prelude::*;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Buf, Bytes};
use hyper::client::conn::http1;
use hyper::server::conn::http1 as http1_server;
use hyper::service::service_fn;
use hyper::{Request, Response, Uri};
use hyper_util::rt::TokioIo;
use rand::Rng;
use serde::Deserialize;
use serde_json as json;
use serde_urlencoded as urlencoded;
use sha2::{Digest, Sha256};
use std::net::{SocketAddr, ToSocketAddrs};
use tokio::net::{TcpListener, TcpStream};

mod config;

async fn handle_auth_response(
    request: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let config = config::app_config();
    let request_uri = request.uri();
    let redirect_uri = &config.redirect_uri;
    if request_uri.scheme() == redirect_uri.scheme()
        && request_uri.authority() == redirect_uri.authority()
        && request_uri.host() == redirect_uri.host()
        && request_uri.port() == redirect_uri.port()
        && request_uri.path() == redirect_uri.path()
    {
        Ok(Response::builder()
            .status(200)
            .body(Full::new(Bytes::from("Hello, World!")))
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

fn start_auth_code_flow() {
    let state = flow_state();
    let (code_challenge, _verifier) = code_challenge();
    let auth_result = authenticate(code_challenge, state);
    eprintln!("auth_code_flow: {auth_result:?}");
}

fn authenticate(code_challenge: &str, state: &str) -> Result<()> {
    let config = config::app_config();
    let client_id = &config.client_id;
    let redirect_uri = &config.redirect_uri;
    let scopes = &config.token_scopes;
    let query_string = urlencoded::to_string([
        ("response_type", "code"),
        ("code_challenge", code_challenge),
        ("code_challenge_method", "S256"),
        ("client_id", &client_id),
        ("redirect_uri", &redirect_uri.to_string()),
        ("scope", &scopes),
        ("state", state),
        ("prompt", "select_account"),
        /*
        ("login_hint", "SISKORO@tbdir.net")
        ("prompt", "none")
        */
    ]);
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

fn http_uri_socket_addr(uri: &Uri) -> SocketAddr {
    let port = uri.port_u16().unwrap_or_else(|| default_port(uri));
    let host = uri.host().unwrap_or("127.0.0.1");
    eprintln!("host: {host}");
    let ip_addr = IpAddr::from_str(host).unwrap();
    SocketAddr::from((ip_addr, port))
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

async fn discover_oidc_endpoints() -> Result<()> {
    let config = config::app_config();
    let uri = &config.redirect_uri;
    let address = http_uri_socket_addr(uri);

    let stream = TcpStream::connect(address).await?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = http1::handshake(io).await?;
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            println!("Connection failed: {:?}", err);
        }
    });

    let authority = config.redirect_uri.authority().unwrap();
    let request = Request::builder()
        .uri(&config.redirect_uri)
        .header(hyper::header::HOST, authority.as_str())
        .body(Empty::<Bytes>::new())?;

    let response = sender.send_request(request).await?;
    println!("Response status: {}", response.status());

    let body = response.collect().await?.aggregate();
    let endponts: OidcEndpoints = json::from_reader(body.reader())?;

    eprintln!("OIDC endpoints: {endponts:?}");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = config::parse_args();
    /*
    let config = config::app_config();

    let addr = http_uri_socket_addr(&config.redirect_uri);
    let listener = TcpListener::bind(addr).await?;
    */

    discover_oidc_endpoints().await?;

    /*
    start_auth_code_flow();

    let (stream, _) = listener.accept().await?;

    // Use an adapter to access something implementing `tokio::io` traits as if they implement
    // `hyper::rt` IO traits.
    let io = TokioIo::new(stream);

    http1_server::Builder::new()
        // `service_fn` converts our function in a `Service`
        .serve_connection(io, service_fn(handle_auth_response))
        .await?;
    */
    Ok(())
}
