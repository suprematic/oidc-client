use std::io::IsTerminal;
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::oidc::{AuthUri, OidcConfiguration};
use anyhow::Result;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1 as http1_server;
use hyper::service::service_fn;
use hyper::{Request, Response, Uri};
use hyper_util::rt::TokioIo;
use serde_json as json;
use tokio::net::TcpListener;

#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

mod browser;
mod config;
mod oidc;

async fn auth_success_page(response: reqwest::Response) -> Result<(String, json::Value)> {
    let json_value: json::Value = response.json().await?;
    let json = json::to_string_pretty(&json_value)?;
    let json_hl = {
        use syntect::easy::HighlightLines;
        use syntect::highlighting::ThemeSet;
        use syntect::html::{styled_line_to_highlighted_html, IncludeBackground};
        use syntect::parsing::SyntaxSet;

        // Load these once at the start of your program
        let ps = SyntaxSet::load_defaults_newlines();
        let ts = ThemeSet::load_defaults();

        let syntax = ps.find_syntax_by_name("JSON").unwrap();
        let mut h = HighlightLines::new(syntax, &ts.themes["Solarized (dark)"]);
        let regions = h.highlight_line(&json, &ps).unwrap();
        styled_line_to_highlighted_html(&regions[..], IncludeBackground::No).unwrap()
    };
    Ok((
        r"
        <!DOCTYPE html>
        <html lang='en'>
        <head>
        <meta charset='UTF-8'>
        <meta name='viewport' content='width=device-width, initial-scale=1.0'>
        <title>Authorized [oidc-client]</title>
        </head>
        <body style='background-color: #222'>
        <pre>"
            .to_string()
            + json_hl.as_str()
            + r"
        </pre>
        <script>
        window.addEventListener('load', function() {
            const req = new XMLHttpRequest();
            req.open('GET', '/_/loaded');
            req.send();
        });
        </script>
        </body>
        </html>
        ",
        json_value,
    ))
}

async fn get_auth_tokens(token_endpoint: &str, auth_code: &str) -> Result<reqwest::Response> {
    let config = config::app_config();
    let redirect_uri = &config.redirect_uri;
    let (_, verifier) = code_challenge();
    let body = oidc::TokenRequestParams::for_auth_code(auth_code)
        .client_id(&config.client_id)
        .scope(&config.token_scopes)
        .redirect_uri(&redirect_uri.to_string())
        .code_verifier(verifier)
        .build()?;
    let response = reqwest::Client::new()
        .post(token_endpoint)
        .body(body)
        .header(
            "Origin",
            redirect_uri.scheme_str().unwrap().to_string()
                + "://"
                + redirect_uri.authority().unwrap().as_str(),
        )
        .send()
        .await?;
    Ok(response)
}

async fn handle_request(
    endpoints: &OidcConfiguration,
    request: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>> {
    let config = config::app_config();
    let request_uri = request.uri();
    trace!("request_uri: {:?}", request_uri.path());
    let redirect_uri = &config.redirect_uri;
    trace!("redirect_uri: {:?}", redirect_uri.path());
    let state = flow_state();

    if request_uri.path() == redirect_uri.path() {
        let auth_code_response = oidc::auth_code_response(request_uri, state)?;
        let token_endpoint = endpoints.token_endpoint.as_ref().unwrap();
        let response = get_auth_tokens(token_endpoint, &auth_code_response.code).await?;
        if response.status().is_success() {
            let (page, json_value) = auth_success_page(response).await?;
            let json = json::to_string(&json_value)?;
            println!("{}", json);
            Ok(Response::builder()
                .status(200)
                .body(Full::new(Bytes::from(page)))
                .unwrap())
        } else {
            Ok(Response::builder()
                .status(response.status())
                .body(Full::new(Bytes::from(response.bytes().await?)))
                .unwrap())
        }
    } else if request_uri.path() == "/_/loaded" {
        std::process::exit(0);
    } else {
        Ok(Response::builder()
            .status(404)
            .body(Full::new(Bytes::from(format!(
                "unrecognized request {request_uri}"
            ))))
            .unwrap())
    }
}

fn start_auth_code_flow(endpoints: &OidcConfiguration) -> Result<()> {
    let state = flow_state();
    let (code_challenge, _verifier) = code_challenge();
    let config = config::app_config();
    let uri = AuthUri::for_code_flow(endpoints.authorization_endpoint.as_ref().unwrap())
        .client_id(&config.client_id)
        .redirect_uri(&config.redirect_uri.to_string())
        .scope(&config.token_scopes)
        .code_challenge(code_challenge, "S256")
        .state(state)
        .login_hint(config.login_hint.as_ref())
        .prompt(config.login_prompt.as_ref())
        .build()?;
    debug!("auth URL: {uri}");
    browser::open(&uri)?;
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

fn code_challenge() -> &'static (String, String) {
    static CODE_CHALLENGE: OnceLock<(String, String)> = OnceLock::new();
    CODE_CHALLENGE.get_or_init(oidc::gen_code_challenge)
}

fn default_port(uri: &Uri) -> u16 {
    match uri.scheme().map(|s| s.as_str()) {
        Some("http") => 80,
        Some("https") => 443,
        _ => unreachable!(),
    }
}

fn http_uri_socket_addrs(uri: &Uri) -> Result<Vec<SocketAddr>> {
    let port = uri.port_u16().unwrap_or_else(|| default_port(uri));
    let host = uri.host().unwrap_or("127.0.0.1");
    let addrs = match dns_lookup::lookup_host(host) {
        Ok(addrs) => addrs,
        Err(error) => {
            error!(%host, "cannot resolve ip address for");
            return Err(anyhow::anyhow!(error));
        }
    };
    if addrs.is_empty() {
        return Err(anyhow::anyhow!("cannot resolve ip address for {}", host));
    }
    let socket_addrs = addrs
        .into_iter()
        .map(|addr| SocketAddr::from((addr, port)))
        .collect();
    Ok(socket_addrs)
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

    let redirect_uri = &config.redirect_uri;
    let addrs = http_uri_socket_addrs(redirect_uri)?;
    info!("listening on {redirect_uri} {:?}", addrs);
    let listener = TcpListener::bind(addrs.as_slice()).await?;

    let uri = &config.discovery_endpoint;
    let endpoints = oidc::discover_oidc_endpoints(&uri.to_string()).await?;

    start_auth_code_flow(&endpoints)?;

    loop {
        let (stream, _) = listener.accept().await?;

        // Use an adapter to access something implementing `tokio::io` traits as if they implement
        // `hyper::rt` IO traits.
        let io = TokioIo::new(stream);

        http1_server::Builder::new()
            .serve_connection(io, service_fn(|r| handle_request(&endpoints, r)))
            .await?;
    }
}
