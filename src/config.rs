use anyhow::Result;
use clap::builder::{ArgAction, NonEmptyStringValueParser, StringValueParser};
use hyper::Uri;
use std::sync::OnceLock;

#[derive(Debug)]
pub struct ConfigInner {
    pub log_level: tracing::Level,
    pub redirect_uri: Uri,
    pub discovery_endpoint: Uri,
    pub client_id: String,
    pub token_scopes: String,
    pub additional_http_headers: Vec<String>,
}

const fn const_unwrap_or(opt: Option<&'static str>, default: &'static str) -> &'static str {
    match opt {
        Some(x) => x,
        None => default,
    }
}

pub type Config = std::sync::Arc<ConfigInner>;

pub(crate) const VERSION: &str = clap::crate_version!();
pub(crate) const COMMIT_HASH: &str = const_unwrap_or(option_env!("COMMIT_HASH"), "deadbeef");
pub(crate) const FULL_VERSION: &str = const_format::formatcp!("{} {}", VERSION, COMMIT_HASH);

fn new() -> Result<Config> {
    let args = clap::command!()
        .version(FULL_VERSION)
        .author("SUPREMATIC Technology Arts GmbH")
        .args(&[
            clap::Arg::new("log")
                .long("log")
                .value_parser(clap::value_parser!(tracing::Level))
                .default_value(tracing::Level::ERROR.as_str()),
            clap::Arg::new("redirect-uri")
                .long("redirect-uri")
                .required(true)
                .value_parser(clap::value_parser!(Uri)),
            clap::Arg::new("discovery-endpoint")
                .long("discovery-endpoint")
                .required(true)
                .value_parser(clap::value_parser!(Uri)),
            clap::Arg::new("client-id")
                .long("client-id")
                .required(true)
                .value_parser(NonEmptyStringValueParser::new()),
            clap::Arg::new("token-scopes")
                .long("token-scopes")
                .default_value("openid profile")
                .value_parser(StringValueParser::new()),
            clap::Arg::new("additional-http-headers")
                .long("additional-http-header")
                .action(ArgAction::Append)
                .value_parser(NonEmptyStringValueParser::new()),
        ])
        .get_matches();

    let config = ConfigInner {
        log_level: *args.get_one("log").unwrap_or(&tracing::Level::INFO),
        redirect_uri: args.get_one::<Uri>("redirect-uri").unwrap().clone(),
        discovery_endpoint: args.get_one::<Uri>("discovery-endpoint").unwrap().clone(),
        client_id: args.get_one::<String>("client-id").unwrap().clone(),
        token_scopes: args.get_one::<String>("token-scopes").unwrap().clone(),
        additional_http_headers: args
            .get_many::<String>("additional-http-headers")
            .unwrap_or_default()
            .map(Clone::clone)
            .collect(),
    };
    Ok(std::sync::Arc::new(config))
}

pub(crate) fn app_config() -> &'static Config {
    static CONFIG: OnceLock<Config> = OnceLock::new();
    CONFIG.get_or_init(|| self::new().unwrap())
}

pub(crate) fn parse_args() -> &'static Config {
    app_config()
}
