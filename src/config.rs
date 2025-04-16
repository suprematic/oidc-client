use anyhow::Result;
use clap::{
    builder::{NonEmptyStringValueParser, StringValueParser},
    ArgAction,
};
use clap_complete::Shell;
use hyper::Uri;
use std::sync::OnceLock;

#[derive(Debug)]
pub struct ConfigInner {
    pub log_level: tracing::Level,
    pub redirect_uri: Uri,
    pub discovery_endpoint: Uri,
    pub client_id: String,
    pub token_scopes: Vec<String>,
    pub login_hint: Option<String>,
    pub login_prompt: Option<String>,
}

const fn const_unwrap_or(opt: Option<&'static str>, default: &'static str) -> &'static str {
    match opt {
        Some(x) => x,
        None => default,
    }
}

fn wrap_at(s: &str, at: usize) -> String {
    let words = s.split(&[' ', '\t']).filter(|l| !l.is_empty());
    let mut wrapped = vec![];
    let mut line = String::new();
    for w in words {
        if !line.is_empty() && line.len() + w.len() >= at {
            wrapped.push(line);
            line = "".into()
        }
        line = line + w + " ";
    }
    wrapped.push(line);
    wrapped.join("\n")
}

fn wrap_help(s: &str) -> String {
    wrap_at(s, 70)
}

pub type Config = std::sync::Arc<ConfigInner>;

pub(crate) const VERSION: &str = clap::crate_version!();
pub(crate) const COMMIT_HASH: &str = const_unwrap_or(option_env!("COMMIT_HASH"), "deadbeef");
pub(crate) const FULL_VERSION: &str = const_format::formatcp!("{} {}", VERSION, COMMIT_HASH);

fn cli() -> clap::Command {
    clap::command!()
        .version(FULL_VERSION)
        .author("SUPREMATIC Technology Arts GmbH")
        .args(&[
            clap::Arg::new("log")
                .long("log")
                .help(wrap_help("Log level"))
                .value_parser(clap::value_parser!(tracing::Level))
                .default_value(tracing::Level::ERROR.as_str()),
            clap::Arg::new("redirect-uri")
                .long("redirect-uri")
                .help(wrap_help(
                    "Redirect URI to use in the authorization request",
                ))
                .required_unless_present("print-completions")
                .value_parser(clap::value_parser!(Uri)),
            clap::Arg::new("discovery-endpoint")
                .long("discovery-endpoint")
                .alias("oidc-configuration-uri")
                .help(wrap_help("OIDC configuration URI"))
                .required_unless_present("print-completions")
                .value_parser(clap::value_parser!(Uri)),
            clap::Arg::new("client-id")
                .long("client-id")
                .help(wrap_help("OIDC client ID obtaining the token(s)"))
                .required_unless_present("print-completions")
                .value_parser(NonEmptyStringValueParser::new()),
            clap::Arg::new("scopes")
                .long("scopes")
                .alias("token-scopes")
                .conflicts_with("scope")
                .help(wrap_help("Space-separated OIDC scope values"))
                .default_value("openid profile")
                .value_parser(StringValueParser::new()),
            clap::Arg::new("scope")
                .long("scope")
                .help(wrap_help("OIDC scope value"))
                .value_parser(StringValueParser::new())
                .action(ArgAction::Append)
                .num_args(1),
            clap::Arg::new("login-hint")
                .long("login-hint")
                .help(wrap_help(
                    "Hint to the authorization server about the user login identifier",
                ))
                .value_parser(NonEmptyStringValueParser::new()),
            clap::Arg::new("login-prompt")
                .long("login-prompt")
                .help(wrap_help(
                    "Space-delimited list that specifies whether the authorization server prompts the user for reauthentication and consent"
                ))
                .value_parser(["none", "login", "consent", "select_account"]),
            clap::Arg::new("print-completions")
                .long("print-completions")
                .value_name("SHELL")
                .help("Print shell completions.")
                .value_parser(clap::value_parser!(clap_complete::Shell)),
        ])
}

fn new() -> Result<Config> {
    let args = cli().get_matches();

    if let Some(shell) = args.get_one::<Shell>("print-completions").copied() {
        let mut cmd = cli();
        eprintln!("Generating completion file for {shell}...");
        let name = cmd.get_name().to_string();
        clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
        std::process::exit(0);
    }

    let scopes = args.get_one::<String>("scopes").unwrap().clone();
    let config = ConfigInner {
        log_level: *args.get_one("log").unwrap_or(&tracing::Level::INFO),
        redirect_uri: args.get_one::<Uri>("redirect-uri").unwrap().clone(),
        discovery_endpoint: args.get_one::<Uri>("discovery-endpoint").unwrap().clone(),
        client_id: args.get_one::<String>("client-id").unwrap().clone(),
        token_scopes: args
            .get_many::<String>("scope")
            .map(|scopes| scopes.map(Clone::clone).collect())
            .unwrap_or(vec![scopes]),
        login_hint: args.get_one::<String>("login-hint").cloned(),
        login_prompt: args.get_one::<String>("login-prompt").cloned(),
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
