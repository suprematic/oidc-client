use anyhow::Result;
use base64::prelude::*;
use hyper::Uri;
use rand::Rng;
use serde::Deserialize;
use serde_urlencoded as urlencoded;
use sha2::{Digest, Sha256};

#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub struct OidcConfiguration {
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

pub fn auth_code<'a>(uri: &'a Uri) -> Result<Option<&'a str>> {
    let query = uri.query().expect("no query component in the request URI");
    let query = urlencoded::from_str::<Vec<(&str, &str)>>(query)?;
    let code = query.into_iter().find(|i| i.0 == "code").map(|i| i.1);
    Ok(code)
}

fn gen_code_verifier() -> String {
    let bytes = rand::thread_rng().gen::<u32>().to_ne_bytes();
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}

pub fn gen_code_challenge() -> (String, String) {
    let verifier = gen_code_verifier();
    let bytes = verifier.bytes().collect::<Vec<u8>>();
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let sha_bytes = hasher.finalize();
    let challenge = BASE64_URL_SAFE_NO_PAD.encode(sha_bytes);
    (challenge, verifier)
}

pub async fn discover_oidc_endpoints(discovery_uri: &str) -> Result<OidcConfiguration> {
    let endpoints = reqwest::get(discovery_uri)
        .await?
        .json::<OidcConfiguration>()
        .await?;
    debug!("OIDC endpoints: {endpoints:#?}");
    Ok(endpoints)
}
