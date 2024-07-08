use std::collections::HashSet;

use anyhow::{anyhow, Result};
use base64::prelude::*;
use hyper::Uri;
use rand::Rng;
use serde::Deserialize;
use serde_urlencoded as urlencoded;
use sha2::{Digest, Sha256};

#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

#[derive(Deserialize, Debug)]
#[allow(unused)]
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

pub struct AuthCodeResponse {
    pub code: String,
    #[allow(unused)]
    pub state: String,
}

pub fn auth_code_response<'a>(uri: &'a Uri, flow_state: &str) -> Result<AuthCodeResponse> {
    let query = uri.query().expect("no query component in the request URI");
    let query = urlencoded::from_str::<Vec<(&str, &str)>>(query)?;
    let code = query
        .iter()
        .find(|i| i.0 == "code")
        .map(|i| i.1.to_string());
    let state = query
        .iter()
        .find(|i| i.0 == "state")
        .map(|i| i.1.to_string());
    match (code, state) {
        (Some(code), Some(state)) => {
            if state != flow_state {
                return Err(anyhow::anyhow!(
                    "state doesnt match: expected={}, actual={}",
                    state,
                    flow_state
                ));
            }
            Ok(AuthCodeResponse { code, state })
        }
        (None, _) => Err(anyhow::anyhow!("no auth code")),
        (Some(_), None) => Err(anyhow::anyhow!("no state")),
    }
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
    let response = reqwest::get(discovery_uri).await?;
    let endpoints = response.json::<OidcConfiguration>().await?;
    Ok(endpoints)
}

pub enum AuthResponseType {
    Code,
}

impl Into<String> for AuthResponseType {
    fn into(self) -> String {
        match self {
            Self::Code => "code".into(),
        }
    }
}

impl Default for AuthResponseType {
    fn default() -> Self {
        Self::Code
    }
}

enum GranType {
    AuthorizationCode,
}

impl Default for GranType {
    fn default() -> Self {
        GranType::AuthorizationCode
    }
}

impl Into<String> for GranType {
    fn into(self) -> String {
        match self {
            Self::AuthorizationCode => "authorization_code".into(),
        }
    }
}
/// https://login.microsoftonline.com/505cca53-5750-4134-9501-8d52d5df3cd1/oauth2/v2.0/authorize?response_type=code&code_challenge=xH59Ixp_8ctglP5C_6Aj9RaP-vU6MFJnN9KJnNDaByA&code_challenge_method=S256&client_id=39e5e7ed-4928-4f27-9751-2591fa6df86c&redirect_uri=http%3A%2F%2Flocalhost%3A4956%2Flogin&scope=openid+profile&state=1719290469650
#[derive(Default)]
pub struct TokenRequestParams {
    grant_type: GranType,
    code: String,
    redirect_uri: Option<String>,
    scopes: HashSet<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
}

impl TokenRequestParams {
    pub fn for_auth_code<T: Into<String>>(code: T) -> Self {
        Self {
            grant_type: GranType::AuthorizationCode,
            code: code.into(),
            ..Default::default()
        }
    }

    pub fn redirect_uri<T: Into<String>>(mut self, uri: T) -> Self {
        self.redirect_uri = Some(uri.into());
        self
    }

    pub fn scope<T: Into<String>>(mut self, scope: T) -> Self {
        self.scopes.insert(scope.into());
        self
    }

    pub fn client_id<T: Into<String>>(mut self, id: T) -> Self {
        self.client_id = Some(id.into());
        self
    }

    pub fn code_verifier<T: Into<String>>(mut self, code_verifier: T) -> Self {
        self.code_verifier = Some(code_verifier.into());
        self
    }

    pub fn build(self) -> Result<String> {
        let grant_type: String = self.grant_type.into();
        let scopes = self.scopes.clone().into_iter().collect::<Vec<_>>();
        let scopes: String = scopes.join(" ");
        let redirect_uri = self.redirect_uri.ok_or(anyhow!("no redirect_uri"))?;
        let client_id = self.client_id.ok_or(anyhow!("no client_id"))?;
        let code_verifier = self.code_verifier.ok_or(anyhow!("no code_verifier"))?;
        let query = vec![
            ("grant_type", grant_type.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("code", self.code.as_str()),
            ("scope", scopes.as_str()),
            ("client_id", client_id.as_str()),
            ("code_verifier", code_verifier.as_str()),
        ];
        let params = urlencoded::to_string(query)?;
        Ok(params)
    }
}

/// https://login.microsoftonline.com/505cca53-5750-4134-9501-8d52d5df3cd1/oauth2/v2.0/authorize?response_type=code&code_challenge=xH59Ixp_8ctglP5C_6Aj9RaP-vU6MFJnN9KJnNDaByA&code_challenge_method=S256&client_id=39e5e7ed-4928-4f27-9751-2591fa6df86c&redirect_uri=http%3A%2F%2Flocalhost%3A4956%2Flogin&scope=openid+profile&state=1719290469650
#[derive(Default)]
pub struct AuthUri {
    response_type: AuthResponseType,
    endpoint: String,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    scopes: HashSet<String>,
    state: Option<String>,
    login_hint: Option<String>,
    prompt: Option<String>,
}

impl AuthUri {
    pub fn for_code_flow<T: Into<String>>(auth_endpoint: T) -> Self {
        Self {
            response_type: AuthResponseType::Code,
            endpoint: auth_endpoint.into(),
            ..Self::default()
        }
    }

    pub fn code_challenge<C: Into<String>, M: Into<String>>(
        mut self,
        challenge: C,
        method: M,
    ) -> Self {
        self.code_challenge = Some(challenge.into());
        self.code_challenge_method = Some(method.into());
        self
    }

    pub fn client_id<T: Into<String>>(mut self, id: T) -> Self {
        self.client_id = Some(id.into());
        self
    }

    pub fn redirect_uri<T: Into<String>>(mut self, uri: T) -> Self {
        self.redirect_uri = Some(uri.into());
        self
    }

    pub fn scope<T: Into<String>>(mut self, scope: T) -> Self {
        self.scopes.insert(scope.into());
        self
    }

    pub fn state<T: Into<String>>(mut self, state: T) -> Self {
        self.state = Some(state.into());
        self
    }

    pub fn login_hint<T: Into<String>>(mut self, hint: Option<T>) -> Self {
        self.login_hint = hint.map(Into::into);
        self
    }

    pub fn prompt<T: Into<String>>(mut self, prompt: Option<T>) -> Self {
        self.prompt = prompt.map(Into::into);
        self
    }

    pub fn build(self) -> Result<String> {
        let response_type: String = self.response_type.into();
        let code_challenge = self.code_challenge.ok_or(anyhow!("no code_challenge"))?;
        let code_challenge_method = self
            .code_challenge_method
            .ok_or(anyhow!("no code_challenge_method"))?;
        let client_id = self.client_id.ok_or(anyhow!("no client_id"))?;
        let redirect_uri = self.redirect_uri.ok_or(anyhow!("no redirect_uri"))?;
        let state = self.state.ok_or(anyhow!("no state"))?;
        let scopes = self.scopes.clone().into_iter().collect::<Vec<_>>();
        let scopes: String = scopes.join(" ");
        let mut query = vec![
            ("response_type", response_type.as_str()),
            ("code_challenge", code_challenge.as_str()),
            ("code_challenge_method", code_challenge_method.as_str()),
            ("client_id", client_id.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("scope", scopes.as_str()),
            ("state", state.as_str()),
        ];
        if let Some(hint) = self.login_hint.as_ref() {
            query.push(("login_hint", hint))
        }
        if let Some(prompt) = self.prompt.as_ref() {
            query.push(("prompt", prompt))
        }
        let query_string = urlencoded::to_string(query).unwrap();
        let auth_endpoint = &self.endpoint;
        let uri = format!("{auth_endpoint}?{query_string}");
        Ok(uri)
    }
}
