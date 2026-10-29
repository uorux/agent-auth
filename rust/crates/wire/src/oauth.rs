//! The OAuth server for web UIs and remote MCP (surfaces spec §C): dynamic
//! client registration (RFC 7591), tokens, errors, discovery documents, and
//! the operator's connector listing.
//!
//! Registration is open to anyone, so it is parsed defensively, but RFC 7591
//! says unknown client metadata is ignored, so unlike the agent API it does
//! not refuse unknown fields.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use crate::literal::Bearer;
use crate::secret::WireSecret;

/// At most this many redirect URIs per client, each at most this long.
pub const MAX_REDIRECT_URIS: usize = 16;
pub const MAX_REDIRECT_URI_LEN: usize = 2048;

/// How a client authenticates at the token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenAuthMethod {
    /// A public client (PKCE only).
    #[default]
    None,
    ClientSecretPost,
    ClientSecretBasic,
}

/// `POST /oauth/register`, structurally checked. Whether each redirect URI
/// is `https` to an allowed host is the broker's check (its configuration).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRegistration {
    pub redirect_uris: Vec<String>,
    pub token_endpoint_auth_method: TokenAuthMethod,
    /// At most 200 characters.
    pub client_name: Option<String>,
}

impl ClientRegistration {
    /// Parse a registration body, answering refusals as RFC 7591 errors with
    /// the Python's descriptions.
    pub fn from_json(body: &[u8]) -> Result<Self, OAuthError> {
        let value: Value = serde_json::from_slice(body)
            .map_err(|_| OAuthError::new(OAuthErrorCode::InvalidClientMetadata, "a JSON body"))?;
        let Value::Object(map) = value else {
            return Err(OAuthError::new(
                OAuthErrorCode::InvalidClientMetadata,
                "a JSON object",
            ));
        };
        let uris_err = || {
            OAuthError::new(
                OAuthErrorCode::InvalidRedirectUri,
                "redirect_uris: a list of URLs",
            )
        };
        let redirect_uris = match map.get("redirect_uris") {
            Some(Value::Array(items)) if !items.is_empty() && items.len() <= MAX_REDIRECT_URIS => {
                items
                    .iter()
                    .map(|v| match v {
                        Value::String(s) if s.len() <= MAX_REDIRECT_URI_LEN => Ok(s.clone()),
                        _ => Err(uris_err()),
                    })
                    .collect::<Result<Vec<_>, _>>()?
            }
            _ => return Err(uris_err()),
        };
        let token_endpoint_auth_method = match map.get("token_endpoint_auth_method") {
            None | Some(Value::Null) => TokenAuthMethod::None,
            Some(v) => serde_json::from_value::<TokenAuthMethod>(v.clone()).map_err(|_| {
                let shown = match v {
                    Value::String(s) => s.chars().take(64).collect::<String>(),
                    other => other.to_string().chars().take(64).collect(),
                };
                OAuthError::new(
                    OAuthErrorCode::InvalidClientMetadata,
                    format!("token_endpoint_auth_method '{shown}' is not supported"),
                )
            })?,
        };
        let client_name = match map.get("client_name") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.chars().take(200).collect()),
            Some(other) => Some(other.to_string().chars().take(200).collect()),
        };
        Ok(ClientRegistration {
            redirect_uris,
            token_endpoint_auth_method,
            client_name,
        })
    }
}

/// `POST /oauth/register` → 201.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientRegistered {
    pub client_id: String,
    /// Unix seconds.
    pub client_id_issued_at: i64,
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub token_endpoint_auth_method: TokenAuthMethod,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<WireSecret<256>>,
    /// `0` (never) when a secret was issued.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret_expires_at: Option<i64>,
}

/// `POST /oauth/token` → 200.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: WireSecret<256>,
    pub token_type: Bearer,
    pub expires_in: u64,
    pub refresh_token: WireSecret<256>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthErrorCode {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
    InvalidClientMetadata,
    InvalidRedirectUri,
    AccessDenied,
}

/// An OAuth error body (400, or 401 for client authentication).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthError {
    pub error: OAuthErrorCode,
    pub error_description: String,
}

impl OAuthError {
    #[must_use]
    pub fn new(error: OAuthErrorCode, description: impl Into<String>) -> Self {
        OAuthError {
            error,
            error_description: description.into(),
        }
    }
}

/// `GET /.well-known/oauth-protected-resource[/mcp]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    pub bearer_methods_supported: Vec<String>,
    pub resource_name: String,
}

/// `GET /.well-known/oauth-authorization-server`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub registration_endpoint: String,
    pub revocation_endpoint: String,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<TokenAuthMethod>,
    pub revocation_endpoint_auth_methods_supported: Vec<TokenAuthMethod>,
    pub authorization_response_iss_parameter_supported: bool,
    pub scopes_supported: Vec<String>,
}

impl AuthorizationServerMetadata {
    /// The broker's document for `base` (no trailing `/`).
    #[must_use]
    pub fn for_base(base: &str) -> Self {
        let all = vec![
            TokenAuthMethod::None,
            TokenAuthMethod::ClientSecretPost,
            TokenAuthMethod::ClientSecretBasic,
        ];
        AuthorizationServerMetadata {
            issuer: base.to_owned(),
            authorization_endpoint: format!("{base}/oauth/authorize"),
            token_endpoint: format!("{base}/oauth/token"),
            registration_endpoint: format!("{base}/oauth/register"),
            revocation_endpoint: format!("{base}/oauth/revoke"),
            response_types_supported: vec!["code".to_owned()],
            grant_types_supported: vec![
                "authorization_code".to_owned(),
                "refresh_token".to_owned(),
            ],
            code_challenge_methods_supported: vec!["S256".to_owned()],
            token_endpoint_auth_methods_supported: all.clone(),
            revocation_endpoint_auth_methods_supported: all,
            authorization_response_iss_parameter_supported: true,
            scopes_supported: Vec::new(),
        }
    }
}

/// `GET /admin/connectors` items.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorOut {
    pub client_id: String,
    pub name: Option<String>,
    pub redirect_uris: Vec<String>,
    /// The bound web agent's name.
    pub agent: Option<String>,
    #[serde(with = "crate::timestamp")]
    pub created_at: OffsetDateTime,
    #[serde(default, with = "crate::timestamp::option")]
    pub last_used_at: Option<OffsetDateTime>,
    #[serde(default, with = "crate::timestamp::option")]
    pub revoked_at: Option<OffsetDateTime>,
    pub live_authorizations: u32,
}

/// `POST /admin/connectors/{id}/revoke` → 200.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorRevoked {
    pub revoked: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(body: &str) -> Result<ClientRegistration, OAuthError> {
        ClientRegistration::from_json(body.as_bytes())
    }

    #[test]
    fn registration() {
        let ok = reg(
            r#"{"redirect_uris": ["https://claude.ai/cb"], "client_name": "Claude",
                         "software_id": "ignored"}"#,
        )
        .unwrap();
        assert_eq!(ok.redirect_uris, ["https://claude.ai/cb"]);
        assert_eq!(ok.token_endpoint_auth_method, TokenAuthMethod::None);
        assert_eq!(ok.client_name.as_deref(), Some("Claude"));

        let err = |b: &str| reg(b).unwrap_err();
        assert_eq!(err("nope").error_description, "a JSON body");
        assert_eq!(err("[]").error_description, "a JSON object");
        assert_eq!(err("{}").error, OAuthErrorCode::InvalidRedirectUri);
        assert_eq!(
            err(r#"{"redirect_uris": []}"#).error_description,
            "redirect_uris: a list of URLs"
        );
        assert_eq!(
            err(r#"{"redirect_uris": [1]}"#).error_description,
            "redirect_uris: a list of URLs"
        );
        assert_eq!(
            err(r#"{"redirect_uris": ["https://x"], "token_endpoint_auth_method": "private_key_jwt"}"#)
                .error_description,
            "token_endpoint_auth_method 'private_key_jwt' is not supported"
        );
        let long = format!(
            r#"{{"redirect_uris": ["https://x"], "client_name": "{}"}}"#,
            "n".repeat(300)
        );
        assert_eq!(reg(&long).unwrap().client_name.unwrap().len(), 200);
    }

    #[test]
    fn errors_serialize_as_rfc() {
        let e = OAuthError::new(OAuthErrorCode::InvalidGrant, "this code was already used");
        assert_eq!(
            serde_json::to_value(&e).unwrap(),
            serde_json::json!({"error": "invalid_grant", "error_description": "this code was already used"})
        );
    }
}
