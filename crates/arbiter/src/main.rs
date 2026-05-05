//! arbiter HTTP server
//!
//! Thin Axum shell over the policy engine library.
//! Endpoints:
//!   POST /decide           — policy or delegation decision
//!   POST /issue-delegation — issue a scoped authority token
//!   GET  /pubkey           — Ed25519 public key for delegation verification

use arbiter::{
    PolicyEngine,
    decision::{DecisionMode, PolicyDecision, PolicyOutcome},
    delegation,
    types::DecideRequest,
};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Serialize;
use std::{fs, net::SocketAddr, path::PathBuf, sync::Arc};
use thiserror::Error;
use tracing::info;
use tracing_subscriber::FmtSubscriber;

#[derive(Debug, Error)]
enum ServerError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("config: {0}")]
    Config(String),
    #[error("policy: {0}")]
    Policy(String),
    #[error("delegation: {0}")]
    Delegation(String),
    #[error("engine: {0}")]
    Engine(String),
    #[error("server: {0}")]
    #[allow(dead_code)]
    Server(String),
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let status = match &self {
            ServerError::Unauthorized => StatusCode::UNAUTHORIZED,
            ServerError::Forbidden(_) => StatusCode::FORBIDDEN,
            ServerError::NotFound(_) => StatusCode::NOT_FOUND,
            ServerError::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ServerError::Delegation(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = Json(serde_json::json!({ "error": self.to_string() }));
        (status, body).into_response()
    }
}

// -------------------- HTTP response types --------------------

#[derive(Debug, Serialize)]
struct DecideResp {
    outcome: PolicyOutcome,
    reason: Option<String>,
    mode: DecisionMode,
}

impl From<PolicyDecision> for DecideResp {
    fn from(d: PolicyDecision) -> Self {
        Self {
            outcome: d.outcome,
            reason: d.reason,
            mode: d.mode,
        }
    }
}

#[derive(Debug, Serialize)]
struct PubKeyResp {
    pubkey_b64: String,
}

#[derive(Debug, Clone)]
struct ServerConfig {
    bind: SocketAddr,
    policy_path: PathBuf,
    issue_delegation_enabled: bool,
    issue_admin_token: Option<String>,
    signing_key_b64: Option<String>,
}

impl ServerConfig {
    fn from_env() -> Result<Self, ServerError> {
        let bind = std::env::var("POLICY_BIND")
            .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
            .parse()
            .map_err(|err| ServerError::Server(format!("invalid POLICY_BIND: {err}")))?;

        let policy_path = std::env::var("POLICY_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("policies/policy.cedar"));

        let issue_delegation_enabled = std::env::var("POLICY_ENABLE_DELEGATION_ISSUANCE")
            .map(|value| {
                matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes"
                )
            })
            .unwrap_or(false);

        let issue_admin_token = std::env::var("POLICY_ISSUE_ADMIN_TOKEN")
            .ok()
            .map(|token| token.trim().to_string())
            .filter(|token| !token.is_empty());

        let signing_key_b64 = std::env::var("POLICY_SIGNING_KEY_B64")
            .ok()
            .map(|key| key.trim().to_string())
            .filter(|key| !key.is_empty());

        Ok(Self {
            bind,
            policy_path,
            issue_delegation_enabled,
            issue_admin_token,
            signing_key_b64,
        })
    }
}

// -------------------- App State --------------------

#[derive(Clone)]
struct AppState {
    engine: Arc<PolicyEngine>,
    signing_key: Option<Arc<SigningKey>>,
    verifying_key: Option<Arc<VerifyingKey>>,
    issue_delegation_enabled: bool,
    issue_admin_token: Option<String>,
}

impl AppState {
    fn from_config(config: &ServerConfig, engine: PolicyEngine) -> Result<Self, ServerError> {
        let signing_key = config
            .signing_key_b64
            .as_ref()
            .map(|value| load_signing_key(value))
            .transpose()?;
        let verifying_key = signing_key.as_ref().map(SigningKey::verifying_key);

        Ok(Self {
            engine: Arc::new(engine),
            signing_key: signing_key.map(Arc::new),
            verifying_key: verifying_key.map(Arc::new),
            issue_delegation_enabled: config.issue_delegation_enabled,
            issue_admin_token: config.issue_admin_token.clone(),
        })
    }
}

fn load_signing_key(encoded: &str) -> Result<SigningKey, ServerError> {
    let raw = general_purpose::STANDARD_NO_PAD
        .decode(encoded)
        .or_else(|_| general_purpose::STANDARD.decode(encoded))
        .map_err(|err| ServerError::Config(format!("invalid POLICY_SIGNING_KEY_B64: {err}")))?;

    let bytes: [u8; 32] = raw.try_into().map_err(|_| {
        ServerError::Config("POLICY_SIGNING_KEY_B64 must decode to 32 bytes".into())
    })?;

    Ok(SigningKey::from_bytes(&bytes))
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
        })
}

fn require_issue_admin(headers: &HeaderMap, state: &AppState) -> Result<(), ServerError> {
    if !state.issue_delegation_enabled {
        return Err(ServerError::NotFound(
            "delegation issuance is not enabled".to_string(),
        ));
    }

    let expected = state.issue_admin_token.as_deref().ok_or_else(|| {
        ServerError::Forbidden("delegation issuance is not configured".to_string())
    })?;

    let provided = extract_bearer_token(headers).ok_or(ServerError::Unauthorized)?;

    if provided != expected {
        return Err(ServerError::Unauthorized);
    }

    Ok(())
}

fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/decide", post(decide))
        .route("/issue-delegation", post(issue_delegation))
        .route("/pubkey", get(pubkey))
        .with_state(state)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = FmtSubscriber::new();
    if let Err(err) = tracing::subscriber::set_global_default(subscriber) {
        eprintln!("logging already initialized: {err}");
    }

    let config = ServerConfig::from_env()?;
    let policy_text = fs::read_to_string(&config.policy_path)?;
    let engine = PolicyEngine::from_policy_str(&policy_text)
        .map_err(|err| ServerError::Policy(err.to_string()))?;

    let state = AppState::from_config(&config, engine)?;
    let app = build_app(state.clone());

    info!(
        addr = %config.bind,
        delegation_verify_enabled = state.verifying_key.is_some(),
        delegation_issue_enabled = state.issue_delegation_enabled
            && state.issue_admin_token.is_some()
            && state.signing_key.is_some(),
        "arbiter listening"
    );
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// -------------------- Endpoints --------------------

async fn decide(
    State(state): State<AppState>,
    Json(input): Json<DecideRequest>,
) -> Result<Json<DecideResp>, ServerError> {
    let decision = if let Some(del_b64) = input.delegation_b64.as_ref() {
        let (outcome, reason) = match state.verifying_key.as_deref() {
            Some(verifying_key) => match delegation::verify(del_b64, verifying_key, &input) {
                Ok(true) => (PolicyOutcome::Promote, None),
                Ok(false) => (
                    PolicyOutcome::Reject,
                    Some("delegation check failed".into()),
                ),
                Err(reason) => (PolicyOutcome::Reject, Some(reason)),
            },
            None => (
                PolicyOutcome::Reject,
                Some("delegation verification is not configured".into()),
            ),
        };
        PolicyDecision::delegation(
            outcome,
            reason,
            input.principal.id.clone(),
            input.action,
            input.resource.id.clone(),
        )
    } else {
        // Cedar policy path
        state
            .engine
            .evaluate(&input)
            .map_err(|err| ServerError::Engine(err.to_string()))?
    };

    Ok(Json(decision.into()))
}

async fn issue_delegation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<delegation::IssueDelegationReq>,
) -> Result<Json<delegation::IssueDelegationResp>, ServerError> {
    require_issue_admin(&headers, &state)?;

    let signing_key = state.signing_key.as_deref().ok_or_else(|| {
        ServerError::Forbidden("delegation signing is not configured".to_string())
    })?;

    let resp = delegation::issue(signing_key, req).map_err(ServerError::Delegation)?;
    Ok(Json(resp))
}

async fn pubkey(State(state): State<AppState>) -> Result<Json<PubKeyResp>, ServerError> {
    let verifying_key = state.verifying_key.as_deref().ok_or_else(|| {
        ServerError::NotFound("delegation verification is not configured".to_string())
    })?;
    let pub_b64 = general_purpose::STANDARD_NO_PAD.encode(verifying_key.to_bytes());
    Ok(Json(PubKeyResp {
        pubkey_b64: pub_b64,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    fn test_engine() -> PolicyEngine {
        let policy = std::fs::read_to_string("policies/policy.cedar")
            .expect("policy file should exist in test working dir");
        PolicyEngine::from_policy_str(&policy).expect("policy should parse")
    }

    fn test_state(issue_enabled: bool) -> AppState {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();

        AppState {
            engine: Arc::new(test_engine()),
            signing_key: Some(Arc::new(signing_key)),
            verifying_key: Some(Arc::new(verifying_key)),
            issue_delegation_enabled: issue_enabled,
            issue_admin_token: Some("top-secret".to_string()),
        }
    }

    #[tokio::test]
    async fn issue_delegation_requires_admin_bearer() {
        let app = build_app(test_state(true));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/issue-delegation")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{
                            "sub":"agent:ops",
                            "issuer":"human:ceo",
                            "delegated_authority":"supervisory",
                            "actions":["commit"],
                            "resource_pattern":"flow:vendor-*",
                            "max_amount":5000,
                            "nbf_epoch":1700000000,
                            "exp_epoch":4102444800,
                            "jti":"delegation-1"
                        }"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn issue_delegation_disabled_returns_not_found() {
        let app = build_app(test_state(false));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/issue-delegation")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer top-secret")
                    .body(Body::from(
                        r#"{
                            "sub":"agent:ops",
                            "issuer":"human:ceo",
                            "delegated_authority":"supervisory",
                            "actions":["commit"],
                            "resource_pattern":"flow:vendor-*",
                            "max_amount":5000,
                            "nbf_epoch":1700000000,
                            "exp_epoch":4102444800,
                            "jti":"delegation-1"
                        }"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn decide_rejects_delegation_when_verification_disabled() {
        let state = AppState {
            engine: Arc::new(test_engine()),
            signing_key: None,
            verifying_key: None,
            issue_delegation_enabled: false,
            issue_admin_token: None,
        };
        let app = build_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/decide")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{
                            "principal":{"id":"agent:ops","authority":"advisory","domains":["finance"]},
                            "resource":{"id":"flow:vendor-42","type":"quote","phase":"commitment"},
                            "action":"commit",
                            "context":{"commitment_type":"quote","amount":1000,"human_approval_present":false,"required_gates_met":true},
                            "delegation_b64":"bogus"
                        }"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
