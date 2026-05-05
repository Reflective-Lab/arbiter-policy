//! Delegation tokens — scoped, time-limited authority grants.
//!
//! A supervisor or human issues a delegation to grant an agent
//! temporary elevated authority for specific actions on specific resources.
//! Tokens are CBOR-encoded, Ed25519-signed, and base64-transported.

use base64::{Engine as _, engine::general_purpose};
use ciborium::{de, ser};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::types::DecideRequest;
use converge_core::{AuthorityLevel, FlowAction};
use converge_pack::{ActorId, PrincipalId};

/// Scoped, time-limited authority delegation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delegation {
    /// Suggestor persona being granted authority
    pub sub: PrincipalId,
    /// Who delegated (supervisor persona or human identifier)
    pub issuer: ActorId,
    /// The authority level being granted
    pub delegated_authority: AuthorityLevel,
    /// Allowed actions (commit, promote, etc.)
    pub actions: Vec<FlowAction>,
    /// Resource scope pattern (e.g., `flow:quote-*`)
    pub resource_pattern: String,
    /// Optional spending cap
    pub max_amount: Option<i64>,
    /// Not-before (epoch seconds)
    pub nbf_epoch: i64,
    /// Expires (epoch seconds)
    pub exp_epoch: i64,
    /// Nonce for replay protection
    pub jti: String,
    /// Ed25519 signature over all fields except sig
    pub sig: Option<Vec<u8>>,
}

/// Request to issue a delegation token.
#[derive(Debug, Deserialize)]
pub struct IssueDelegationReq {
    pub sub: PrincipalId,
    pub issuer: ActorId,
    pub delegated_authority: AuthorityLevel,
    pub actions: Vec<FlowAction>,
    pub resource_pattern: String,
    pub max_amount: Option<i64>,
    pub nbf_epoch: i64,
    pub exp_epoch: i64,
    pub jti: String,
}

/// Response from issuing a delegation token.
#[derive(Debug, Serialize)]
pub struct IssueDelegationResp {
    pub delegation_b64: String,
    pub pubkey_b64: String,
}

fn sig_message(d: &Delegation) -> Result<Vec<u8>, String> {
    let mut to_sign = d.clone();
    to_sign.sig = None;
    let mut buf = Vec::new();
    ser::into_writer(&to_sign, &mut buf).map_err(|err| err.to_string())?;
    Ok(buf)
}

/// Issue a signed delegation token.
///
/// # Errors
///
/// Returns `Err` if CBOR serialization or signing fails.
pub fn issue(
    signing_key: &SigningKey,
    req: IssueDelegationReq,
) -> Result<IssueDelegationResp, String> {
    if req.sub.as_str().trim().is_empty() {
        return Err("delegation subject cannot be empty".to_string());
    }
    if req.issuer.as_str().trim().is_empty() {
        return Err("delegation issuer cannot be empty".to_string());
    }
    if req.actions.is_empty() {
        return Err("delegation must include at least one action".to_string());
    }
    if req.resource_pattern.trim().is_empty() {
        return Err("delegation resource_pattern cannot be empty".to_string());
    }
    if req.jti.trim().is_empty() {
        return Err("delegation jti cannot be empty".to_string());
    }
    if req.exp_epoch <= req.nbf_epoch {
        return Err("delegation exp_epoch must be later than nbf_epoch".to_string());
    }
    if let Some(max_amount) = req.max_amount {
        if max_amount < 0 {
            return Err("delegation max_amount cannot be negative".to_string());
        }
    }

    let mut del = Delegation {
        sub: req.sub,
        issuer: req.issuer,
        delegated_authority: req.delegated_authority,
        actions: req.actions,
        resource_pattern: req.resource_pattern,
        max_amount: req.max_amount,
        nbf_epoch: req.nbf_epoch,
        exp_epoch: req.exp_epoch,
        jti: req.jti,
        sig: None,
    };

    let msg = sig_message(&del)?;
    let sig: Signature = signing_key.sign(&msg);
    del.sig = Some(sig.to_bytes().to_vec());

    let mut buf = Vec::new();
    ser::into_writer(&del, &mut buf).map_err(|err| err.to_string())?;

    let verifying_key = signing_key.verifying_key();
    Ok(IssueDelegationResp {
        delegation_b64: general_purpose::STANDARD_NO_PAD.encode(&buf),
        pubkey_b64: general_purpose::STANDARD_NO_PAD.encode(verifying_key.to_bytes()),
    })
}

/// Verify a delegation token against the request.
///
/// Returns `Ok(true)` if the delegation is valid and covers the requested action,
/// `Ok(false)` if verification passes but constraints don't match,
/// `Err(reason)` if the token is malformed or signature fails.
///
/// # Errors
///
/// Returns `Err` if the token cannot be decoded, parsed, or the time source is invalid.
#[allow(clippy::cast_possible_wrap)]
pub fn verify(b64: &str, vkey: &VerifyingKey, req: &DecideRequest) -> Result<bool, String> {
    let raw = general_purpose::STANDARD_NO_PAD
        .decode(b64)
        .map_err(|err| format!("delegation decode failed: {err}"))?;
    let del: Delegation =
        de::from_reader(raw.as_slice()).map_err(|err| format!("delegation parse failed: {err}"))?;

    // Verify signature
    let msg = sig_message(&del)?;
    let sig_bytes = del
        .sig
        .clone()
        .ok_or_else(|| "delegation signature missing".to_string())?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|_| "delegation signature invalid".to_string())?;
    if vkey.verify_strict(&msg, &sig).is_err() {
        return Ok(false);
    }

    // Check time window
    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| format!("time source invalid: {err}"))?
        .as_secs() as i64;
    if now_epoch < del.nbf_epoch || now_epoch > del.exp_epoch {
        return Ok(false);
    }

    // Check subject matches principal
    if del.sub != req.principal.id {
        return Ok(false);
    }

    // Check action is allowed
    if !del.actions.contains(&req.action) {
        return Ok(false);
    }

    // Check resource matches pattern (prefix match; * is wildcard suffix)
    let pattern = del.resource_pattern.trim_end_matches('*');
    if !req.resource.id.starts_with(pattern) {
        return Ok(false);
    }

    // Check amount cap
    if let Some(max) = del.max_amount {
        if let Some(ref ctx) = req.context {
            if let Some(amount) = ctx.amount {
                if amount > max {
                    return Ok(false);
                }
            }
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use converge_core::FlowPhase;
    use converge_pack::ResourceKind;

    fn valid_req() -> IssueDelegationReq {
        IssueDelegationReq {
            sub: "agent:finance".into(),
            issuer: "human:cfo".into(),
            delegated_authority: AuthorityLevel::Supervisory,
            actions: vec![FlowAction::Commit],
            resource_pattern: "flow:quote-*".into(),
            max_amount: Some(50_000),
            nbf_epoch: 1_000_000,
            exp_epoch: 2_000_000,
            jti: "nonce-1".into(),
        }
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    #[test]
    fn issue_succeeds_with_valid_request() {
        let key = signing_key();
        let resp = issue(&key, valid_req());
        assert!(resp.is_ok());
        let resp = resp.unwrap();
        assert!(!resp.delegation_b64.is_empty());
        assert!(!resp.pubkey_b64.is_empty());
    }

    #[test]
    fn issue_rejects_empty_subject() {
        let key = signing_key();
        let mut req = valid_req();
        req.sub = "  ".into();
        let err = issue(&key, req).unwrap_err();
        assert!(err.contains("subject"));
    }

    #[test]
    fn issue_rejects_empty_issuer() {
        let key = signing_key();
        let mut req = valid_req();
        req.issuer = "".into();
        let err = issue(&key, req).unwrap_err();
        assert!(err.contains("issuer"));
    }

    #[test]
    fn issue_rejects_no_actions() {
        let key = signing_key();
        let mut req = valid_req();
        req.actions = vec![];
        let err = issue(&key, req).unwrap_err();
        assert!(err.contains("action"));
    }

    #[test]
    fn issue_rejects_empty_resource_pattern() {
        let key = signing_key();
        let mut req = valid_req();
        req.resource_pattern = "   ".into();
        let err = issue(&key, req).unwrap_err();
        assert!(err.contains("resource_pattern"));
    }

    #[test]
    fn issue_rejects_empty_jti() {
        let key = signing_key();
        let mut req = valid_req();
        req.jti = "".into();
        let err = issue(&key, req).unwrap_err();
        assert!(err.contains("jti"));
    }

    #[test]
    fn issue_rejects_exp_before_nbf() {
        let key = signing_key();
        let mut req = valid_req();
        req.exp_epoch = req.nbf_epoch;
        let err = issue(&key, req).unwrap_err();
        assert!(err.contains("exp_epoch"));
    }

    #[test]
    fn issue_rejects_negative_max_amount() {
        let key = signing_key();
        let mut req = valid_req();
        req.max_amount = Some(-1);
        let err = issue(&key, req).unwrap_err();
        assert!(err.contains("max_amount"));
    }

    #[test]
    fn verify_roundtrip_valid_token() {
        let key = signing_key();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let req = IssueDelegationReq {
            sub: "agent:finance".into(),
            issuer: "human:cfo".into(),
            delegated_authority: AuthorityLevel::Supervisory,
            actions: vec![FlowAction::Commit],
            resource_pattern: "flow:quote-*".into(),
            max_amount: Some(50_000),
            nbf_epoch: now - 100,
            exp_epoch: now + 3600,
            jti: "nonce-rt".into(),
        };

        let resp = issue(&key, req).unwrap();
        let vkey = key.verifying_key();

        let decide_req = DecideRequest {
            principal: crate::types::PrincipalIn {
                id: "agent:finance".into(),
                authority: AuthorityLevel::Supervisory,
                domains: vec!["finance".into()],
                policy_version: None,
            },
            resource: crate::types::ResourceIn {
                id: "flow:quote-2025-001".into(),
                resource_type: Some(ResourceKind::new("quote")),
                phase: Some(FlowPhase::Commitment),
                gates_passed: None,
            },
            action: FlowAction::Commit,
            context: Some(crate::types::ContextIn {
                commitment_type: Some("quote".into()),
                amount: Some(10_000),
                human_approval_present: Some(true),
                required_gates_met: Some(true),
            }),
            delegation_b64: None,
        };

        let result = verify(&resp.delegation_b64, &vkey, &decide_req).unwrap();
        assert!(result);
    }

    #[test]
    fn verify_rejects_wrong_principal() {
        let key = signing_key();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let req = IssueDelegationReq {
            sub: "agent:finance".into(),
            issuer: "human:cfo".into(),
            delegated_authority: AuthorityLevel::Supervisory,
            actions: vec![FlowAction::Commit],
            resource_pattern: "flow:*".into(),
            max_amount: None,
            nbf_epoch: now - 100,
            exp_epoch: now + 3600,
            jti: "nonce-wp".into(),
        };

        let resp = issue(&key, req).unwrap();
        let vkey = key.verifying_key();

        let decide_req = DecideRequest {
            principal: crate::types::PrincipalIn {
                id: "agent:other".into(),
                authority: AuthorityLevel::Advisory,
                domains: vec![],
                policy_version: None,
            },
            resource: crate::types::ResourceIn {
                id: "flow:x".into(),
                resource_type: None,
                phase: None,
                gates_passed: None,
            },
            action: FlowAction::Commit,
            context: None,
            delegation_b64: None,
        };

        let result = verify(&resp.delegation_b64, &vkey, &decide_req).unwrap();
        assert!(!result);
    }

    #[test]
    fn verify_rejects_amount_over_cap() {
        let key = signing_key();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let req = IssueDelegationReq {
            sub: "agent:finance".into(),
            issuer: "human:cfo".into(),
            delegated_authority: AuthorityLevel::Supervisory,
            actions: vec![FlowAction::Commit],
            resource_pattern: "flow:*".into(),
            max_amount: Some(1_000),
            nbf_epoch: now - 100,
            exp_epoch: now + 3600,
            jti: "nonce-cap".into(),
        };

        let resp = issue(&key, req).unwrap();
        let vkey = key.verifying_key();

        let decide_req = DecideRequest {
            principal: crate::types::PrincipalIn {
                id: "agent:finance".into(),
                authority: AuthorityLevel::Supervisory,
                domains: vec![],
                policy_version: None,
            },
            resource: crate::types::ResourceIn {
                id: "flow:x".into(),
                resource_type: None,
                phase: None,
                gates_passed: None,
            },
            action: FlowAction::Commit,
            context: Some(crate::types::ContextIn {
                commitment_type: None,
                amount: Some(5_000),
                human_approval_present: None,
                required_gates_met: None,
            }),
            delegation_b64: None,
        };

        let result = verify(&resp.delegation_b64, &vkey, &decide_req).unwrap();
        assert!(!result);
    }
}
