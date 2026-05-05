use ed25519_dalek::SigningKey;

use converge_core::{AuthorityLevel, FlowAction, FlowPhase};
use converge_pack::{DomainId, GateId, ResourceKind};
use arbiter::{ContextIn, DecideRequest, PolicyEngine, PrincipalIn, ResourceIn};

#[allow(dead_code)]
pub fn test_engine() -> PolicyEngine {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policies/policy.cedar");
    let policy = std::fs::read_to_string(path).expect("policy file should exist");
    PolicyEngine::from_policy_str(&policy).expect("policy should parse")
}

pub fn make_request(authority: &str, action: &str) -> DecideRequest {
    DecideRequest {
        principal: PrincipalIn {
            id: "agent:test".into(),
            authority: authority_level(authority),
            domains: vec![DomainId::new("test")],
            policy_version: None,
        },
        resource: ResourceIn {
            id: "flow:test-001".into(),
            resource_type: Some(ResourceKind::new("quote")),
            phase: Some(FlowPhase::Convergence),
            gates_passed: Some(vec![GateId::new("evidence")]),
        },
        action: flow_action(action),
        context: Some(ContextIn {
            commitment_type: Some("quote".into()),
            amount: Some(5_000),
            human_approval_present: Some(false),
            required_gates_met: Some(true),
        }),
        delegation_b64: None,
    }
}

fn authority_level(authority: &str) -> AuthorityLevel {
    match authority {
        "advisory" => AuthorityLevel::Advisory,
        "supervisory" => AuthorityLevel::Supervisory,
        "participatory" => AuthorityLevel::Participatory,
        "sovereign" => AuthorityLevel::Sovereign,
        _ => panic!("unsupported test authority: {authority}"),
    }
}

fn flow_action(action: &str) -> FlowAction {
    match action {
        "propose" => FlowAction::Propose,
        "validate" => FlowAction::Validate,
        "promote" => FlowAction::Promote,
        "commit" => FlowAction::Commit,
        "advance_phase" => FlowAction::AdvancePhase,
        _ => panic!("unsupported test action: {action}"),
    }
}

#[allow(dead_code)]
pub fn fixed_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}
