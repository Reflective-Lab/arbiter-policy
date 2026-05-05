use std::path::PathBuf;

use arbiter::{FlowGateAuthorizer, PolicyEngine};
use converge_core::{
    AuthorityLevel, FlowAction, FlowGateContext, FlowGateInput, FlowGateOutcome, FlowGatePrincipal,
    FlowGateResource, FlowPhase,
};
use converge_pack::{DomainId, GateId, PolicyVersionId, ResourceKind};

fn vendor_engine() -> PolicyEngine {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policies/vendor_selection.cedar");
    let policy = std::fs::read_to_string(path).expect("vendor selection policy should exist");
    PolicyEngine::from_policy_str(&policy).expect("vendor selection policy should parse")
}

fn vendor_input(
    amount: i64,
    human_approval_present: bool,
    gates_passed: Vec<&str>,
) -> FlowGateInput {
    FlowGateInput {
        principal: FlowGatePrincipal {
            id: "agent:procurement".into(),
            authority: AuthorityLevel::Supervisory,
            domains: vec![DomainId::new("procurement")],
            policy_version: Some(PolicyVersionId::new("vendor_v1")),
        },
        resource: FlowGateResource {
            id: "vendor-selection:001".into(),
            kind: ResourceKind::new("spend"),
            phase: FlowPhase::Commitment,
            gates_passed: gates_passed.into_iter().map(GateId::new).collect(),
        },
        action: FlowAction::Commit,
        context: FlowGateContext {
            commitment_type: Some("spend".into()),
            amount: Some(amount),
            human_approval_present: Some(human_approval_present),
            required_gates_met: Some(true),
        },
    }
}

#[test]
fn supervisory_procurement_commit_without_approval_escalates() {
    let engine = vendor_engine();
    let input = vendor_input(
        15_000,
        false,
        vec!["vendor_due_diligence", "competitive_review"],
    );

    let decision = engine
        .decide(&input)
        .expect("policy evaluation should succeed");
    assert_eq!(decision.outcome, FlowGateOutcome::Escalate);
}

#[test]
fn supervisory_procurement_commit_with_approval_promotes() {
    let engine = vendor_engine();
    let input = vendor_input(
        15_000,
        true,
        vec!["vendor_due_diligence", "competitive_review"],
    );

    let decision = engine
        .decide(&input)
        .expect("policy evaluation should succeed");
    assert_eq!(decision.outcome, FlowGateOutcome::Promote);
}

#[test]
fn vendor_selection_requires_due_diligence_gate() {
    let engine = vendor_engine();
    let input = vendor_input(15_000, true, vec!["competitive_review"]);

    let decision = engine
        .decide(&input)
        .expect("policy evaluation should succeed");
    assert_eq!(decision.outcome, FlowGateOutcome::Reject);
}
