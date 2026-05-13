use arbiter::{
    ContextIn, DecideRequest, EXPENSE_APPROVAL_POLICY, PolicyEngine, PolicyOutcome, PrincipalIn,
    ResourceIn,
};
use converge_core::{AuthorityLevel, FlowAction, FlowPhase};
use converge_pack::{DomainId, GateId, PolicyVersionId, ResourceKind};

const NON_FINANCE_COMMIT_INVARIANT: &str =
    include_str!("../invariants/expense_non_finance_commit.feature");

fn expense_engine() -> PolicyEngine {
    PolicyEngine::from_policy_str(EXPENSE_APPROVAL_POLICY)
        .expect("expense approval policy should parse")
}

fn high_value_non_finance_commit_request() -> DecideRequest {
    DecideRequest {
        principal: PrincipalIn {
            id: "agent:operations-supervisor".into(),
            authority: AuthorityLevel::Supervisory,
            domains: vec![DomainId::new("operations")],
            policy_version: Some(PolicyVersionId::new("expense_v1")),
        },
        resource: ResourceIn {
            id: "expense:high-value-001".into(),
            resource_type: Some(ResourceKind::new("expense")),
            phase: Some(FlowPhase::Commitment),
            gates_passed: Some(vec![
                GateId::new("receipt"),
                GateId::new("manager_approval"),
            ]),
        },
        action: FlowAction::Commit,
        context: Some(ContextIn {
            commitment_type: Some("expense".into()),
            amount: Some(8_400),
            human_approval_present: Some(true),
            required_gates_met: Some(true),
        }),
        delegation_b64: None,
    }
}

#[test]
fn invariant_fixture_records_non_finance_commit_boundary() {
    assert!(
        NON_FINANCE_COMMIT_INVARIANT
            .contains("Scenario: Non-finance cannot commit a high-value expense")
    );
    assert!(NON_FINANCE_COMMIT_INVARIANT.contains("Then Arbiter must reject the decision"));
}

#[test]
fn non_finance_cannot_commit_high_value_expense_even_with_approval() {
    let decision = expense_engine()
        .evaluate(&high_value_non_finance_commit_request())
        .expect("policy evaluation should succeed");

    assert_eq!(decision.outcome, PolicyOutcome::Reject);
}
