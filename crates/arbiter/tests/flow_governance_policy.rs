use converge_core::{
    AuthorityLevel, FlowAction, FlowGateContext, FlowGateInput, FlowGateOutcome, FlowGatePrincipal,
    FlowGateResource, FlowPhase,
};
use converge_pack::{DomainId, GateId, PolicyVersionId, PrincipalId, ResourceId, ResourceKind};
use arbiter::{FLOW_GOVERNANCE_POLICY, FlowGateAuthorizer, PolicyEngine};

fn engine() -> PolicyEngine {
    PolicyEngine::from_policy_str(FLOW_GOVERNANCE_POLICY)
        .expect("flow governance policy should parse")
}

fn input(
    domain: &str,
    kind: &str,
    authority: &str,
    human_approval_present: bool,
    gates_passed: Vec<&str>,
    required_gates_met: bool,
    amount: Option<i64>,
) -> FlowGateInput {
    FlowGateInput {
        principal: FlowGatePrincipal {
            id: PrincipalId::new(format!("agent:{domain}:{authority}")),
            authority: authority_level(authority),
            domains: vec![DomainId::new(domain)],
            policy_version: Some(PolicyVersionId::new("flow_governance_v1")),
        },
        resource: FlowGateResource {
            id: ResourceId::new(format!("{kind}:001")),
            kind: ResourceKind::new(kind),
            phase: FlowPhase::Commitment,
            gates_passed: gates_passed.into_iter().map(GateId::new).collect(),
        },
        action: FlowAction::Commit,
        context: FlowGateContext {
            commitment_type: Some(kind.into()),
            amount,
            human_approval_present: Some(human_approval_present),
            required_gates_met: Some(required_gates_met),
        },
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

#[test]
fn supervisory_sales_quote_commit_without_approval_escalates() {
    let decision = engine()
        .decide(&input(
            "sales",
            "quote",
            "supervisory",
            false,
            vec![],
            true,
            Some(50_000),
        ))
        .expect("quote policy should evaluate");

    assert_eq!(decision.outcome, FlowGateOutcome::Escalate);
}

#[test]
fn supervisory_procurement_spend_commit_with_approval_promotes() {
    let decision = engine()
        .decide(&input(
            "procurement",
            "spend",
            "supervisory",
            true,
            vec!["vendor_due_diligence", "competitive_review"],
            true,
            Some(15_000),
        ))
        .expect("spend policy should evaluate");

    assert_eq!(decision.outcome, FlowGateOutcome::Promote);
}

#[test]
fn supervisory_legal_contract_commit_without_approval_escalates() {
    let decision = engine()
        .decide(&input(
            "legal",
            "contract",
            "supervisory",
            false,
            vec!["legal_review", "counterparty_signed"],
            true,
            None,
        ))
        .expect("contract policy should evaluate");

    assert_eq!(decision.outcome, FlowGateOutcome::Escalate);
}

#[test]
fn supervisory_finance_invoice_commit_with_approval_promotes() {
    let decision = engine()
        .decide(&input(
            "finance",
            "invoice",
            "supervisory",
            true,
            vec!["customer_validated", "line_items_balanced"],
            true,
            Some(12_500),
        ))
        .expect("invoice policy should evaluate");

    assert_eq!(decision.outcome, FlowGateOutcome::Promote);
}

#[test]
fn invoice_commit_missing_balanced_line_items_rejects() {
    let decision = engine()
        .decide(&input(
            "finance",
            "invoice",
            "supervisory",
            true,
            vec!["customer_validated"],
            true,
            Some(12_500),
        ))
        .expect("invoice policy should evaluate");

    assert_eq!(decision.outcome, FlowGateOutcome::Reject);
}
