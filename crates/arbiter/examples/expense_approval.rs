use std::path::PathBuf;

use arbiter::{ContextIn, DecideRequest, PolicyEngine, PrincipalIn, ResourceIn};
use converge_core::{AuthorityLevel, FlowAction, FlowPhase};
use converge_pack::{DomainId, GateId, PrincipalId, ResourceId, ResourceKind};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policies/expense_approval.cedar");
    let policy = std::fs::read_to_string(policy_path)?;
    let engine = PolicyEngine::from_policy_str(&policy)?;

    let scenarios = vec![
        (
            "finance supervisor validates expense with receipt",
            expense_request(
                "supervisory",
                vec!["finance"],
                "validate",
                2_500,
                false,
                vec!["receipt"],
            ),
        ),
        (
            "ops supervisor cannot validate finance expense",
            expense_request(
                "supervisory",
                vec!["operations"],
                "validate",
                2_500,
                false,
                vec!["receipt"],
            ),
        ),
        (
            "finance supervisor commit over threshold without approval escalates",
            expense_request(
                "supervisory",
                vec!["finance"],
                "commit",
                8_400,
                false,
                vec!["receipt", "manager_approval"],
            ),
        ),
        (
            "finance supervisor commit low-value reimbursement with approval promotes",
            expense_request(
                "supervisory",
                vec!["finance"],
                "commit",
                4_200,
                true,
                vec!["receipt", "manager_approval"],
            ),
        ),
        (
            "sovereign finance can commit fully gated expense",
            expense_request(
                "sovereign",
                vec!["finance"],
                "commit",
                18_000,
                true,
                vec!["receipt", "manager_approval"],
            ),
        ),
    ];

    for (name, request) in scenarios {
        let decision = engine.evaluate(&request)?;
        println!("{name}");
        println!("{}", serde_json::to_string_pretty(&request)?);
        println!("{}", serde_json::to_string_pretty(&decision)?);
        println!();
    }

    Ok(())
}

fn expense_request(
    authority: &str,
    domains: Vec<&str>,
    action: &str,
    amount: i64,
    human_approval_present: bool,
    gates_passed: Vec<&str>,
) -> DecideRequest {
    DecideRequest {
        principal: PrincipalIn {
            id: PrincipalId::new(format!("agent:{authority}")),
            authority: authority_level(authority),
            domains: domains.into_iter().map(DomainId::new).collect(),
            policy_version: Some("expense_v1".into()),
        },
        resource: ResourceIn {
            id: ResourceId::new(format!("expense:{action}-{amount}")),
            resource_type: Some(ResourceKind::new("expense")),
            phase: Some(FlowPhase::Commitment),
            gates_passed: Some(gates_passed.into_iter().map(GateId::new).collect()),
        },
        action: flow_action(action),
        context: Some(ContextIn {
            commitment_type: Some("expense".into()),
            amount: Some(amount),
            human_approval_present: Some(human_approval_present),
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
        _ => panic!("unsupported example authority: {authority}"),
    }
}

fn flow_action(action: &str) -> FlowAction {
    match action {
        "propose" => FlowAction::Propose,
        "validate" => FlowAction::Validate,
        "promote" => FlowAction::Promote,
        "commit" => FlowAction::Commit,
        "advance_phase" => FlowAction::AdvancePhase,
        _ => panic!("unsupported example action: {action}"),
    }
}
