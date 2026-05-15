#![cfg(feature = "analysis")]

use arbiter::{
    CedarAnalysisExecutionStatus, CedarAnalysisInput, CedarAnalysisQuery, EXPENSE_APPROVAL_POLICY,
    EXPENSE_APPROVAL_SCHEMA, execute_analysis_with_cvc5,
};

const INVARIANT_ID: &str = "expense.non_finance_commit.high_value";
const BROKEN_EXPENSE_POLICY_ALLOWS_CLAIM_SPACE: &str = r#"
permit(principal, action == Action::"commit", resource)
when {
  resource.resource_type == "expense" &&
  principal.domains.contains("finance") == false &&
  principal.authority == "supervisory" &&
  context.amount > 5000 &&
  context.human_approval_present == true &&
  resource.gates_passed.contains("receipt") &&
  resource.gates_passed.contains("manager_approval") &&
  context.required_gates_met == true
};
"#;

fn expense_input() -> CedarAnalysisInput {
    CedarAnalysisInput::new(
        INVARIANT_ID,
        CedarAnalysisQuery::ExpenseNonFinanceHighValueCommitDenied,
        EXPENSE_APPROVAL_POLICY,
        EXPENSE_APPROVAL_SCHEMA,
    )
}

fn broken_expense_input() -> CedarAnalysisInput {
    CedarAnalysisInput::new(
        format!("{INVARIANT_ID}.mutant"),
        CedarAnalysisQuery::ExpenseNonFinanceHighValueCommitDenied,
        BROKEN_EXPENSE_POLICY_ALLOWS_CLAIM_SPACE,
        EXPENSE_APPROVAL_SCHEMA,
    )
}

#[tokio::test]
#[ignore = "requires a local cvc5 binary; run only in scheduled/manual solver CI"]
async fn cvc5_smoke_proves_conditional_expense_claim_has_no_violation() {
    let report = execute_analysis_with_cvc5(&expense_input())
        .await
        .expect("CVC5-backed Cedar Analysis should produce a report");

    assert_eq!(report.plan.invariant_id, INVARIANT_ID);
    assert_eq!(
        report.plan.query,
        CedarAnalysisQuery::ExpenseNonFinanceHighValueCommitDenied
    );
    assert_eq!(report.execution_identity.backend, "cvc5");
    assert_eq!(
        report.execution_identity.producer.name,
        "converge-arbiter-policy"
    );
    assert_eq!(
        report
            .execution_identity
            .native_identity
            .as_ref()
            .map(|identity| identity.backend.as_str()),
        Some("CVC5")
    );
    assert!(report.plan.request_env_count() > 0);
    assert!(!report.checks.is_empty());
    assert!(
        report
            .checks
            .iter()
            .all(|check| check.status != CedarAnalysisExecutionStatus::Error),
        "CVC5 smoke should not produce solver/concretization errors: {report:#?}"
    );
    assert_eq!(report.status, CedarAnalysisExecutionStatus::NoViolation);
}

#[tokio::test]
#[ignore = "requires a local cvc5 binary; run only in scheduled/manual solver CI"]
async fn cvc5_smoke_finds_counterexample_for_broken_conditional_claim_policy() {
    let report = execute_analysis_with_cvc5(&broken_expense_input())
        .await
        .expect("CVC5-backed Cedar Analysis should produce a report for the mutant policy");

    assert_eq!(
        report.status,
        CedarAnalysisExecutionStatus::CounterexampleFound
    );
    assert_eq!(report.execution_identity.backend, "cvc5");
    assert!(
        report.checks.iter().any(|check| {
            check.status == CedarAnalysisExecutionStatus::CounterexampleFound
                && check
                    .counterexample
                    .as_ref()
                    .is_some_and(|counterexample| !counterexample.is_empty())
        }),
        "mutant policy should produce a concrete counterexample: {report:#?}"
    );
}
