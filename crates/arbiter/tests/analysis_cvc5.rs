#![cfg(feature = "analysis")]

use arbiter::{
    CedarAnalysisExecutionStatus, CedarAnalysisInput, CedarAnalysisQuery, EXPENSE_APPROVAL_POLICY,
    EXPENSE_APPROVAL_SCHEMA, execute_analysis_with_cvc5,
};

const INVARIANT_ID: &str = "expense.non_finance_commit.high_value";

fn expense_input() -> CedarAnalysisInput {
    CedarAnalysisInput::new(
        INVARIANT_ID,
        CedarAnalysisQuery::ExpenseNonFinanceHighValueCommitDenied,
        EXPENSE_APPROVAL_POLICY,
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
