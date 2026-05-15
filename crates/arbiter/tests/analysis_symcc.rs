#![cfg(feature = "analysis")]

use arbiter::{
    CedarAnalysisError, CedarAnalysisExecutionStatus, CedarAnalysisInput, CedarAnalysisQuery,
    ContextIn, DecideRequest, EXPENSE_APPROVAL_POLICY, EXPENSE_APPROVAL_SCHEMA,
    EXPENSE_NON_FINANCE_HIGH_VALUE_COMMIT_CLAIM_POLICY, PolicyEngine, PolicyOutcome, PrincipalIn,
    ResourceIn, compile_analysis_plan, execute_analysis_with_solver,
};
use cedar_policy_symcc::solver::{Decision, DecisionWithModel, Solver, SolverError};
use converge_core::{AuthorityLevel, FlowAction, FlowPhase};
use converge_pack::{DomainId, GateId, PolicyVersionId, ResourceKind};
use proptest::prelude::*;
use tokio::io::{AsyncWrite, Sink};

const INVARIANT_ID: &str = "expense.non_finance_commit.high_value";
const SIMPLE_SCHEMA: &str = r"
    entity User;
    entity Thing;
    action View appliesTo {
        principal: [User],
        resource: [Thing]
    };
";
const PERMIT_ALL_POLICY: &str = r#"permit(principal, action == Action::"View", resource);"#;
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

#[derive(Debug, Clone)]
struct ExpenseClaimReviewCase {
    name: &'static str,
    authority: AuthorityLevel,
    domains: &'static [&'static str],
    resource_type: &'static str,
    action: FlowAction,
    amount: i64,
    human_approval_present: bool,
    gates_passed: &'static [&'static str],
    required_gates_met: bool,
    expected_claim_match: bool,
}

impl ExpenseClaimReviewCase {
    fn request(&self) -> DecideRequest {
        DecideRequest {
            principal: PrincipalIn {
                id: format!("agent:{}", self.name.replace('_', "-")).into(),
                authority: self.authority,
                domains: self.domains.iter().copied().map(DomainId::new).collect(),
                policy_version: Some(PolicyVersionId::new("expense_v1")),
            },
            resource: ResourceIn {
                id: format!("expense:{}", self.name.replace('_', "-")).into(),
                resource_type: Some(ResourceKind::new(self.resource_type)),
                phase: Some(FlowPhase::Commitment),
                gates_passed: Some(self.gates_passed.iter().copied().map(GateId::new).collect()),
            },
            action: self.action,
            context: Some(ContextIn {
                commitment_type: Some("expense".into()),
                amount: Some(self.amount),
                human_approval_present: Some(self.human_approval_present),
                required_gates_met: Some(self.required_gates_met),
            }),
            delegation_b64: None,
        }
    }
}

#[derive(Debug)]
struct FixedDecisionSolver {
    sink: Sink,
    decision: DecisionWithModel,
}

impl FixedDecisionSolver {
    fn unsat() -> Self {
        Self {
            sink: tokio::io::sink(),
            decision: DecisionWithModel::Unsat,
        }
    }

    fn unknown() -> Self {
        Self {
            sink: tokio::io::sink(),
            decision: DecisionWithModel::Unknown,
        }
    }
}

impl Solver for FixedDecisionSolver {
    fn smtlib_input(&mut self) -> &mut (dyn AsyncWrite + Unpin + Send) {
        &mut self.sink
    }

    async fn enable_models(&mut self) -> Result<(), SolverError> {
        Ok(())
    }

    async fn check_sat(&mut self) -> Result<Decision, SolverError> {
        Ok(match self.decision {
            DecisionWithModel::Sat { .. } => Decision::Sat,
            DecisionWithModel::Unsat => Decision::Unsat,
            DecisionWithModel::Unknown => Decision::Unknown,
        })
    }

    async fn check_sat_with_model(&mut self) -> Result<DecisionWithModel, SolverError> {
        Ok(self.decision.clone())
    }
}

fn expense_input(invariant_id: impl Into<String>) -> CedarAnalysisInput {
    CedarAnalysisInput::new(
        invariant_id,
        CedarAnalysisQuery::AlwaysDenies,
        EXPENSE_APPROVAL_POLICY,
        EXPENSE_APPROVAL_SCHEMA,
    )
}

fn expense_high_risk_claim_input() -> CedarAnalysisInput {
    CedarAnalysisInput::new(
        INVARIANT_ID,
        CedarAnalysisQuery::ExpenseNonFinanceHighValueCommitDenied,
        EXPENSE_APPROVAL_POLICY,
        EXPENSE_APPROVAL_SCHEMA,
    )
}

fn permit_all_input() -> CedarAnalysisInput {
    CedarAnalysisInput::new(
        "simple.permit_all.must_not_always_deny",
        CedarAnalysisQuery::AlwaysDenies,
        PERMIT_ALL_POLICY,
        SIMPLE_SCHEMA,
    )
}

fn positive_claim_review_case() -> ExpenseClaimReviewCase {
    ExpenseClaimReviewCase {
        name: "baseline_non_finance_high_value_commit",
        authority: AuthorityLevel::Supervisory,
        domains: &["operations"],
        resource_type: "expense",
        action: FlowAction::Commit,
        amount: 5_001,
        human_approval_present: true,
        gates_passed: &["receipt", "manager_approval"],
        required_gates_met: true,
        expected_claim_match: true,
    }
}

fn claim_review_cases() -> Vec<ExpenseClaimReviewCase> {
    vec![
        positive_claim_review_case(),
        ExpenseClaimReviewCase {
            name: "finance_domain_is_outside_claim",
            domains: &["finance"],
            expected_claim_match: false,
            ..positive_claim_review_case()
        },
        ExpenseClaimReviewCase {
            name: "advisory_authority_is_outside_claim",
            authority: AuthorityLevel::Advisory,
            expected_claim_match: false,
            ..positive_claim_review_case()
        },
        ExpenseClaimReviewCase {
            name: "threshold_amount_is_outside_claim",
            amount: 5_000,
            expected_claim_match: false,
            ..positive_claim_review_case()
        },
        ExpenseClaimReviewCase {
            name: "missing_human_approval_is_outside_claim",
            human_approval_present: false,
            expected_claim_match: false,
            ..positive_claim_review_case()
        },
        ExpenseClaimReviewCase {
            name: "missing_receipt_gate_is_outside_claim",
            gates_passed: &["manager_approval"],
            expected_claim_match: false,
            ..positive_claim_review_case()
        },
        ExpenseClaimReviewCase {
            name: "missing_manager_gate_is_outside_claim",
            gates_passed: &["receipt"],
            expected_claim_match: false,
            ..positive_claim_review_case()
        },
        ExpenseClaimReviewCase {
            name: "required_gates_false_is_outside_claim",
            required_gates_met: false,
            expected_claim_match: false,
            ..positive_claim_review_case()
        },
        ExpenseClaimReviewCase {
            name: "non_expense_resource_is_outside_claim",
            resource_type: "invoice",
            expected_claim_match: false,
            ..positive_claim_review_case()
        },
        ExpenseClaimReviewCase {
            name: "validate_action_is_outside_claim",
            action: FlowAction::Validate,
            expected_claim_match: false,
            ..positive_claim_review_case()
        },
    ]
}

#[test]
fn compiles_expense_policy_for_symbolic_analysis() {
    let plan = compile_analysis_plan(&expense_input(INVARIANT_ID))
        .expect("expense policy should compile for Cedar symbolic analysis");

    assert_eq!(plan.invariant_id, INVARIANT_ID);
    assert_eq!(plan.query, CedarAnalysisQuery::AlwaysDenies);
    assert_eq!(plan.policy_count, 11);
    assert_eq!(plan.request_env_count(), 4);
    assert_eq!(plan.cedar_symcc_version, "0.4");
    assert!(plan.policy_hash.starts_with("fnv1a64:"));
    assert!(plan.schema_hash.starts_with("fnv1a64:"));
    assert!(plan.query_hash.starts_with("fnv1a64:"));
    assert!(
        plan.request_environments
            .iter()
            .all(|env| env.assertion_count > 0)
    );
    assert!(
        plan.request_environments
            .iter()
            .any(|env| env.action == "Action::\"commit\"")
    );
}

#[test]
fn compiles_conditional_expense_claim_for_symbolic_analysis() {
    let plan = compile_analysis_plan(&expense_high_risk_claim_input())
        .expect("conditional expense claim should compile for Cedar symbolic analysis");

    assert_eq!(plan.invariant_id, INVARIANT_ID);
    assert_eq!(
        plan.query,
        CedarAnalysisQuery::ExpenseNonFinanceHighValueCommitDenied
    );
    assert_eq!(plan.policy_count, 11);
    assert_eq!(plan.request_env_count(), 4);
    assert!(
        plan.request_environments
            .iter()
            .all(|env| env.assertion_count > 0)
    );
    assert!(
        plan.request_environments
            .iter()
            .any(|env| env.action == "Action::\"commit\"")
    );
}

#[test]
fn conditional_expense_claim_policy_matches_business_review_fixtures() {
    assert_eq!(
        CedarAnalysisQuery::ExpenseNonFinanceHighValueCommitDenied.claim_policy_source(),
        Some(EXPENSE_NON_FINANCE_HIGH_VALUE_COMMIT_CLAIM_POLICY)
    );
    let claim_engine = PolicyEngine::from_policy_str(
        CedarAnalysisQuery::ExpenseNonFinanceHighValueCommitDenied
            .claim_policy_source()
            .expect("conditional query should expose its Cedar claim policy"),
    )
    .expect("claim policy should parse");

    for case in claim_review_cases() {
        let decision = claim_engine
            .evaluate(&case.request())
            .unwrap_or_else(|err| panic!("{} should evaluate: {err}", case.name));

        assert_eq!(
            decision.outcome.is_allowed(),
            case.expected_claim_match,
            "{} mapped to unexpected claim-policy membership: {decision:#?}",
            case.name
        );
    }
}

#[test]
fn production_policy_rejects_positive_claim_review_fixture() {
    let engine = PolicyEngine::from_policy_str(EXPENSE_APPROVAL_POLICY)
        .expect("production expense policy should parse");
    let decision = engine
        .evaluate(&positive_claim_review_case().request())
        .expect("positive claim fixture should evaluate");

    assert_eq!(decision.outcome, PolicyOutcome::Reject);
}

#[test]
fn negative_mutant_policy_allows_positive_claim_review_fixture() {
    let engine = PolicyEngine::from_policy_str(BROKEN_EXPENSE_POLICY_ALLOWS_CLAIM_SPACE)
        .expect("mutant policy should parse");
    let decision = engine
        .evaluate(&positive_claim_review_case().request())
        .expect("positive claim fixture should evaluate against mutant policy");

    assert_eq!(decision.outcome, PolicyOutcome::Promote);
    assert!(
        compile_analysis_plan(&CedarAnalysisInput::new(
            "expense.non_finance_commit.high_value.mutant",
            CedarAnalysisQuery::ExpenseNonFinanceHighValueCommitDenied,
            BROKEN_EXPENSE_POLICY_ALLOWS_CLAIM_SPACE,
            EXPENSE_APPROVAL_SCHEMA,
        ))
        .is_ok(),
        "the conditional query must still compile against a policy that violates the claim"
    );
}

#[test]
fn rejects_empty_invariant_id() {
    let err = compile_analysis_plan(&expense_input("   "))
        .expect_err("empty invariant id should be rejected");

    assert_eq!(err, CedarAnalysisError::MissingInvariantId);
}

#[test]
fn rejects_invalid_schema_source() {
    let input = CedarAnalysisInput::new(
        INVARIANT_ID,
        CedarAnalysisQuery::AlwaysDenies,
        EXPENSE_APPROVAL_POLICY,
        "entity ;",
    );
    let err = compile_analysis_plan(&input).expect_err("invalid schema should be rejected");

    assert!(matches!(err, CedarAnalysisError::SchemaParse(_)));
}

#[test]
fn rejects_policy_that_does_not_validate_against_schema() {
    let input = CedarAnalysisInput::new(
        INVARIANT_ID,
        CedarAnalysisQuery::AlwaysDenies,
        r#"permit(principal, action == Action::"commit", resource)
           when { principal.unknown_attr == "finance" };"#,
        EXPENSE_APPROVAL_SCHEMA,
    );
    let err = compile_analysis_plan(&input).expect_err("schema-invalid policy should fail");

    assert!(matches!(err, CedarAnalysisError::PolicyValidation(_)));
}

#[test]
fn query_shape_changes_query_hash() {
    let denies = compile_analysis_plan(&expense_input(INVARIANT_ID))
        .expect("always-denies plan should compile");
    let allows = compile_analysis_plan(&CedarAnalysisInput::new(
        INVARIANT_ID,
        CedarAnalysisQuery::AlwaysAllows,
        EXPENSE_APPROVAL_POLICY,
        EXPENSE_APPROVAL_SCHEMA,
    ))
    .expect("always-allows plan should compile");

    assert_ne!(denies.query_hash, allows.query_hash);
    assert_eq!(denies.policy_hash, allows.policy_hash);
    assert_eq!(denies.schema_hash, allows.schema_hash);

    let conditional = compile_analysis_plan(&expense_high_risk_claim_input())
        .expect("conditional claim plan should compile");
    assert_ne!(denies.query_hash, conditional.query_hash);
    assert_eq!(denies.policy_hash, conditional.policy_hash);
    assert_eq!(denies.schema_hash, conditional.schema_hash);
}

#[tokio::test]
async fn solver_execution_reports_no_violation_when_solver_returns_unsat() {
    let report =
        execute_analysis_with_solver(&expense_input(INVARIANT_ID), FixedDecisionSolver::unsat())
            .await
            .expect("solver-backed execution should produce a report");

    assert_eq!(report.status, CedarAnalysisExecutionStatus::NoViolation);
    assert_eq!(
        report.execution_identity.backend,
        "caller-supplied-symcc-solver"
    );
    assert_eq!(report.execution_identity.backend_version, "not_applicable");
    assert!(report.execution_identity.native_identity.is_none());
    assert!(
        report
            .execution_identity
            .runtime_config
            .contains("query=always_denies")
    );
    assert_eq!(report.checks.len(), report.plan.request_env_count());
    assert!(
        report
            .checks
            .iter()
            .all(|check| check.status == CedarAnalysisExecutionStatus::NoViolation)
    );
}

#[tokio::test]
async fn conditional_expense_claim_reports_no_violation_when_solver_returns_unsat() {
    let report = execute_analysis_with_solver(
        &expense_high_risk_claim_input(),
        FixedDecisionSolver::unsat(),
    )
    .await
    .expect("conditional solver-backed execution should produce a report");

    assert_eq!(report.status, CedarAnalysisExecutionStatus::NoViolation);
    assert_eq!(
        report.plan.query,
        CedarAnalysisQuery::ExpenseNonFinanceHighValueCommitDenied
    );
    assert!(
        report
            .execution_identity
            .runtime_config
            .contains("query=expense_non_finance_high_value_commit_denied")
    );
    assert!(
        report
            .checks
            .iter()
            .all(|check| check.status == CedarAnalysisExecutionStatus::NoViolation)
    );
}

#[tokio::test]
async fn solver_execution_maps_unknown_to_report_status() {
    let report =
        execute_analysis_with_solver(&expense_input(INVARIANT_ID), FixedDecisionSolver::unknown())
            .await
            .expect("unknown solver response should still produce a report");

    assert_eq!(report.status, CedarAnalysisExecutionStatus::Unknown);
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.status == CedarAnalysisExecutionStatus::Unknown)
    );
}

#[tokio::test]
async fn solver_execution_captures_counterexample_details() {
    let report = execute_analysis_with_solver(&permit_all_input(), FixedDecisionSolver::unknown())
        .await
        .expect("constant counterexample should not require a real solver");

    assert_eq!(
        report.status,
        CedarAnalysisExecutionStatus::CounterexampleFound
    );
    assert!(report.checks.iter().any(|check| {
        check.status == CedarAnalysisExecutionStatus::CounterexampleFound
            && check
                .counterexample
                .as_ref()
                .is_some_and(|counterexample| !counterexample.is_empty())
    }));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn preserves_valid_invariant_ids(invariant_id in "[a-z][a-z0-9_.-]{0,32}") {
        let plan = compile_analysis_plan(&expense_input(invariant_id.clone()))
            .expect("valid generated invariant id should compile");

        prop_assert_eq!(&plan.invariant_id, &invariant_id);
        prop_assert_eq!(plan.request_env_count(), 4);
    }

    #[test]
    fn rejects_whitespace_only_invariant_ids(invariant_id in "[ \\t\\n]{0,16}") {
        let err = compile_analysis_plan(&expense_input(invariant_id))
            .expect_err("whitespace-only invariant ids should be rejected");

        prop_assert_eq!(err, CedarAnalysisError::MissingInvariantId);
    }
}
