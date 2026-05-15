//! Optional Cedar symbolic-analysis support.
//!
//! This module uses `cedar-policy-symcc` to compile a policy set against a
//! Cedar schema and produce deterministic analysis evidence. Solver execution
//! is optional: tests can use an in-process SymCC solver, while scheduled or
//! manual checks can use a local CVC5 process.

use std::{env, process::Command, str::FromStr};

use cedar_policy::{PolicySet, RequestEnv, Schema, ValidationMode, Validator};
use cedar_policy_symcc::{
    CedarSymCompiler, CompiledPolicySet, always_allows_asserts, always_denies_asserts,
    disjoint_asserts,
    err::Error as SymccError,
    solver::{LocalSolver, Solver},
};
use converge_pack::{
    ExecutionIdentity, ExecutionProducerIdentity, FactPayload, NativeExecutionIdentity,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const CEDAR_SYMCC_VERSION: &str = "0.4";
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
/// Cedar policy that defines the request space for
/// [`CedarAnalysisQuery::ExpenseNonFinanceHighValueCommitDenied`].
///
/// This is the model-adequacy boundary: reviewers should compare this Cedar
/// claim policy to the human business invariant before trusting solver output.
pub const EXPENSE_NON_FINANCE_HIGH_VALUE_COMMIT_CLAIM_POLICY: &str = r#"
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

/// The symbolic query shape Arbiter can prepare without invoking an SMT solver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CedarAnalysisQuery {
    /// Generate an assertion set whose unsatisfiability means every modeled
    /// request is allowed by the policy set.
    AlwaysAllows,
    /// Generate an assertion set whose unsatisfiability means every modeled
    /// request is denied by the policy set.
    AlwaysDenies,
    /// Generate an assertion set whose unsatisfiability means no modeled
    /// request matching the high-risk Arbiter expense claim is allowed by the
    /// policy set. The claim is:
    /// non-finance supervisory principals cannot commit high-value expenses
    /// even when receipt, manager approval, required gates, and human approval
    /// are present.
    ExpenseNonFinanceHighValueCommitDenied,
}

/// Input for a Cedar symbolic-analysis preparation run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CedarAnalysisInput {
    /// Stable invariant identifier, usually derived from a Gherkin scenario.
    pub invariant_id: String,
    /// Query to prepare.
    pub query: CedarAnalysisQuery,
    /// Cedar policy set source.
    pub policy_source: String,
    /// Cedar schema source.
    pub schema_source: String,
}

impl FactPayload for CedarAnalysisInput {
    const FAMILY: &'static str = "arbiter.cedar_analysis.input";
    const VERSION: u16 = 1;
}

/// Backend that can execute a Cedar Analysis request.
///
/// This trait is intentionally in Arbiter so products can assemble different
/// solver backends without making Arbiter depend on another extension crate.
#[async_trait::async_trait]
pub trait CedarAnalysisBackend: Send + Sync {
    /// Stable backend name for diagnostics and provenance.
    fn name(&self) -> &'static str;

    /// Execute the analysis request.
    async fn analyze(
        &self,
        input: &CedarAnalysisInput,
    ) -> Result<CedarAnalysisReport, CedarAnalysisError>;
}

/// Cedar Analysis backend that uses the local `cvc5` binary through
/// `cedar-policy-symcc`.
#[derive(Debug, Clone, Copy, Default)]
pub struct LocalCvc5AnalysisBackend;

#[async_trait::async_trait]
impl CedarAnalysisBackend for LocalCvc5AnalysisBackend {
    fn name(&self) -> &'static str {
        "cedar-analysis-local-cvc5"
    }

    async fn analyze(
        &self,
        input: &CedarAnalysisInput,
    ) -> Result<CedarAnalysisReport, CedarAnalysisError> {
        let input = input.clone();
        tokio::task::spawn_blocking(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|err| CedarAnalysisError::SolverInit(err.to_string()))?;

            runtime.block_on(async { execute_analysis_with_cvc5(&input).await })
        })
        .await
        .map_err(|err| CedarAnalysisError::SolverInit(err.to_string()))?
    }
}

impl CedarAnalysisInput {
    /// Construct a new analysis input from borrowed source strings.
    pub fn new(
        invariant_id: impl Into<String>,
        query: CedarAnalysisQuery,
        policy_source: impl Into<String>,
        schema_source: impl Into<String>,
    ) -> Self {
        Self {
            invariant_id: invariant_id.into(),
            query,
            policy_source: policy_source.into(),
            schema_source: schema_source.into(),
        }
    }
}

/// Per-request-environment analysis produced by SymCC compilation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CedarRequestEnvironmentAnalysis {
    /// Principal entity type from the request environment.
    pub principal_type: String,
    /// Cedar action entity UID from the request environment.
    pub action: String,
    /// Resource entity type from the request environment.
    pub resource_type: String,
    /// Number of symbolic assertions generated for this environment/query.
    pub assertion_count: usize,
}

impl CedarRequestEnvironmentAnalysis {
    fn from_request_env(request_env: &RequestEnv, assertion_count: usize) -> Self {
        Self {
            principal_type: request_env.principal().to_string(),
            action: request_env.action().to_string(),
            resource_type: request_env.resource().to_string(),
            assertion_count,
        }
    }
}

/// Deterministic, auditable evidence that a policy/schema/query combination
/// can be handed to Cedar's symbolic compiler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CedarAnalysisPlan {
    /// Stable invariant identifier.
    pub invariant_id: String,
    /// Query prepared for symbolic analysis.
    pub query: CedarAnalysisQuery,
    /// Stable content hash of the policy source.
    pub policy_hash: String,
    /// Stable content hash of the schema source.
    pub schema_hash: String,
    /// Stable content hash of the invariant id and query.
    pub query_hash: String,
    /// Cedar SDK version used for parsing and validation.
    pub cedar_policy_version: String,
    /// Cedar SymCC crate version used for symbolic compilation.
    pub cedar_symcc_version: String,
    /// Number of static policies in the policy set.
    pub policy_count: usize,
    /// Request environments successfully compiled by SymCC.
    pub request_environments: Vec<CedarRequestEnvironmentAnalysis>,
}

impl FactPayload for CedarAnalysisPlan {
    const FAMILY: &'static str = "arbiter.cedar_analysis.plan";
    const VERSION: u16 = 1;
}

impl CedarAnalysisPlan {
    /// Number of request environments represented in this plan.
    pub fn request_env_count(&self) -> usize {
        self.request_environments.len()
    }
}

/// Overall status of a solver-backed Cedar Analysis execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CedarAnalysisExecutionStatus {
    /// All request environments had no counterexample for the selected query.
    NoViolation,
    /// At least one request environment produced a concrete counterexample.
    CounterexampleFound,
    /// At least one request environment returned `unknown`, and none produced a
    /// counterexample or hard error.
    Unknown,
    /// At least one request environment hit a solver/model/concretization
    /// error.
    Error,
}

/// Per-request-environment solver result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CedarAnalysisCheck {
    /// Request environment analyzed by the solver.
    pub environment: CedarRequestEnvironmentAnalysis,
    /// Solver-backed status for this environment.
    pub status: CedarAnalysisExecutionStatus,
    /// Concrete counterexample recovered by SymCC, when one exists.
    pub counterexample: Option<String>,
    /// Diagnostic text for unknown or error outcomes.
    pub diagnostics: Option<String>,
}

/// Solver-backed Cedar Analysis report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CedarAnalysisReport {
    /// Solver-free preparation evidence for the same policy/schema/query.
    pub plan: CedarAnalysisPlan,
    /// Runtime identity for the backend that executed the symbolic query.
    pub execution_identity: ExecutionIdentity,
    /// Rollup status across all request environments.
    pub status: CedarAnalysisExecutionStatus,
    /// Per-request-environment solver results.
    pub checks: Vec<CedarAnalysisCheck>,
}

impl FactPayload for CedarAnalysisReport {
    const FAMILY: &'static str = "arbiter.cedar_analysis.report";
    const VERSION: u16 = 2;
}

/// Errors from preparing Cedar symbolic-analysis evidence.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CedarAnalysisError {
    /// The invariant identifier was empty or whitespace.
    #[error("invariant id must not be empty")]
    MissingInvariantId,
    /// The Cedar schema could not be parsed.
    #[error("failed to parse Cedar schema: {0}")]
    SchemaParse(String),
    /// The Cedar policy set could not be parsed.
    #[error("failed to parse Cedar policy set: {0}")]
    PolicyParse(String),
    /// The policy set failed Cedar schema validation.
    #[error("failed Cedar policy validation: {0}")]
    PolicyValidation(String),
    /// The schema did not expose any request environments.
    #[error("schema did not produce any request environments")]
    NoRequestEnvironments,
    /// SymCC could not compile a policy/query environment.
    #[error("failed to compile Cedar symbolic analysis: {0}")]
    Compile(String),
    /// The solver or symbolic compiler could not be initialized.
    #[error("failed to initialize Cedar symbolic-analysis solver: {0}")]
    SolverInit(String),
}

/// Parse, validate, and symbolically compile a Cedar policy/schema/query pair.
///
/// This produces analysis evidence only. It does not call an SMT solver and
/// therefore does not prove the query satisfiable or unsatisfiable.
pub fn compile_analysis_plan(
    input: &CedarAnalysisInput,
) -> Result<CedarAnalysisPlan, CedarAnalysisError> {
    if input.invariant_id.trim().is_empty() {
        return Err(CedarAnalysisError::MissingInvariantId);
    }

    let schema = parse_schema(&input.schema_source)?;
    let policies = parse_policy_set(&input.policy_source)?;
    validate_policy_set(&schema, &policies)?;
    let query_policies = parse_query_policy_set(input.query)?;
    if let Some(query_policies) = &query_policies {
        validate_policy_set(&schema, query_policies)?;
    }

    let request_environments = schema
        .request_envs()
        .map(|request_env| {
            let compiled = CompiledPolicySet::compile(&policies, &request_env, &schema)
                .map_err(|err| CedarAnalysisError::Compile(format!("{err:?}")))?;
            let assertion_count = match input.query {
                CedarAnalysisQuery::AlwaysAllows => {
                    always_allows_asserts(&compiled).asserts().len()
                }
                CedarAnalysisQuery::AlwaysDenies => {
                    always_denies_asserts(&compiled).asserts().len()
                }
                CedarAnalysisQuery::ExpenseNonFinanceHighValueCommitDenied => {
                    let query_policies = query_policies.as_ref().ok_or_else(|| {
                        CedarAnalysisError::Compile(
                            "conditional expense claim policy was not prepared".to_string(),
                        )
                    })?;
                    let compiled_query =
                        CompiledPolicySet::compile(query_policies, &request_env, &schema)
                            .map_err(|err| CedarAnalysisError::Compile(format!("{err:?}")))?;
                    disjoint_asserts(&compiled, &compiled_query).asserts().len()
                }
            };

            Ok(CedarRequestEnvironmentAnalysis::from_request_env(
                &request_env,
                assertion_count,
            ))
        })
        .collect::<Result<Vec<_>, CedarAnalysisError>>()?;

    if request_environments.is_empty() {
        return Err(CedarAnalysisError::NoRequestEnvironments);
    }

    Ok(CedarAnalysisPlan {
        invariant_id: input.invariant_id.clone(),
        query: input.query,
        policy_hash: stable_hash(&input.policy_source),
        schema_hash: stable_hash(&input.schema_source),
        query_hash: stable_query_hash(&input.invariant_id, input.query),
        cedar_policy_version: cedar_policy::get_sdk_version().to_string(),
        cedar_symcc_version: CEDAR_SYMCC_VERSION.to_string(),
        policy_count: policies.policies().count(),
        request_environments,
    })
}

/// Execute a Cedar Analysis query with a caller-supplied SymCC solver.
///
/// This is the first solver-backed lane: `NoViolation` means the solver found
/// no counterexample for the prepared query across all modeled request
/// environments. It remains `Searched` evidence, not formal proof evidence.
pub async fn execute_analysis_with_solver<S: Solver>(
    input: &CedarAnalysisInput,
    solver: S,
) -> Result<CedarAnalysisReport, CedarAnalysisError> {
    execute_analysis_with_solver_and_identity(
        input,
        solver,
        non_native_analysis_identity(input, "caller-supplied-symcc-solver"),
    )
    .await
}

/// Execute a Cedar Analysis query with a caller-supplied SymCC solver and
/// explicit execution identity.
///
/// Use this when the caller can name the real backend more precisely than
/// Arbiter's generic in-process solver wrapper.
pub async fn execute_analysis_with_solver_and_identity<S: Solver>(
    input: &CedarAnalysisInput,
    solver: S,
    execution_identity: ExecutionIdentity,
) -> Result<CedarAnalysisReport, CedarAnalysisError> {
    let plan = compile_analysis_plan(input)?;
    let schema = parse_schema(&input.schema_source)?;
    let policies = parse_policy_set(&input.policy_source)?;
    validate_policy_set(&schema, &policies)?;
    let query_policies = parse_query_policy_set(input.query)?;
    if let Some(query_policies) = &query_policies {
        validate_policy_set(&schema, query_policies)?;
    }
    let mut compiler = CedarSymCompiler::new(solver)
        .map_err(|err| CedarAnalysisError::SolverInit(err.to_string()))?;

    let mut checks = Vec::with_capacity(plan.request_env_count());
    for request_env in schema.request_envs() {
        let compiled = CompiledPolicySet::compile(&policies, &request_env, &schema)
            .map_err(|err| CedarAnalysisError::Compile(format!("{err:?}")))?;
        let solver_result = match input.query {
            CedarAnalysisQuery::AlwaysAllows => {
                let assertions = always_allows_asserts(&compiled);
                compiler.check_sat(&assertions).await
            }
            CedarAnalysisQuery::AlwaysDenies => {
                let assertions = always_denies_asserts(&compiled);
                compiler.check_sat(&assertions).await
            }
            CedarAnalysisQuery::ExpenseNonFinanceHighValueCommitDenied => {
                let query_policies = query_policies.as_ref().ok_or_else(|| {
                    CedarAnalysisError::Compile(
                        "conditional expense claim policy was not prepared".to_string(),
                    )
                })?;
                let compiled_query =
                    CompiledPolicySet::compile(query_policies, &request_env, &schema)
                        .map_err(|err| CedarAnalysisError::Compile(format!("{err:?}")))?;
                let assertions = disjoint_asserts(&compiled, &compiled_query);
                compiler.check_sat(&assertions).await
            }
        };
        let environment = CedarRequestEnvironmentAnalysis::from_request_env(
            &request_env,
            plan.request_environments[checks.len()].assertion_count,
        );

        let check = match solver_result {
            Ok(None) => CedarAnalysisCheck {
                environment,
                status: CedarAnalysisExecutionStatus::NoViolation,
                counterexample: None,
                diagnostics: None,
            },
            Ok(Some(counterexample)) => CedarAnalysisCheck {
                environment,
                status: CedarAnalysisExecutionStatus::CounterexampleFound,
                counterexample: Some(format!("{counterexample:#?}")),
                diagnostics: None,
            },
            Err(SymccError::SolverUnknown) => CedarAnalysisCheck {
                environment,
                status: CedarAnalysisExecutionStatus::Unknown,
                counterexample: None,
                diagnostics: Some("solver returned unknown".to_string()),
            },
            Err(err) => CedarAnalysisCheck {
                environment,
                status: CedarAnalysisExecutionStatus::Error,
                counterexample: None,
                diagnostics: Some(err.to_string()),
            },
        };
        checks.push(check);
    }

    Ok(CedarAnalysisReport {
        status: overall_status(&checks),
        execution_identity,
        plan,
        checks,
    })
}

/// Execute a Cedar Analysis query with a local CVC5 process.
///
/// The executable is resolved by `cedar-policy-symcc`: `CVC5` environment
/// variable first, then `cvc5` on `PATH`.
pub async fn execute_analysis_with_cvc5(
    input: &CedarAnalysisInput,
) -> Result<CedarAnalysisReport, CedarAnalysisError> {
    let solver =
        LocalSolver::cvc5().map_err(|err| CedarAnalysisError::SolverInit(err.to_string()))?;
    execute_analysis_with_solver_and_identity(input, solver, cvc5_analysis_identity(input)).await
}

fn non_native_analysis_identity(input: &CedarAnalysisInput, backend: &str) -> ExecutionIdentity {
    ExecutionIdentity::non_native(
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        backend,
        analysis_runtime_config(input),
    )
}

fn cvc5_analysis_identity(input: &CedarAnalysisInput) -> ExecutionIdentity {
    let version = local_cvc5_version();
    ExecutionIdentity::new(
        ExecutionProducerIdentity::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
        "cvc5",
        version.clone(),
        "external_process=true",
        analysis_runtime_config(input),
        Some(NativeExecutionIdentity::new(
            "CVC5",
            version.clone(),
            "https://github.com/cvc5/cvc5",
            "external",
            version,
            "external-process",
        )),
    )
}

fn analysis_runtime_config(input: &CedarAnalysisInput) -> String {
    format!(
        "invariant_id={}; query={}; policy_hash={}; schema_hash={}; query_hash={}",
        input.invariant_id,
        input.query.stable_label(),
        stable_hash(&input.policy_source),
        stable_hash(&input.schema_source),
        stable_query_hash(&input.invariant_id, input.query)
    )
}

fn local_cvc5_version() -> String {
    let executable = env::var("CVC5").unwrap_or_else(|_| "cvc5".to_string());
    Command::new(executable)
        .arg("--version")
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok()
            } else {
                None
            }
        })
        .and_then(|stdout| stdout.lines().next().map(str::trim).map(str::to_string))
        .filter(|version| !version.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn overall_status(checks: &[CedarAnalysisCheck]) -> CedarAnalysisExecutionStatus {
    if checks
        .iter()
        .any(|check| check.status == CedarAnalysisExecutionStatus::Error)
    {
        CedarAnalysisExecutionStatus::Error
    } else if checks
        .iter()
        .any(|check| check.status == CedarAnalysisExecutionStatus::CounterexampleFound)
    {
        CedarAnalysisExecutionStatus::CounterexampleFound
    } else if checks
        .iter()
        .any(|check| check.status == CedarAnalysisExecutionStatus::Unknown)
    {
        CedarAnalysisExecutionStatus::Unknown
    } else {
        CedarAnalysisExecutionStatus::NoViolation
    }
}

fn parse_schema(source: &str) -> Result<Schema, CedarAnalysisError> {
    Schema::from_cedarschema_str(source)
        .map(|(schema, _warnings)| schema)
        .map_err(|err| CedarAnalysisError::SchemaParse(format!("{err:?}")))
}

fn parse_policy_set(source: &str) -> Result<PolicySet, CedarAnalysisError> {
    PolicySet::from_str(source).map_err(|err| CedarAnalysisError::PolicyParse(format!("{err:?}")))
}

fn parse_query_policy_set(
    query: CedarAnalysisQuery,
) -> Result<Option<PolicySet>, CedarAnalysisError> {
    match query {
        CedarAnalysisQuery::AlwaysAllows | CedarAnalysisQuery::AlwaysDenies => Ok(None),
        CedarAnalysisQuery::ExpenseNonFinanceHighValueCommitDenied => {
            parse_policy_set(EXPENSE_NON_FINANCE_HIGH_VALUE_COMMIT_CLAIM_POLICY).map(Some)
        }
    }
}

fn validate_policy_set(schema: &Schema, policies: &PolicySet) -> Result<(), CedarAnalysisError> {
    let result = Validator::new(schema.clone()).validate(policies, ValidationMode::Strict);
    if result.validation_passed() {
        Ok(())
    } else {
        Err(CedarAnalysisError::PolicyValidation(format!("{result:?}")))
    }
}

fn stable_hash(value: &str) -> String {
    format_hash(fnv1a([value.as_bytes()]))
}

fn stable_query_hash(invariant_id: &str, query: CedarAnalysisQuery) -> String {
    match query.policy_source() {
        Some(policy_source) => format_hash(fnv1a([
            invariant_id.as_bytes(),
            b"\0",
            query.stable_label().as_bytes(),
            b"\0",
            policy_source.as_bytes(),
        ])),
        None => format_hash(fnv1a([
            invariant_id.as_bytes(),
            b"\0",
            query.stable_label().as_bytes(),
        ])),
    }
}

impl CedarAnalysisQuery {
    /// Cedar policy source that encodes the claim space for this query, when
    /// the query is conditional.
    #[must_use]
    pub const fn claim_policy_source(self) -> Option<&'static str> {
        self.policy_source()
    }

    const fn stable_label(self) -> &'static str {
        match self {
            Self::AlwaysAllows => "always_allows",
            Self::AlwaysDenies => "always_denies",
            Self::ExpenseNonFinanceHighValueCommitDenied => {
                "expense_non_finance_high_value_commit_denied"
            }
        }
    }

    const fn policy_source(self) -> Option<&'static str> {
        match self {
            Self::AlwaysAllows | Self::AlwaysDenies => None,
            Self::ExpenseNonFinanceHighValueCommitDenied => {
                Some(EXPENSE_NON_FINANCE_HIGH_VALUE_COMMIT_CLAIM_POLICY)
            }
        }
    }
}

fn fnv1a<const N: usize>(parts: [&[u8]; N]) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    for part in parts {
        for byte in part {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
    }
    hash
}

fn format_hash(hash: u64) -> String {
    format!("fnv1a64:{hash:016x}")
}
