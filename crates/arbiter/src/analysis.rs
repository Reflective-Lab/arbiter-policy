//! Optional Cedar symbolic-analysis support.
//!
//! This module uses `cedar-policy-symcc` to compile a policy set against a
//! Cedar schema and produce deterministic analysis evidence. It deliberately
//! stops before solver execution so the default Arbiter path does not require a
//! local SMT solver such as CVC5.

use std::str::FromStr;

use cedar_policy::{PolicySet, RequestEnv, Schema, ValidationMode, Validator};
use cedar_policy_symcc::{
    CedarSymCompiler, CompiledPolicySet, always_allows_asserts, always_denies_asserts,
    err::Error as SymccError,
    solver::{LocalSolver, Solver},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const CEDAR_SYMCC_VERSION: &str = "0.4";
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

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
}

/// Input for a Cedar symbolic-analysis preparation run.
#[derive(Debug, Clone, PartialEq, Eq)]
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
pub struct CedarAnalysisReport {
    /// Solver-free preparation evidence for the same policy/schema/query.
    pub plan: CedarAnalysisPlan,
    /// Rollup status across all request environments.
    pub status: CedarAnalysisExecutionStatus,
    /// Per-request-environment solver results.
    pub checks: Vec<CedarAnalysisCheck>,
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

    let request_environments = schema
        .request_envs()
        .map(|request_env| {
            let compiled = CompiledPolicySet::compile(&policies, &request_env, &schema)
                .map_err(|err| CedarAnalysisError::Compile(format!("{err:?}")))?;
            let assertions = match input.query {
                CedarAnalysisQuery::AlwaysAllows => always_allows_asserts(&compiled),
                CedarAnalysisQuery::AlwaysDenies => always_denies_asserts(&compiled),
            };

            Ok(CedarRequestEnvironmentAnalysis::from_request_env(
                &request_env,
                assertions.asserts().len(),
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
    let plan = compile_analysis_plan(input)?;
    let schema = parse_schema(&input.schema_source)?;
    let policies = parse_policy_set(&input.policy_source)?;
    validate_policy_set(&schema, &policies)?;
    let mut compiler = CedarSymCompiler::new(solver)
        .map_err(|err| CedarAnalysisError::SolverInit(err.to_string()))?;

    let mut checks = Vec::with_capacity(plan.request_env_count());
    for request_env in schema.request_envs() {
        let compiled = CompiledPolicySet::compile(&policies, &request_env, &schema)
            .map_err(|err| CedarAnalysisError::Compile(format!("{err:?}")))?;
        let assertions = match input.query {
            CedarAnalysisQuery::AlwaysAllows => always_allows_asserts(&compiled),
            CedarAnalysisQuery::AlwaysDenies => always_denies_asserts(&compiled),
        };
        let environment = CedarRequestEnvironmentAnalysis::from_request_env(
            &request_env,
            assertions.asserts().len(),
        );

        let check = match compiler.check_sat(&assertions).await {
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
    execute_analysis_with_solver(input, solver).await
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
    let query = match query {
        CedarAnalysisQuery::AlwaysAllows => "always_allows",
        CedarAnalysisQuery::AlwaysDenies => "always_denies",
    };
    format_hash(fnv1a([invariant_id.as_bytes(), b"\0", query.as_bytes()]))
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
