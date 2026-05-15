//! # arbiter
//!
//! Cedar-based policy enforcement as Suggestors for the Converge Engine.
//!
//! Policy gates participate INSIDE the convergence loop — they evaluate
//! proposals against Cedar policies and write constraints for violations.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use arbiter::{PolicyGateSuggestor, PolicyEngine};
//! use std::sync::Arc;
//!
//! let engine = PolicyEngine::from_policy_str(EXPENSE_APPROVAL_POLICY)?;
//! let gate = PolicyGateSuggestor::new(Arc::new(engine));
//! converge_engine.register_suggestor(gate);
//! ```
//!
//! ## Available Suggestors
//!
//! - [`PolicyGateSuggestor`] — Cedar policy evaluation
//! - [`DelegationVerifySuggestor`] — Ed25519 delegation chain verification
//! - [`FlowGateSuggestor`] — Flow-level authorization gates
//! - [`CedarHitlGateSuggestor`] — named strict Cedar-backed HITL gate for Formations

// ── Public API: Suggestors + construction types ───────────────────────

#[cfg(feature = "analysis")]
pub mod analysis;
pub mod engine;
pub mod formation;
pub mod provenance;
pub mod suggestor;
pub mod types;

#[cfg(feature = "analysis")]
pub use analysis::{
    CedarAnalysisBackend, CedarAnalysisCheck, CedarAnalysisError, CedarAnalysisExecutionStatus,
    CedarAnalysisInput, CedarAnalysisPlan, CedarAnalysisQuery, CedarAnalysisReport,
    CedarRequestEnvironmentAnalysis, EXPENSE_NON_FINANCE_HIGH_VALUE_COMMIT_CLAIM_POLICY,
    LocalCvc5AnalysisBackend, compile_analysis_plan, execute_analysis_with_cvc5,
    execute_analysis_with_solver, execute_analysis_with_solver_and_identity,
};
pub use engine::PolicyEngine;
pub use formation::{
    ANALYSIS_EVIDENCE_CAPABILITY_ID, ARBITER_FORMATION_CAPABILITIES, ARBITER_FORMATION_PACK_ID,
    ArbiterFormationCapability, ArbiterFormationCapabilityKind, HITL_GATE_CAPABILITY_ID,
    POLICY_GATE_CAPABILITY_ID, find_formation_capability, formation_capabilities,
};
pub use provenance::{ARBITER_PROVENANCE, Arbiter};
#[cfg(feature = "analysis")]
pub use suggestor::CedarAnalysisSuggestor;
pub use suggestor::{
    ApprovalConstraintPayload, ApprovalGateStatus, ApprovalGateSuggestor, ApprovalRiskPayload,
    BudgetConstraintPayload, BudgetGateSuggestor, CedarHitlGateSuggestor, ComplianceCondition,
    ComplianceConstraintPayload, ComplianceDocumentPayload, ComplianceGateSuggestor,
    ComplianceRule, CostEstimatePayload, DataClassificationConstraintPayload,
    DataClassificationGateSuggestor, DelegationVerificationPayload, DelegationVerifySuggestor,
    FlowGateSuggestor, GateConstraintAction, PolicyGateSuggestor, RateLimitConstraintPayload,
    RateLimitGateSuggestor,
};
pub use types::{ContextIn, DecideRequest, PrincipalIn, ResourceIn};

/// Built-in Cedar policies for reference and testing.
pub const EXPENSE_APPROVAL_POLICY: &str = include_str!("../policies/expense_approval.cedar");
pub const EXPENSE_APPROVAL_SCHEMA: &str = include_str!("../schemas/expense_approval.cedarschema");
pub const FLOW_GOVERNANCE_POLICY: &str = include_str!("../policies/flow_governance.cedar");
pub const VENDOR_SELECTION_POLICY: &str = include_str!("../policies/vendor_selection.cedar");

// ── Supporting types (needed by consumers for construction/evaluation) ─

pub mod decision;
pub mod delegation;
pub mod flow;

pub use converge_core::{
    FlowAction, FlowGateAuthorizer, FlowGateDecision, FlowGateError, FlowGateInput, FlowGateOutcome,
};
pub use decision::{PolicyDecision, PolicyOutcome};
pub use delegation::Delegation;
