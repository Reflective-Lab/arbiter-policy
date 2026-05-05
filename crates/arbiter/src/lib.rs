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

// ── Public API: Suggestors + construction types ───────────────────────

pub mod engine;
pub mod suggestor;
pub mod types;

pub use engine::PolicyEngine;
pub use suggestor::{
    ApprovalGateSuggestor, BudgetGateSuggestor, ComplianceCondition, ComplianceGateSuggestor,
    ComplianceRule, DataClassificationGateSuggestor, DelegationVerifySuggestor, FlowGateSuggestor,
    PolicyGateSuggestor, RateLimitGateSuggestor,
};
pub use types::{ContextIn, DecideRequest, PrincipalIn, ResourceIn};

/// Built-in Cedar policies for reference and testing.
pub const EXPENSE_APPROVAL_POLICY: &str = include_str!("../policies/expense_approval.cedar");
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
