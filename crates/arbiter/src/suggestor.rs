use std::sync::Arc;

use converge_core::FlowGateInput;
use converge_pack::{
    AgentEffect, Context, ContextKey, DiagnosticPayload, FactId, FactPayload, ProposalId,
    Suggestor, fact::ProposedFact,
};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

#[cfg(feature = "analysis")]
use crate::analysis::{
    CedarAnalysisBackend, CedarAnalysisExecutionStatus, CedarAnalysisInput, CedarAnalysisReport,
};
use converge_pack::ProvenanceSource;

use crate::delegation;
use crate::engine::PolicyEngine;
use crate::provenance::{ARBITER_PROVENANCE, Arbiter};
use crate::types::DecideRequest;

const PROVENANCE_SOURCE: Arbiter = ARBITER_PROVENANCE;
const POLICY_GATE_NAME: &str = "policy-gate";
const DELEGATION_VERIFY_NAME: &str = "delegation-verify";
const CEDAR_HITL_GATE_NAME: &str = "cedar-hitl-gate";
const FLOW_GATE_NAME: &str = "flow-gate";
const RATE_LIMIT_GATE_NAME: &str = "rate-limit-gate";
const BUDGET_GATE_NAME: &str = "budget-gate";
const APPROVAL_GATE_NAME: &str = "approval-gate";
const DATA_CLASSIFICATION_GATE_NAME: &str = "data-classification-gate";
const COMPLIANCE_GATE_NAME: &str = "compliance-gate";
#[cfg(feature = "analysis")]
const CEDAR_ANALYSIS_NAME: &str = "cedar-analysis";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateConstraintAction {
    Block,
    Pause,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalGateStatus {
    PendingHumanReview,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CostEstimatePayload {
    pub cost: f64,
}

impl FactPayload for CostEstimatePayload {
    const FAMILY: &'static str = "arbiter.cost_estimate";
    const VERSION: u16 = 1;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRiskPayload {
    pub confidence: f64,
}

impl FactPayload for ApprovalRiskPayload {
    const FAMILY: &'static str = "arbiter.approval_risk";
    const VERSION: u16 = 1;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComplianceDocumentPayload {
    pub fields: serde_json::Map<String, serde_json::Value>,
}

impl FactPayload for ComplianceDocumentPayload {
    const FAMILY: &'static str = "arbiter.compliance_document";
    const VERSION: u16 = 1;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationVerificationPayload {
    pub valid: bool,
    pub reason: Option<String>,
}

impl FactPayload for DelegationVerificationPayload {
    const FAMILY: &'static str = "arbiter.delegation_verification";
    const VERSION: u16 = 1;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConstraintPayload {
    pub key: ContextKey,
    pub count: usize,
    pub limit: usize,
    pub action: GateConstraintAction,
}

impl FactPayload for RateLimitConstraintPayload {
    const FAMILY: &'static str = "arbiter.constraint.rate_limit";
    const VERSION: u16 = 1;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetConstraintPayload {
    pub total_cost: f64,
    pub limit: f64,
    pub action: GateConstraintAction,
}

impl FactPayload for BudgetConstraintPayload {
    const FAMILY: &'static str = "arbiter.constraint.budget";
    const VERSION: u16 = 1;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalConstraintPayload {
    pub status: ApprovalGateStatus,
    pub threshold: f64,
    pub action: GateConstraintAction,
}

impl FactPayload for ApprovalConstraintPayload {
    const FAMILY: &'static str = "arbiter.constraint.approval";
    const VERSION: u16 = 1;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataClassificationConstraintPayload {
    pub fact_id: FactId,
    pub detected_types: Vec<String>,
    pub action: GateConstraintAction,
}

impl FactPayload for DataClassificationConstraintPayload {
    const FAMILY: &'static str = "arbiter.constraint.data_classification";
    const VERSION: u16 = 1;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComplianceConstraintPayload {
    pub rule_id: String,
    pub framework: String,
    pub fact_id: FactId,
    pub field: String,
    pub action: GateConstraintAction,
}

impl FactPayload for ComplianceConstraintPayload {
    const FAMILY: &'static str = "arbiter.constraint.compliance";
    const VERSION: u16 = 1;
}

fn proposed_fact(
    key: ContextKey,
    id: impl Into<ProposalId>,
    payload: impl FactPayload + PartialEq,
) -> ProposedFact {
    PROVENANCE_SOURCE.proposed_fact(key, id, payload)
}

#[cfg(feature = "analysis")]
fn diagnostic(id: impl Into<ProposalId>, message: impl Into<String>) -> ProposedFact {
    proposed_fact(
        ContextKey::Diagnostic,
        id,
        DiagnosticPayload::new("arbiter", message.into()),
    )
}

#[cfg(feature = "analysis")]
fn analysis_confidence(report: &CedarAnalysisReport) -> f64 {
    match report.status {
        CedarAnalysisExecutionStatus::NoViolation
        | CedarAnalysisExecutionStatus::CounterexampleFound => 0.9,
        CedarAnalysisExecutionStatus::Unknown => 0.2,
        CedarAnalysisExecutionStatus::Error => 0.0,
    }
}

// --- CedarAnalysisSuggestor ---

#[cfg(feature = "analysis")]
pub struct CedarAnalysisSuggestor<B> {
    backend: B,
    input_key: ContextKey,
    output_key: ContextKey,
}

#[cfg(feature = "analysis")]
impl<B> CedarAnalysisSuggestor<B>
where
    B: CedarAnalysisBackend,
{
    #[must_use]
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            input_key: ContextKey::Seeds,
            output_key: ContextKey::Evaluations,
        }
    }

    #[must_use]
    pub fn with_keys(mut self, input_key: ContextKey, output_key: ContextKey) -> Self {
        self.input_key = input_key;
        self.output_key = output_key;
        self
    }
}

#[cfg(feature = "analysis")]
#[async_trait::async_trait]
impl<B> Suggestor for CedarAnalysisSuggestor<B>
where
    B: CedarAnalysisBackend + 'static,
{
    fn name(&self) -> &'static str {
        CEDAR_ANALYSIS_NAME
    }

    fn dependencies(&self) -> &[ContextKey] {
        std::slice::from_ref(&self.input_key)
    }

    fn accepts(&self, ctx: &dyn Context) -> bool {
        ctx.has(self.input_key) && !ctx.has(self.output_key)
    }

    fn provenance(&self) -> &'static str {
        ARBITER_PROVENANCE.as_str()
    }

    async fn execute(&self, ctx: &dyn Context) -> AgentEffect {
        let mut proposals = Vec::new();
        let mut inputs = Vec::new();
        for fact in ctx.get(self.input_key) {
            match fact.require_payload::<CedarAnalysisInput>() {
                Ok(input) => inputs.push(input.clone()),
                Err(err) => {
                    proposals.push(diagnostic(
                        format!("cedar-analysis-parse-error-{}", fact.id()),
                        format!("expected CedarAnalysisInput payload: {err}"),
                    ));
                }
            }
        }

        for input in inputs {
            match self.backend.analyze(&input).await {
                Ok(report) => proposals.push(
                    proposed_fact(
                        self.output_key,
                        format!("cedar-analysis-report-{}", report.plan.invariant_id),
                        report.clone(),
                    )
                    .with_confidence(analysis_confidence(&report)),
                ),
                Err(err) => proposals.push(diagnostic(
                    format!("cedar-analysis-backend-error-{}", input.invariant_id),
                    format!(
                        "Cedar Analysis backend {} failed: {err}",
                        self.backend.name()
                    ),
                )),
            }
        }

        AgentEffect::with_proposals(proposals)
    }
}

// --- PolicyGateSuggestor ---

pub struct PolicyGateSuggestor {
    engine: Arc<PolicyEngine>,
    input_key: ContextKey,
    output_key: ContextKey,
}

impl PolicyGateSuggestor {
    #[must_use]
    pub fn new(engine: Arc<PolicyEngine>) -> Self {
        Self {
            engine,
            input_key: ContextKey::Seeds,
            output_key: ContextKey::Constraints,
        }
    }

    #[must_use]
    pub fn with_keys(
        engine: Arc<PolicyEngine>,
        input_key: ContextKey,
        output_key: ContextKey,
    ) -> Self {
        Self {
            engine,
            input_key,
            output_key,
        }
    }
}

#[async_trait::async_trait]
impl Suggestor for PolicyGateSuggestor {
    fn name(&self) -> &'static str {
        POLICY_GATE_NAME
    }

    fn dependencies(&self) -> &[ContextKey] {
        std::slice::from_ref(&self.input_key)
    }

    fn accepts(&self, ctx: &dyn Context) -> bool {
        ctx.has(self.input_key) && !ctx.has(self.output_key)
    }

    fn provenance(&self) -> &'static str {
        ARBITER_PROVENANCE.as_str()
    }

    async fn execute(&self, ctx: &dyn Context) -> AgentEffect {
        let facts = ctx.get(self.input_key);
        let Some(seed) = facts.first() else {
            return AgentEffect::empty();
        };

        let req: DecideRequest = match seed.require_payload::<DecideRequest>() {
            Ok(r) => r.clone(),
            Err(e) => {
                let diag = proposed_fact(
                    ContextKey::Diagnostic,
                    "policy-gate-error",
                    DiagnosticPayload::new(
                        "arbiter",
                        format!("expected DecideRequest payload: {e}"),
                    ),
                );
                return AgentEffect::with_proposal(diag);
            }
        };

        match self.engine.evaluate(&req) {
            Ok(decision) => {
                let proposal = proposed_fact(self.output_key, "policy-decision", decision);
                AgentEffect::with_proposal(proposal)
            }
            Err(e) => {
                let diag = proposed_fact(
                    ContextKey::Diagnostic,
                    "policy-gate-error",
                    DiagnosticPayload::new("arbiter", format!("policy evaluation failed: {e}")),
                );
                AgentEffect::with_proposal(diag)
            }
        }
    }
}

// --- DelegationVerifySuggestor ---

#[allow(clippy::struct_field_names)]
pub struct DelegationVerifySuggestor {
    verifying_key: VerifyingKey,
    input_key: ContextKey,
    output_key: ContextKey,
}

impl DelegationVerifySuggestor {
    #[must_use]
    pub fn new(verifying_key: VerifyingKey) -> Self {
        Self {
            verifying_key,
            input_key: ContextKey::Seeds,
            output_key: ContextKey::Constraints,
        }
    }

    #[must_use]
    pub fn with_keys(
        verifying_key: VerifyingKey,
        input_key: ContextKey,
        output_key: ContextKey,
    ) -> Self {
        Self {
            verifying_key,
            input_key,
            output_key,
        }
    }
}

#[async_trait::async_trait]
impl Suggestor for DelegationVerifySuggestor {
    fn name(&self) -> &'static str {
        DELEGATION_VERIFY_NAME
    }

    fn dependencies(&self) -> &[ContextKey] {
        std::slice::from_ref(&self.input_key)
    }

    fn accepts(&self, ctx: &dyn Context) -> bool {
        ctx.has(self.input_key) && !ctx.has(self.output_key)
    }

    fn provenance(&self) -> &'static str {
        ARBITER_PROVENANCE.as_str()
    }

    async fn execute(&self, ctx: &dyn Context) -> AgentEffect {
        let facts = ctx.get(self.input_key);
        let Some(seed) = facts.first() else {
            return AgentEffect::empty();
        };

        let req: DecideRequest = match seed.require_payload::<DecideRequest>() {
            Ok(r) => r.clone(),
            Err(e) => {
                let diag = proposed_fact(
                    ContextKey::Diagnostic,
                    "delegation-verify-error",
                    DiagnosticPayload::new(
                        "arbiter",
                        format!("expected DecideRequest payload: {e}"),
                    ),
                );
                return AgentEffect::with_proposal(diag);
            }
        };

        let Some(ref token_b64) = req.delegation_b64 else {
            let diag = proposed_fact(
                ContextKey::Diagnostic,
                "delegation-verify-error",
                DiagnosticPayload::new("arbiter", "no delegation_b64 in request"),
            );
            return AgentEffect::with_proposal(diag);
        };

        match delegation::verify(token_b64, &self.verifying_key, &req) {
            Ok(valid) => {
                let proposal = proposed_fact(
                    self.output_key,
                    "delegation-result",
                    DelegationVerificationPayload {
                        valid,
                        reason: (!valid).then(|| "constraints not met".to_string()),
                    },
                );
                AgentEffect::with_proposal(proposal)
            }
            Err(e) => {
                let proposal = proposed_fact(
                    self.output_key,
                    "delegation-result",
                    DelegationVerificationPayload {
                        valid: false,
                        reason: Some(e),
                    },
                );
                AgentEffect::with_proposal(proposal)
            }
        }
    }
}

fn execute_flow_gate(
    engine: &PolicyEngine,
    input_key: ContextKey,
    output_key: ContextKey,
    proposal_id: &'static str,
    error_id: &'static str,
    ctx: &dyn Context,
) -> AgentEffect {
    let facts = ctx.get(input_key);
    let Some(seed) = facts.first() else {
        return AgentEffect::empty();
    };

    let input: FlowGateInput = match seed.require_payload::<FlowGateInput>() {
        Ok(i) => i.clone(),
        Err(e) => {
            let diag = proposed_fact(
                ContextKey::Diagnostic,
                error_id,
                DiagnosticPayload::new("arbiter", format!("expected FlowGateInput payload: {e}")),
            );
            return AgentEffect::with_proposal(diag);
        }
    };

    match engine.evaluate_flow(&input) {
        Ok(decision) => {
            let proposal = proposed_fact(output_key, proposal_id, decision);
            AgentEffect::with_proposal(proposal)
        }
        Err(e) => {
            let diag = proposed_fact(
                ContextKey::Diagnostic,
                error_id,
                DiagnosticPayload::new("arbiter", format!("flow gate evaluation failed: {e}")),
            );
            AgentEffect::with_proposal(diag)
        }
    }
}

// --- CedarHitlGateSuggestor ---

/// Named Cedar HITL gate surface for Formation registration.
///
/// This is intentionally the same Cedar flow authorization path as
/// [`FlowGateSuggestor`], but exposed under a stricter, discoverable name for
/// high-risk human-in-the-loop gates. Escalation is emitted only when Cedar
/// denies the original request and allows the same request with
/// `human_approval_present = true`.
pub struct CedarHitlGateSuggestor {
    engine: Arc<PolicyEngine>,
    input_key: ContextKey,
    output_key: ContextKey,
}

impl CedarHitlGateSuggestor {
    #[must_use]
    pub fn new(engine: Arc<PolicyEngine>) -> Self {
        Self {
            engine,
            input_key: ContextKey::Seeds,
            output_key: ContextKey::Constraints,
        }
    }

    #[must_use]
    pub fn with_keys(
        engine: Arc<PolicyEngine>,
        input_key: ContextKey,
        output_key: ContextKey,
    ) -> Self {
        Self {
            engine,
            input_key,
            output_key,
        }
    }
}

#[async_trait::async_trait]
impl Suggestor for CedarHitlGateSuggestor {
    fn name(&self) -> &'static str {
        CEDAR_HITL_GATE_NAME
    }

    fn dependencies(&self) -> &[ContextKey] {
        std::slice::from_ref(&self.input_key)
    }

    fn accepts(&self, ctx: &dyn Context) -> bool {
        ctx.has(self.input_key) && !ctx.has(self.output_key)
    }

    fn provenance(&self) -> &'static str {
        ARBITER_PROVENANCE.as_str()
    }

    async fn execute(&self, ctx: &dyn Context) -> AgentEffect {
        execute_flow_gate(
            self.engine.as_ref(),
            self.input_key,
            self.output_key,
            "cedar-hitl-gate-decision",
            "cedar-hitl-gate-error",
            ctx,
        )
    }
}

// --- FlowGateSuggestor ---

pub struct FlowGateSuggestor {
    engine: Arc<PolicyEngine>,
    input_key: ContextKey,
    output_key: ContextKey,
}

impl FlowGateSuggestor {
    #[must_use]
    pub fn new(engine: Arc<PolicyEngine>) -> Self {
        Self {
            engine,
            input_key: ContextKey::Seeds,
            output_key: ContextKey::Constraints,
        }
    }

    #[must_use]
    pub fn with_keys(
        engine: Arc<PolicyEngine>,
        input_key: ContextKey,
        output_key: ContextKey,
    ) -> Self {
        Self {
            engine,
            input_key,
            output_key,
        }
    }
}

#[async_trait::async_trait]
impl Suggestor for FlowGateSuggestor {
    fn name(&self) -> &'static str {
        FLOW_GATE_NAME
    }

    fn dependencies(&self) -> &[ContextKey] {
        std::slice::from_ref(&self.input_key)
    }

    fn accepts(&self, ctx: &dyn Context) -> bool {
        ctx.has(self.input_key) && !ctx.has(self.output_key)
    }

    fn provenance(&self) -> &'static str {
        ARBITER_PROVENANCE.as_str()
    }

    async fn execute(&self, ctx: &dyn Context) -> AgentEffect {
        execute_flow_gate(
            self.engine.as_ref(),
            self.input_key,
            self.output_key,
            "flow-gate-decision",
            "flow-gate-error",
            ctx,
        )
    }
}

// --- RateLimitGateSuggestor ---

/// Throttles agent activity by counting proposals per key per convergence run.
/// If the count exceeds the limit, emits a constraint blocking further proposals.
pub struct RateLimitGateSuggestor {
    max_proposals_per_key: usize,
    watched_key: ContextKey,
}

impl RateLimitGateSuggestor {
    #[must_use]
    pub fn new(watched_key: ContextKey, max_proposals_per_key: usize) -> Self {
        Self {
            max_proposals_per_key,
            watched_key,
        }
    }
}

#[async_trait::async_trait]
impl Suggestor for RateLimitGateSuggestor {
    fn name(&self) -> &'static str {
        RATE_LIMIT_GATE_NAME
    }

    fn dependencies(&self) -> &[ContextKey] {
        std::slice::from_ref(&self.watched_key)
    }

    fn accepts(&self, ctx: &dyn Context) -> bool {
        ctx.count(self.watched_key) > self.max_proposals_per_key
            && !ctx
                .get(ContextKey::Constraints)
                .iter()
                .any(|f| f.id() == "rate-limit-exceeded")
    }

    fn provenance(&self) -> &'static str {
        ARBITER_PROVENANCE.as_str()
    }

    async fn execute(&self, ctx: &dyn Context) -> AgentEffect {
        let count = ctx.count(self.watched_key);
        AgentEffect::with_proposal(proposed_fact(
            ContextKey::Constraints,
            "rate-limit-exceeded",
            RateLimitConstraintPayload {
                key: self.watched_key,
                count,
                limit: self.max_proposals_per_key,
                action: GateConstraintAction::Block,
            },
        ))
    }
}

// --- BudgetGateSuggestor ---

/// Enforces a cost/token budget within a convergence run.
/// Reads cost estimates from proposals and blocks when cumulative cost exceeds the limit.
pub struct BudgetGateSuggestor {
    max_cost: f64,
    cost_key: ContextKey,
}

impl BudgetGateSuggestor {
    #[must_use]
    pub fn new(cost_key: ContextKey, max_cost: f64) -> Self {
        Self { max_cost, cost_key }
    }
}

#[async_trait::async_trait]
impl Suggestor for BudgetGateSuggestor {
    fn name(&self) -> &'static str {
        BUDGET_GATE_NAME
    }

    fn dependencies(&self) -> &[ContextKey] {
        std::slice::from_ref(&self.cost_key)
    }

    fn accepts(&self, ctx: &dyn Context) -> bool {
        ctx.has(self.cost_key)
            && !ctx
                .get(ContextKey::Constraints)
                .iter()
                .any(|f| f.id() == "budget-exceeded")
    }

    fn provenance(&self) -> &'static str {
        ARBITER_PROVENANCE.as_str()
    }

    async fn execute(&self, ctx: &dyn Context) -> AgentEffect {
        let facts = ctx.get(self.cost_key);
        let total_cost: f64 = facts
            .iter()
            .filter_map(|fact| {
                fact.payload::<CostEstimatePayload>()
                    .map(|payload| payload.cost)
            })
            .sum();

        if total_cost > self.max_cost {
            AgentEffect::with_proposal(proposed_fact(
                ContextKey::Constraints,
                "budget-exceeded",
                BudgetConstraintPayload {
                    total_cost,
                    limit: self.max_cost,
                    action: GateConstraintAction::Block,
                },
            ))
        } else {
            AgentEffect::empty()
        }
    }
}

// --- ApprovalGateSuggestor ---

/// Requires human-in-the-loop approval for high-stakes proposals.
/// Blocks proposals matching a predicate until an approval fact appears.
pub struct ApprovalGateSuggestor {
    watched_key: ContextKey,
    approval_key: ContextKey,
    stakes_threshold: f64,
}

impl ApprovalGateSuggestor {
    /// Gate proposals on `watched_key` that have confidence above `stakes_threshold`.
    /// Approval is signaled by a fact in `approval_key`.
    #[must_use]
    pub fn new(watched_key: ContextKey, stakes_threshold: f64) -> Self {
        Self {
            watched_key,
            approval_key: ContextKey::Signals,
            stakes_threshold,
        }
    }

    #[must_use]
    pub fn with_approval_key(mut self, key: ContextKey) -> Self {
        self.approval_key = key;
        self
    }
}

#[async_trait::async_trait]
impl Suggestor for ApprovalGateSuggestor {
    fn name(&self) -> &'static str {
        APPROVAL_GATE_NAME
    }

    fn dependencies(&self) -> &[ContextKey] {
        std::slice::from_ref(&self.watched_key)
    }

    fn accepts(&self, ctx: &dyn Context) -> bool {
        ctx.has(self.watched_key)
            && !ctx.has(self.approval_key)
            && !ctx
                .get(ContextKey::Constraints)
                .iter()
                .any(|f| f.id() == "approval-pending")
    }

    fn provenance(&self) -> &'static str {
        ARBITER_PROVENANCE.as_str()
    }

    async fn execute(&self, ctx: &dyn Context) -> AgentEffect {
        let facts = ctx.get(self.watched_key);
        let needs_approval = facts.iter().any(|f| {
            f.payload::<ApprovalRiskPayload>()
                .is_none_or(|payload| payload.confidence >= self.stakes_threshold)
        });

        if needs_approval {
            AgentEffect::with_proposal(proposed_fact(
                ContextKey::Constraints,
                "approval-pending",
                ApprovalConstraintPayload {
                    status: ApprovalGateStatus::PendingHumanReview,
                    threshold: self.stakes_threshold,
                    action: GateConstraintAction::Pause,
                },
            ))
        } else {
            AgentEffect::empty()
        }
    }
}

// --- DataClassificationGateSuggestor ---

/// Blocks proposals containing PII or sensitive data patterns from crossing boundaries.
/// Scans proposal content for configurable patterns (emails, SSNs, credit cards, etc.).
pub struct DataClassificationGateSuggestor {
    watched_key: ContextKey,
    patterns: Vec<(&'static str, regex::Regex)>,
}

impl DataClassificationGateSuggestor {
    /// Create with default PII patterns (email, SSN, credit card).
    #[must_use]
    pub fn default_patterns(watched_key: ContextKey) -> Self {
        Self {
            watched_key,
            patterns: vec![
                (
                    "email",
                    regex::Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
                        .expect("valid regex"),
                ),
                (
                    "ssn",
                    regex::Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("valid regex"),
                ),
                (
                    "credit_card",
                    regex::Regex::new(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b")
                        .expect("valid regex"),
                ),
                (
                    "phone",
                    regex::Regex::new(r"\b\+?\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
                        .expect("valid regex"),
                ),
            ],
        }
    }
}

#[async_trait::async_trait]
impl Suggestor for DataClassificationGateSuggestor {
    fn name(&self) -> &'static str {
        DATA_CLASSIFICATION_GATE_NAME
    }

    fn dependencies(&self) -> &[ContextKey] {
        std::slice::from_ref(&self.watched_key)
    }

    fn accepts(&self, ctx: &dyn Context) -> bool {
        ctx.has(self.watched_key)
            && !ctx
                .get(ContextKey::Constraints)
                .iter()
                .any(|f| f.id().as_str().starts_with("pii-detected-"))
    }

    fn provenance(&self) -> &'static str {
        ARBITER_PROVENANCE.as_str()
    }

    async fn execute(&self, ctx: &dyn Context) -> AgentEffect {
        let facts = ctx.get(self.watched_key);
        let mut proposals = Vec::new();

        for fact in facts {
            let mut detected = Vec::new();
            for (label, pattern) in &self.patterns {
                if fact.text().is_some_and(|content| pattern.is_match(content)) {
                    detected.push(*label);
                }
            }
            if !detected.is_empty() {
                proposals.push(proposed_fact(
                    ContextKey::Constraints,
                    format!("pii-detected-{}", fact.id()),
                    DataClassificationConstraintPayload {
                        fact_id: fact.id().clone(),
                        detected_types: detected.into_iter().map(str::to_string).collect(),
                        action: GateConstraintAction::Block,
                    },
                ));
            }
        }

        AgentEffect::with_proposals(proposals)
    }
}

// --- ComplianceGateSuggestor ---

/// Checks proposals against compliance requirements (GDPR, SOC2, HIPAA, etc.).
/// Configurable with compliance rules that map to constraint violations.
pub struct ComplianceGateSuggestor {
    watched_key: ContextKey,
    rules: Vec<ComplianceRule>,
}

/// A compliance rule that checks a condition and produces a violation if met.
pub struct ComplianceRule {
    /// Rule identifier (e.g., "gdpr-data-retention").
    pub id: String,
    /// Compliance framework (e.g., "GDPR", "SOC2", "HIPAA").
    pub framework: String,
    /// JSON path to check in proposal content.
    pub field: String,
    /// Condition that triggers a violation.
    pub condition: ComplianceCondition,
}

/// What triggers a compliance violation.
pub enum ComplianceCondition {
    /// Field must not be present.
    FieldMustNotExist,
    /// Field value must not exceed this numeric threshold.
    MaxValue(f64),
    /// Field value must not contain these strings.
    MustNotContain(Vec<String>),
}

impl ComplianceGateSuggestor {
    #[must_use]
    pub fn new(watched_key: ContextKey, rules: Vec<ComplianceRule>) -> Self {
        Self { watched_key, rules }
    }
}

#[async_trait::async_trait]
impl Suggestor for ComplianceGateSuggestor {
    fn name(&self) -> &'static str {
        COMPLIANCE_GATE_NAME
    }

    fn dependencies(&self) -> &[ContextKey] {
        std::slice::from_ref(&self.watched_key)
    }

    fn accepts(&self, ctx: &dyn Context) -> bool {
        ctx.has(self.watched_key)
            && !ctx
                .get(ContextKey::Constraints)
                .iter()
                .any(|f| f.id().as_str().starts_with("compliance-"))
    }

    fn provenance(&self) -> &'static str {
        ARBITER_PROVENANCE.as_str()
    }

    async fn execute(&self, ctx: &dyn Context) -> AgentEffect {
        let facts = ctx.get(self.watched_key);
        let mut proposals = Vec::new();

        for fact in facts {
            let Some(value) = fact.payload::<ComplianceDocumentPayload>() else {
                continue;
            };

            for rule in &self.rules {
                let violated = match &rule.condition {
                    ComplianceCondition::FieldMustNotExist => {
                        value.fields.get(&rule.field).is_some()
                    }
                    ComplianceCondition::MaxValue(max) => value
                        .fields
                        .get(&rule.field)
                        .and_then(serde_json::Value::as_f64)
                        .is_some_and(|v| v > *max),
                    ComplianceCondition::MustNotContain(forbidden) => value
                        .fields
                        .get(&rule.field)
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| forbidden.iter().any(|f| s.contains(f.as_str()))),
                };

                if violated {
                    proposals.push(proposed_fact(
                        ContextKey::Constraints,
                        format!("compliance-{}-{}", rule.id, fact.id()),
                        ComplianceConstraintPayload {
                            rule_id: rule.id.clone(),
                            framework: rule.framework.clone(),
                            fact_id: fact.id().clone(),
                            field: rule.field.clone(),
                            action: GateConstraintAction::Block,
                        },
                    ));
                }
            }
        }

        AgentEffect::with_proposals(proposals)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use converge_core::{
        AuthorityLevel, FlowAction, FlowGateContext, FlowGatePrincipal, FlowGateResource, FlowPhase,
    };
    use converge_pack::{
        ContentHash, ContextFact, FactActor, FactActorKind, FactLocalTrace, FactPayload,
        FactPromotionRecord, FactTraceLink, FactValidationSummary, TextPayload, Timestamp,
    };
    use std::collections::HashMap;

    #[cfg(feature = "analysis")]
    #[derive(Debug, Clone, Copy)]
    struct FixedAnalysisBackend {
        status: crate::analysis::CedarAnalysisExecutionStatus,
    }

    #[cfg(feature = "analysis")]
    #[async_trait::async_trait]
    impl crate::analysis::CedarAnalysisBackend for FixedAnalysisBackend {
        fn name(&self) -> &'static str {
            "fixed-analysis"
        }

        async fn analyze(
            &self,
            input: &crate::analysis::CedarAnalysisInput,
        ) -> Result<crate::analysis::CedarAnalysisReport, crate::analysis::CedarAnalysisError>
        {
            let plan = crate::analysis::compile_analysis_plan(input)?;
            Ok(crate::analysis::CedarAnalysisReport {
                plan,
                execution_identity: converge_pack::ExecutionIdentity::non_native(
                    env!("CARGO_PKG_NAME"),
                    env!("CARGO_PKG_VERSION"),
                    self.name(),
                    format!(
                        "invariant_id={}; status={:?}",
                        input.invariant_id, self.status
                    ),
                ),
                status: self.status,
                checks: Vec::new(),
            })
        }
    }

    struct MockContext {
        facts: HashMap<ContextKey, Vec<ContextFact>>,
    }

    impl MockContext {
        fn empty() -> Self {
            Self {
                facts: HashMap::new(),
            }
        }
    }

    fn context_fact(
        key: ContextKey,
        id: impl Into<converge_pack::FactId>,
        payload: impl FactPayload + PartialEq,
    ) -> ContextFact {
        ContextFact::new_projection(
            key,
            id,
            payload,
            FactPromotionRecord::new_projection(
                "policy-test",
                ContentHash::zero(),
                FactActor::new_projection("policy-test", FactActorKind::System),
                FactValidationSummary::default(),
                Vec::new(),
                FactTraceLink::Local(FactLocalTrace::new_projection(
                    "policy-test",
                    "policy-test",
                    None,
                    true,
                )),
                Timestamp::epoch(),
            ),
            Timestamp::epoch(),
        )
    }

    impl Context for MockContext {
        fn has(&self, key: ContextKey) -> bool {
            self.facts.get(&key).is_some_and(|v| !v.is_empty())
        }

        fn get(&self, key: ContextKey) -> &[ContextFact] {
            self.facts.get(&key).map_or(&[], Vec::as_slice)
        }
    }

    #[test]
    fn policy_gate_name() {
        let engine = Arc::new(
            PolicyEngine::from_policy_str("permit(principal, action, resource);").unwrap(),
        );
        let s = PolicyGateSuggestor::new(engine);
        assert_eq!(s.name(), "policy-gate");
    }

    #[test]
    fn policy_gate_dependencies() {
        let engine = Arc::new(
            PolicyEngine::from_policy_str("permit(principal, action, resource);").unwrap(),
        );
        let s = PolicyGateSuggestor::new(engine);
        assert_eq!(s.dependencies(), &[ContextKey::Seeds]);
    }

    #[test]
    fn policy_gate_rejects_empty_context() {
        let engine = Arc::new(
            PolicyEngine::from_policy_str("permit(principal, action, resource);").unwrap(),
        );
        let s = PolicyGateSuggestor::new(engine);
        let ctx = MockContext::empty();
        assert!(!s.accepts(&ctx));
    }

    #[test]
    fn delegation_verify_name() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]).verifying_key();
        let s = DelegationVerifySuggestor::new(key);
        assert_eq!(s.name(), "delegation-verify");
    }

    #[test]
    fn flow_gate_name() {
        let engine = Arc::new(
            PolicyEngine::from_policy_str("permit(principal, action, resource);").unwrap(),
        );
        let s = FlowGateSuggestor::new(engine);
        assert_eq!(s.name(), "flow-gate");
    }

    #[test]
    fn cedar_hitl_gate_name_and_deps() {
        let engine = Arc::new(
            PolicyEngine::from_policy_str("permit(principal, action, resource);").unwrap(),
        );
        let s = CedarHitlGateSuggestor::new(engine);
        assert_eq!(s.name(), "cedar-hitl-gate");
        assert_eq!(s.dependencies(), &[ContextKey::Seeds]);
    }

    #[cfg(feature = "analysis")]
    #[test]
    fn cedar_analysis_suggestor_name_and_deps() {
        let s = CedarAnalysisSuggestor::new(FixedAnalysisBackend {
            status: crate::analysis::CedarAnalysisExecutionStatus::NoViolation,
        });

        assert_eq!(s.name(), "cedar-analysis");
        assert_eq!(s.dependencies(), &[ContextKey::Seeds]);
    }

    #[test]
    fn flow_gate_rejects_empty_context() {
        let engine = Arc::new(
            PolicyEngine::from_policy_str("permit(principal, action, resource);").unwrap(),
        );
        let s = FlowGateSuggestor::new(engine);
        let ctx = MockContext::empty();
        assert!(!s.accepts(&ctx));
    }

    #[tokio::test]
    async fn cedar_hitl_gate_emits_strict_escalation_decision() {
        let policy = r#"
            permit(principal, action == Action::"commit", resource)
            when { context.human_approval_present == true };
        "#;
        let engine = Arc::new(PolicyEngine::from_policy_str(policy).unwrap());
        let s = CedarHitlGateSuggestor::new(engine);
        let input = FlowGateInput {
            principal: FlowGatePrincipal {
                id: "agent:finance".into(),
                authority: AuthorityLevel::Supervisory,
                domains: vec!["finance".into()],
                policy_version: Some("expense_v1".into()),
            },
            resource: FlowGateResource {
                id: "expense:001".into(),
                kind: "expense".into(),
                phase: FlowPhase::Commitment,
                gates_passed: vec!["receipt".into()],
            },
            action: FlowAction::Commit,
            context: FlowGateContext {
                commitment_type: Some("expense".into()),
                amount: Some(1_250),
                human_approval_present: Some(false),
                required_gates_met: Some(true),
            },
        };

        let mut ctx = MockContext::empty();
        ctx.facts.insert(
            ContextKey::Seeds,
            vec![context_fact(ContextKey::Seeds, "flow-gate-input", input)],
        );

        assert!(s.accepts(&ctx));
        let effect = s.execute(&ctx).await;
        assert_eq!(effect.proposals().len(), 1);
        assert!(
            effect.proposals()[0]
                .id
                .contains("cedar-hitl-gate-decision")
        );

        let decision = effect.proposals()[0]
            .require_payload::<crate::PolicyDecision>()
            .unwrap();
        assert_eq!(decision.outcome, crate::PolicyOutcome::Escalate);
    }

    #[cfg(feature = "analysis")]
    #[tokio::test]
    async fn cedar_analysis_suggestor_emits_searched_report() {
        let s = CedarAnalysisSuggestor::new(FixedAnalysisBackend {
            status: crate::analysis::CedarAnalysisExecutionStatus::NoViolation,
        });
        let input = crate::analysis::CedarAnalysisInput::new(
            "expense.non_finance_commit.high_value",
            crate::analysis::CedarAnalysisQuery::ExpenseNonFinanceHighValueCommitDenied,
            crate::EXPENSE_APPROVAL_POLICY,
            crate::EXPENSE_APPROVAL_SCHEMA,
        );

        let mut ctx = MockContext::empty();
        ctx.facts.insert(
            ContextKey::Seeds,
            vec![context_fact(
                ContextKey::Seeds,
                "cedar-analysis-input",
                input,
            )],
        );

        assert!(s.accepts(&ctx));
        let effect = s.execute(&ctx).await;

        assert_eq!(effect.proposals().len(), 1);
        assert_eq!(effect.proposals()[0].key, ContextKey::Evaluations);
        assert_eq!(effect.proposals()[0].provenance(), "arbiter");
        let report = effect.proposals()[0]
            .require_payload::<crate::analysis::CedarAnalysisReport>()
            .unwrap();
        assert_eq!(
            report.status,
            crate::analysis::CedarAnalysisExecutionStatus::NoViolation
        );
        assert_eq!(
            report.plan.query,
            crate::analysis::CedarAnalysisQuery::ExpenseNonFinanceHighValueCommitDenied
        );
        assert_eq!(report.execution_identity.backend, "fixed-analysis");
        assert_eq!(
            report.execution_identity.producer.name,
            env!("CARGO_PKG_NAME")
        );
    }

    #[cfg(feature = "analysis")]
    #[tokio::test]
    async fn cedar_analysis_suggestor_routes_parse_errors_to_diagnostics() {
        let s = CedarAnalysisSuggestor::new(FixedAnalysisBackend {
            status: crate::analysis::CedarAnalysisExecutionStatus::NoViolation,
        });

        let mut ctx = MockContext::empty();
        ctx.facts.insert(
            ContextKey::Seeds,
            vec![context_fact(
                ContextKey::Seeds,
                "not-analysis-input",
                TextPayload::new("{not json"),
            )],
        );

        let effect = s.execute(&ctx).await;

        assert_eq!(effect.proposals().len(), 1);
        assert_eq!(effect.proposals()[0].key, ContextKey::Diagnostic);
        assert!(
            effect.proposals()[0]
                .id
                .contains("cedar-analysis-parse-error")
        );
    }

    // ── New gate tests ────────────────────────────────────────────

    #[test]
    fn rate_limit_gate_name_and_deps() {
        let s = RateLimitGateSuggestor::new(ContextKey::Strategies, 10);
        assert_eq!(s.name(), "rate-limit-gate");
        assert_eq!(s.dependencies(), &[ContextKey::Strategies]);
    }

    #[test]
    fn rate_limit_gate_rejects_empty() {
        let s = RateLimitGateSuggestor::new(ContextKey::Strategies, 5);
        let ctx = MockContext::empty();
        assert!(!s.accepts(&ctx));
    }

    #[test]
    fn budget_gate_name_and_deps() {
        let s = BudgetGateSuggestor::new(ContextKey::Strategies, 1000.0);
        assert_eq!(s.name(), "budget-gate");
        assert_eq!(s.dependencies(), &[ContextKey::Strategies]);
    }

    #[test]
    fn approval_gate_name_and_deps() {
        let s = ApprovalGateSuggestor::new(ContextKey::Strategies, 0.9);
        assert_eq!(s.name(), "approval-gate");
        assert_eq!(s.dependencies(), &[ContextKey::Strategies]);
    }

    #[test]
    fn data_classification_gate_name() {
        let s = DataClassificationGateSuggestor::default_patterns(ContextKey::Strategies);
        assert_eq!(s.name(), "data-classification-gate");
    }

    #[test]
    fn compliance_gate_name() {
        let rules = vec![ComplianceRule {
            id: "gdpr-retention".into(),
            framework: "GDPR".into(),
            field: "retention_days".into(),
            condition: ComplianceCondition::MaxValue(365.0),
        }];
        let s = ComplianceGateSuggestor::new(ContextKey::Strategies, rules);
        assert_eq!(s.name(), "compliance-gate");
    }

    #[tokio::test]
    async fn data_classification_detects_email() {
        let s = DataClassificationGateSuggestor::default_patterns(ContextKey::Strategies);

        let mut ctx = MockContext::empty();
        ctx.facts.insert(
            ContextKey::Strategies,
            vec![context_fact(
                ContextKey::Strategies,
                "strat-1",
                TextPayload::new("Contact john@example.com for details"),
            )],
        );

        assert!(s.accepts(&ctx));
        let effect = s.execute(&ctx).await;
        assert_eq!(effect.proposals().len(), 1);
        assert!(effect.proposals()[0].id.contains("pii-detected"));
    }

    #[tokio::test]
    async fn data_classification_passes_clean_content() {
        let s = DataClassificationGateSuggestor::default_patterns(ContextKey::Strategies);

        let mut ctx = MockContext::empty();
        ctx.facts.insert(
            ContextKey::Strategies,
            vec![context_fact(
                ContextKey::Strategies,
                "strat-1",
                TextPayload::new("Allocate budget across 4 departments"),
            )],
        );

        assert!(s.accepts(&ctx));
        let effect = s.execute(&ctx).await;
        assert!(effect.proposals().is_empty());
    }

    #[tokio::test]
    async fn budget_gate_blocks_over_limit() {
        let s = BudgetGateSuggestor::new(ContextKey::Strategies, 100.0);

        let mut ctx = MockContext::empty();
        ctx.facts.insert(
            ContextKey::Strategies,
            vec![
                context_fact(
                    ContextKey::Strategies,
                    "s1",
                    CostEstimatePayload { cost: 60.0 },
                ),
                context_fact(
                    ContextKey::Strategies,
                    "s2",
                    CostEstimatePayload { cost: 50.0 },
                ),
            ],
        );

        assert!(s.accepts(&ctx));
        let effect = s.execute(&ctx).await;
        assert_eq!(effect.proposals().len(), 1);
        assert!(effect.proposals()[0].id.contains("budget-exceeded"));
    }

    #[tokio::test]
    async fn budget_gate_allows_within_limit() {
        let s = BudgetGateSuggestor::new(ContextKey::Strategies, 200.0);

        let mut ctx = MockContext::empty();
        ctx.facts.insert(
            ContextKey::Strategies,
            vec![
                context_fact(
                    ContextKey::Strategies,
                    "s1",
                    CostEstimatePayload { cost: 60.0 },
                ),
                context_fact(
                    ContextKey::Strategies,
                    "s2",
                    CostEstimatePayload { cost: 50.0 },
                ),
            ],
        );

        assert!(s.accepts(&ctx));
        let effect = s.execute(&ctx).await;
        assert!(effect.proposals().is_empty());
    }
}
