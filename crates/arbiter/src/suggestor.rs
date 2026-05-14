use std::sync::Arc;

use converge_core::FlowGateInput;
use converge_pack::{AgentEffect, Context, ContextKey, ProposalId, Suggestor, fact::ProposedFact};
use ed25519_dalek::VerifyingKey;
use tracing::info_span;

use crate::delegation;
use crate::engine::PolicyEngine;
use crate::provenance::ProvenanceSource;
use crate::types::DecideRequest;

const PROVENANCE_SOURCE: ProvenanceSource = ProvenanceSource::Arbiter;
const POLICY_GATE_NAME: &str = "policy-gate";
const DELEGATION_VERIFY_NAME: &str = "delegation-verify";
const CEDAR_HITL_GATE_NAME: &str = "cedar-hitl-gate";
const FLOW_GATE_NAME: &str = "flow-gate";
const RATE_LIMIT_GATE_NAME: &str = "rate-limit-gate";
const BUDGET_GATE_NAME: &str = "budget-gate";
const APPROVAL_GATE_NAME: &str = "approval-gate";
const DATA_CLASSIFICATION_GATE_NAME: &str = "data-classification-gate";
const COMPLIANCE_GATE_NAME: &str = "compliance-gate";

fn proposed_fact(
    key: ContextKey,
    id: impl Into<ProposalId>,
    content: impl Into<String>,
) -> ProposedFact {
    PROVENANCE_SOURCE.proposed_fact(key, id, content)
}

fn suggestor_span(
    name: &'static str,
    input_key: ContextKey,
    output_key: ContextKey,
    input_count: usize,
) -> tracing::Span {
    info_span!(
        "arbiter.suggestor.execute",
        provenance = PROVENANCE_SOURCE.as_str(),
        suggestor = name,
        input_key = ?input_key,
        output_key = ?output_key,
        input_count
    )
}

fn watched_suggestor_span(
    name: &'static str,
    watched_key: ContextKey,
    output_key: ContextKey,
    input_count: usize,
) -> tracing::Span {
    info_span!(
        "arbiter.suggestor.execute",
        provenance = PROVENANCE_SOURCE.as_str(),
        suggestor = name,
        input_key = ?watched_key,
        output_key = ?output_key,
        watched_key = ?watched_key,
        input_count
    )
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

    async fn execute(&self, ctx: &dyn Context) -> AgentEffect {
        let _span = suggestor_span(
            POLICY_GATE_NAME,
            self.input_key,
            self.output_key,
            ctx.count(self.input_key),
        )
        .entered();
        let facts = ctx.get(self.input_key);
        let Some(seed) = facts.first() else {
            return AgentEffect::empty();
        };

        let req: DecideRequest = match serde_json::from_str(seed.content()) {
            Ok(r) => r,
            Err(e) => {
                let diag = proposed_fact(
                    ContextKey::Diagnostic,
                    "policy-gate-error",
                    format!("failed to parse DecideRequest: {e}"),
                );
                return AgentEffect::with_proposal(diag);
            }
        };

        match self.engine.evaluate(&req) {
            Ok(decision) => {
                let content = serde_json::to_string(&decision).unwrap_or_default();
                let proposal = proposed_fact(self.output_key, "policy-decision", content);
                AgentEffect::with_proposal(proposal)
            }
            Err(e) => {
                let diag = proposed_fact(
                    ContextKey::Diagnostic,
                    "policy-gate-error",
                    format!("policy evaluation failed: {e}"),
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

    async fn execute(&self, ctx: &dyn Context) -> AgentEffect {
        let _span = suggestor_span(
            DELEGATION_VERIFY_NAME,
            self.input_key,
            self.output_key,
            ctx.count(self.input_key),
        )
        .entered();
        let facts = ctx.get(self.input_key);
        let Some(seed) = facts.first() else {
            return AgentEffect::empty();
        };

        let req: DecideRequest = match serde_json::from_str(seed.content()) {
            Ok(r) => r,
            Err(e) => {
                let diag = proposed_fact(
                    ContextKey::Diagnostic,
                    "delegation-verify-error",
                    format!("failed to parse DecideRequest: {e}"),
                );
                return AgentEffect::with_proposal(diag);
            }
        };

        let Some(ref token_b64) = req.delegation_b64 else {
            let diag = proposed_fact(
                ContextKey::Diagnostic,
                "delegation-verify-error",
                "no delegation_b64 in request",
            );
            return AgentEffect::with_proposal(diag);
        };

        match delegation::verify(token_b64, &self.verifying_key, &req) {
            Ok(valid) => {
                let content = if valid {
                    r#"{"valid":true}"#.to_string()
                } else {
                    r#"{"valid":false,"reason":"constraints not met"}"#.to_string()
                };
                let proposal = proposed_fact(self.output_key, "delegation-result", content);
                AgentEffect::with_proposal(proposal)
            }
            Err(e) => {
                let content = format!(r#"{{"valid":false,"reason":"{e}"}}"#);
                let proposal = proposed_fact(self.output_key, "delegation-result", content);
                AgentEffect::with_proposal(proposal)
            }
        }
    }
}

fn execute_flow_gate(
    engine: &PolicyEngine,
    suggestor_name: &'static str,
    input_key: ContextKey,
    output_key: ContextKey,
    proposal_id: &'static str,
    error_id: &'static str,
    ctx: &dyn Context,
) -> AgentEffect {
    let _span =
        suggestor_span(suggestor_name, input_key, output_key, ctx.count(input_key)).entered();
    let facts = ctx.get(input_key);
    let Some(seed) = facts.first() else {
        return AgentEffect::empty();
    };

    let input: FlowGateInput = match serde_json::from_str(seed.content()) {
        Ok(i) => i,
        Err(e) => {
            let diag = proposed_fact(
                ContextKey::Diagnostic,
                error_id,
                format!("failed to parse FlowGateInput: {e}"),
            );
            return AgentEffect::with_proposal(diag);
        }
    };

    match engine.evaluate_flow(&input) {
        Ok(decision) => {
            let content = serde_json::to_string(&decision).unwrap_or_default();
            let proposal = proposed_fact(output_key, proposal_id, content);
            AgentEffect::with_proposal(proposal)
        }
        Err(e) => {
            let diag = proposed_fact(
                ContextKey::Diagnostic,
                error_id,
                format!("flow gate evaluation failed: {e}"),
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

    async fn execute(&self, ctx: &dyn Context) -> AgentEffect {
        execute_flow_gate(
            self.engine.as_ref(),
            CEDAR_HITL_GATE_NAME,
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

    async fn execute(&self, ctx: &dyn Context) -> AgentEffect {
        execute_flow_gate(
            self.engine.as_ref(),
            FLOW_GATE_NAME,
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

    async fn execute(&self, ctx: &dyn Context) -> AgentEffect {
        let _span = watched_suggestor_span(
            RATE_LIMIT_GATE_NAME,
            self.watched_key,
            ContextKey::Constraints,
            ctx.count(self.watched_key),
        )
        .entered();
        let count = ctx.count(self.watched_key);
        AgentEffect::with_proposal(proposed_fact(
            ContextKey::Constraints,
            "rate-limit-exceeded",
            serde_json::json!({
                "gate": "rate-limit",
                "key": format!("{:?}", self.watched_key),
                "count": count,
                "limit": self.max_proposals_per_key,
                "action": "block",
            })
            .to_string(),
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

    async fn execute(&self, ctx: &dyn Context) -> AgentEffect {
        let _span = suggestor_span(
            BUDGET_GATE_NAME,
            self.cost_key,
            ContextKey::Constraints,
            ctx.count(self.cost_key),
        )
        .entered();
        let facts = ctx.get(self.cost_key);
        let total_cost: f64 = facts
            .iter()
            .filter_map(|f| {
                serde_json::from_str::<serde_json::Value>(f.content())
                    .ok()
                    .and_then(|v| v.get("cost").and_then(serde_json::Value::as_f64))
            })
            .sum();

        if total_cost > self.max_cost {
            AgentEffect::with_proposal(proposed_fact(
                ContextKey::Constraints,
                "budget-exceeded",
                serde_json::json!({
                    "gate": "budget",
                    "total_cost": total_cost,
                    "limit": self.max_cost,
                    "action": "block",
                })
                .to_string(),
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

    async fn execute(&self, ctx: &dyn Context) -> AgentEffect {
        let _span = suggestor_span(
            APPROVAL_GATE_NAME,
            self.watched_key,
            self.approval_key,
            ctx.count(self.watched_key),
        )
        .entered();
        let facts = ctx.get(self.watched_key);
        let needs_approval = facts.iter().any(|f| {
            serde_json::from_str::<serde_json::Value>(f.content())
                .ok()
                .and_then(|v| v.get("confidence").and_then(serde_json::Value::as_f64))
                .is_none_or(|c| c >= self.stakes_threshold)
        });

        if needs_approval {
            AgentEffect::with_proposal(proposed_fact(
                ContextKey::Constraints,
                "approval-pending",
                serde_json::json!({
                    "gate": "approval",
                    "status": "pending_human_review",
                    "threshold": self.stakes_threshold,
                    "action": "pause",
                })
                .to_string(),
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

    async fn execute(&self, ctx: &dyn Context) -> AgentEffect {
        let _span = suggestor_span(
            DATA_CLASSIFICATION_GATE_NAME,
            self.watched_key,
            ContextKey::Constraints,
            ctx.count(self.watched_key),
        )
        .entered();
        let facts = ctx.get(self.watched_key);
        let mut proposals = Vec::new();

        for fact in facts {
            let mut detected = Vec::new();
            for (label, pattern) in &self.patterns {
                if pattern.is_match(fact.content()) {
                    detected.push(*label);
                }
            }
            if !detected.is_empty() {
                proposals.push(proposed_fact(
                    ContextKey::Constraints,
                    format!("pii-detected-{}", fact.id()),
                    serde_json::json!({
                        "gate": "data-classification",
                        "fact_id": fact.id(),
                        "detected_types": detected,
                        "action": "block",
                    })
                    .to_string(),
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

    async fn execute(&self, ctx: &dyn Context) -> AgentEffect {
        let _span = suggestor_span(
            COMPLIANCE_GATE_NAME,
            self.watched_key,
            ContextKey::Constraints,
            ctx.count(self.watched_key),
        )
        .entered();
        let facts = ctx.get(self.watched_key);
        let mut proposals = Vec::new();

        for fact in facts {
            let Ok(value) = serde_json::from_str::<serde_json::Value>(fact.content()) else {
                continue;
            };

            for rule in &self.rules {
                let violated = match &rule.condition {
                    ComplianceCondition::FieldMustNotExist => value.get(&rule.field).is_some(),
                    ComplianceCondition::MaxValue(max) => value
                        .get(&rule.field)
                        .and_then(serde_json::Value::as_f64)
                        .is_some_and(|v| v > *max),
                    ComplianceCondition::MustNotContain(forbidden) => value
                        .get(&rule.field)
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| forbidden.iter().any(|f| s.contains(f.as_str()))),
                };

                if violated {
                    proposals.push(proposed_fact(
                        ContextKey::Constraints,
                        format!("compliance-{}-{}", rule.id, fact.id()),
                        serde_json::json!({
                            "gate": "compliance",
                            "rule_id": rule.id,
                            "framework": rule.framework,
                            "fact_id": fact.id(),
                            "field": rule.field,
                            "action": "block",
                        })
                        .to_string(),
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
        ContentHash, ContextFact, FactActor, FactActorKind, FactLocalTrace, FactPromotionRecord,
        FactTraceLink, FactValidationSummary, Timestamp,
    };
    use std::collections::HashMap;

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
        content: impl Into<String>,
    ) -> ContextFact {
        ContextFact::new_projection(
            key,
            id,
            content,
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
            vec![context_fact(
                ContextKey::Seeds,
                "flow-gate-input",
                serde_json::to_string(&input).unwrap(),
            )],
        );

        assert!(s.accepts(&ctx));
        let effect = s.execute(&ctx).await;
        assert_eq!(effect.proposals().len(), 1);
        assert!(
            effect.proposals()[0]
                .id
                .contains("cedar-hitl-gate-decision")
        );

        let decision: crate::PolicyDecision =
            serde_json::from_str(effect.proposals()[0].content()).unwrap();
        assert_eq!(decision.outcome, crate::PolicyOutcome::Escalate);
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
                "Contact john@example.com for details",
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
                "Allocate budget across 4 departments",
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
                context_fact(ContextKey::Strategies, "s1", r#"{"cost": 60.0}"#),
                context_fact(ContextKey::Strategies, "s2", r#"{"cost": 50.0}"#),
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
                context_fact(ContextKey::Strategies, "s1", r#"{"cost": 60.0}"#),
                context_fact(ContextKey::Strategies, "s2", r#"{"cost": 50.0}"#),
            ],
        );

        assert!(s.accepts(&ctx));
        let effect = s.execute(&ctx).await;
        assert!(effect.proposals().is_empty());
    }
}
