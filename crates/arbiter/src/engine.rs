//! Cedar policy evaluation engine.
//!
//! Wraps the Cedar authorizer with Converge-specific entity mapping.
//! All decision-relevant data is passed through the Cedar Context as JSON,
//! keeping entity construction minimal.

use cedar_policy::{
    Authorizer, Context, Entities, Entity, EntityId, EntityTypeName, EntityUid, PolicySet, Request,
    RestrictedExpression,
};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use thiserror::Error;

use crate::decision::{PolicyDecision, PolicyOutcome};
use crate::types::{ContextIn, DecideRequest};
use converge_core::{AuthorityLevel, FlowAction};
use converge_pack::{DomainId, GateId, PolicyVersionId, ResourceKind};

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("policy parse failed: {0}")]
    PolicyParse(String),
    #[error("request build failed: {0}")]
    RequestBuild(String),
    #[error("context build failed: {0}")]
    ContextBuild(String),
    #[error("entity build failed: {0}")]
    EntityBuild(String),
}

/// Cedar-based policy engine for Converge gate decisions.
pub struct PolicyEngine {
    policies: PolicySet,
    auth: Authorizer,
}

impl PolicyEngine {
    /// Create an engine from a Cedar policy source string.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the Cedar policy text fails to parse.
    pub fn from_policy_str(policy_text: &str) -> Result<Self, EngineError> {
        let ps: PolicySet = policy_text
            .parse()
            .map_err(|err| EngineError::PolicyParse(format!("{err:?}")))?;
        Ok(Self {
            policies: ps,
            auth: Authorizer::new(),
        })
    }

    /// Evaluate a policy decision.
    ///
    /// Builds Cedar principal (`Suggestor::Persona`), resource (`Flow::Commitment`),
    /// and context from the request, then evaluates the loaded policies.
    ///
    /// # Errors
    ///
    /// Returns `Err` if entity or context construction fails.
    pub fn evaluate(&self, req: &DecideRequest) -> Result<PolicyDecision, EngineError> {
        let ctx = req.context.clone().unwrap_or_default();

        // Build principal entity: Suggestor::Persona
        let p_type = EntityTypeName::from_str("Suggestor::Persona")
            .map_err(|e| EngineError::EntityBuild(e.to_string()))?;
        let p_id = EntityId::from_str(&req.principal.id)
            .map_err(|e| EngineError::EntityBuild(e.to_string()))?;
        let p_uid = EntityUid::from_type_name_and_id(p_type, p_id);

        let p_attrs: HashMap<String, RestrictedExpression> = HashMap::from([
            (
                "authority".to_string(),
                RestrictedExpression::new_string(req.principal.authority.as_str().to_string()),
            ),
            (
                "policy_version".to_string(),
                RestrictedExpression::new_string(
                    req.principal
                        .policy_version
                        .as_ref()
                        .map_or_else(String::new, PolicyVersionId::to_string),
                ),
            ),
            (
                "domains".to_string(),
                string_set(req.principal.domains.iter().map(DomainId::to_string)),
            ),
        ]);
        let principal_entity = Entity::new(p_uid.clone(), p_attrs, HashSet::new());

        // Build resource entity: Flow::Commitment
        let r_type = EntityTypeName::from_str("Flow::Commitment")
            .map_err(|e| EngineError::EntityBuild(e.to_string()))?;
        let r_id = EntityId::from_str(&req.resource.id)
            .map_err(|e| EngineError::EntityBuild(e.to_string()))?;
        let r_uid = EntityUid::from_type_name_and_id(r_type, r_id);

        let r_attrs: HashMap<String, RestrictedExpression> = HashMap::from([
            (
                "resource_type".to_string(),
                RestrictedExpression::new_string(
                    req.resource
                        .resource_type
                        .as_ref()
                        .map_or_else(String::new, ResourceKind::to_string),
                ),
            ),
            (
                "phase".to_string(),
                RestrictedExpression::new_string(
                    req.resource
                        .phase
                        .map_or_else(String::new, |phase| phase.as_str().to_string()),
                ),
            ),
            (
                "gates_passed".to_string(),
                string_set(
                    req.resource
                        .gates_passed
                        .iter()
                        .flatten()
                        .map(GateId::to_string),
                ),
            ),
        ]);
        let resource_entity = Entity::new(r_uid.clone(), r_attrs, HashSet::new());

        // Build entities set
        let entities = Entities::from_entities([principal_entity, resource_entity])
            .map_err(|e| EngineError::EntityBuild(e.to_string()))?;

        // Build context as JSON — all decision-relevant facts
        let ctx_json = serde_json::json!({
            "commitment_type": ctx.commitment_type.clone().unwrap_or_default(),
            "amount": ctx.amount.unwrap_or(0),
            "human_approval_present": ctx.human_approval_present.unwrap_or(false),
            "required_gates_met": ctx.required_gates_met.unwrap_or(false),
            "principal_domains": req.principal.domains.iter().map(DomainId::as_str).collect::<Vec<_>>(),
            "gates_passed": req.resource.gates_passed.iter().flatten().map(GateId::as_str).collect::<Vec<_>>(),
        });
        let context = Context::from_json_value(ctx_json, None)
            .map_err(|e| EngineError::ContextBuild(e.to_string()))?;

        // Build action UID
        let action_uid: EntityUid = format!("Action::\"{}\"", req.action.as_str())
            .parse()
            .map_err(|e: cedar_policy::ParseErrors| EngineError::RequestBuild(e.to_string()))?;

        let request = Request::new(Some(p_uid), Some(action_uid), Some(r_uid), context);

        let response = self.auth.is_authorized(&request, &self.policies, &entities);
        let cedar_decision = response.decision();

        let outcome = match cedar_decision {
            cedar_policy::Decision::Allow => PolicyOutcome::Promote,
            cedar_policy::Decision::Deny => {
                if should_escalate(req.action, req.principal.authority, &ctx) {
                    PolicyOutcome::Escalate
                } else {
                    PolicyOutcome::Reject
                }
            }
        };

        let reasons: Vec<String> = response
            .diagnostics()
            .reason()
            .map(std::string::ToString::to_string)
            .collect();
        let reason = if reasons.is_empty() {
            None
        } else {
            Some(reasons.join(", "))
        };

        Ok(PolicyDecision::policy(
            outcome,
            reason,
            req.principal.id.clone(),
            req.action,
            req.resource.id.clone(),
        ))
    }
}

fn string_set(values: impl IntoIterator<Item = String>) -> RestrictedExpression {
    RestrictedExpression::new_set(values.into_iter().map(RestrictedExpression::new_string))
}

/// Determine if a denied action should escalate rather than reject.
///
/// Escalation happens when:
/// - The action is a commitment-level action (commit, promote)
/// - The principal has authority that could be unlocked with human approval
/// - Human approval is not yet present
fn should_escalate(action: FlowAction, authority: AuthorityLevel, ctx: &ContextIn) -> bool {
    matches!(action, FlowAction::Commit | FlowAction::Promote)
        && matches!(
            authority,
            AuthorityLevel::Supervisory | AuthorityLevel::Participatory
        )
        && !ctx.human_approval_present.unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{PrincipalIn, ResourceIn};
    use converge_core::FlowPhase;
    use converge_pack::{DomainId, GateId, PolicyVersionId, ResourceKind};

    fn test_engine() -> PolicyEngine {
        let policy = std::fs::read_to_string("policies/policy.cedar")
            .expect("policy file should exist in test working dir");
        PolicyEngine::from_policy_str(&policy).expect("policy should parse")
    }

    fn make_request(
        authority: AuthorityLevel,
        action: FlowAction,
        amount: i64,
        human_approval: bool,
    ) -> DecideRequest {
        DecideRequest {
            principal: PrincipalIn {
                id: "agent:test".into(),
                authority,
                domains: vec![DomainId::new("test")],
                policy_version: None::<PolicyVersionId>,
            },
            resource: ResourceIn {
                id: "flow:test-001".into(),
                resource_type: Some(ResourceKind::new("quote")),
                phase: Some(FlowPhase::Convergence),
                gates_passed: Some(vec![GateId::new("evidence")]),
            },
            action,
            context: Some(ContextIn {
                commitment_type: Some("quote".into()),
                amount: Some(amount),
                human_approval_present: Some(human_approval),
                required_gates_met: Some(true),
            }),
            delegation_b64: None,
        }
    }

    #[test]
    fn advisory_can_propose() {
        let engine = test_engine();
        let req = make_request(AuthorityLevel::Advisory, FlowAction::Propose, 5000, false);
        let decision = engine.evaluate(&req).unwrap();
        assert_eq!(decision.outcome, PolicyOutcome::Promote);
    }

    #[test]
    fn advisory_cannot_commit() {
        let engine = test_engine();
        let req = make_request(AuthorityLevel::Advisory, FlowAction::Commit, 5000, false);
        let decision = engine.evaluate(&req).unwrap();
        assert_ne!(decision.outcome, PolicyOutcome::Promote);
    }

    #[test]
    fn supervisory_can_commit_with_approval() {
        let engine = test_engine();
        let req = make_request(AuthorityLevel::Supervisory, FlowAction::Commit, 25000, true);
        let decision = engine.evaluate(&req).unwrap();
        assert_eq!(decision.outcome, PolicyOutcome::Promote);
    }

    #[test]
    fn supervisory_escalates_without_approval() {
        let engine = test_engine();
        let req = make_request(
            AuthorityLevel::Supervisory,
            FlowAction::Commit,
            25000,
            false,
        );
        let decision = engine.evaluate(&req).unwrap();
        assert_eq!(decision.outcome, PolicyOutcome::Escalate);
    }

    #[test]
    fn sovereign_can_commit_autonomously() {
        let engine = test_engine();
        let req = make_request(AuthorityLevel::Sovereign, FlowAction::Commit, 25000, false);
        let decision = engine.evaluate(&req).unwrap();
        assert_eq!(decision.outcome, PolicyOutcome::Promote);
    }
}
