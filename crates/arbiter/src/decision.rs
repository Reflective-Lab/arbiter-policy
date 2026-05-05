//! Policy decision types aligned with converge-core's gate model.
//!
//! Maps Cedar allow/deny to the three-valued `GateDecision`:
//! Promote (allow), Reject (deny), Escalate (needs human).

use serde::{Deserialize, Serialize};

use converge_core::FlowAction;
use converge_pack::{PrincipalId, ResourceId};

/// Outcome of a policy evaluation, aligned with converge-core's `GateDecision`.
///
/// This is intentionally compatible with `converge_pack::gate::GateDecision`
/// so that policy decisions can flow directly into the promotion gate pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyOutcome {
    /// Action is allowed — maps to `GateDecision::Promote`
    Promote,
    /// Action is denied — maps to `GateDecision::Reject`
    Reject,
    /// Action requires escalation to human authority — maps to `GateDecision::Escalate`
    Escalate,
}

impl PolicyOutcome {
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Promote)
    }

    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Promote | Self::Reject)
    }
}

/// Full policy decision with rationale and audit trail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// The outcome
    pub outcome: PolicyOutcome,
    /// How the decision was made
    pub mode: DecisionMode,
    /// Human-readable rationale (from Cedar diagnostics or delegation verification)
    pub reason: Option<String>,
    /// The principal that was evaluated
    pub principal_id: PrincipalId,
    /// The action that was attempted
    pub action: FlowAction,
    /// The resource that was targeted
    pub resource_id: ResourceId,
}

/// How the decision was reached
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionMode {
    /// Evaluated via Cedar policy rules
    Policy,
    /// Verified via signed delegation token
    Delegation,
}

impl PolicyDecision {
    #[must_use]
    pub fn policy(
        outcome: PolicyOutcome,
        reason: Option<String>,
        principal_id: impl Into<PrincipalId>,
        action: FlowAction,
        resource_id: impl Into<ResourceId>,
    ) -> Self {
        Self {
            outcome,
            mode: DecisionMode::Policy,
            reason,
            principal_id: principal_id.into(),
            action,
            resource_id: resource_id.into(),
        }
    }

    #[must_use]
    pub fn delegation(
        outcome: PolicyOutcome,
        reason: Option<String>,
        principal_id: impl Into<PrincipalId>,
        action: FlowAction,
        resource_id: impl Into<ResourceId>,
    ) -> Self {
        Self {
            outcome,
            mode: DecisionMode::Delegation,
            reason,
            principal_id: principal_id.into(),
            action,
            resource_id: resource_id.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_outcome_is_allowed() {
        assert!(PolicyOutcome::Promote.is_allowed());
        assert!(!PolicyOutcome::Reject.is_allowed());
        assert!(!PolicyOutcome::Escalate.is_allowed());
    }

    #[test]
    fn policy_outcome_is_terminal() {
        assert!(PolicyOutcome::Promote.is_terminal());
        assert!(PolicyOutcome::Reject.is_terminal());
        assert!(!PolicyOutcome::Escalate.is_terminal());
    }

    #[test]
    fn policy_decision_constructor_sets_mode() {
        let d = PolicyDecision::policy(
            PolicyOutcome::Promote,
            Some("reason".into()),
            "agent:x",
            FlowAction::Propose,
            "flow:1",
        );
        assert_eq!(d.mode, DecisionMode::Policy);
        assert_eq!(d.outcome, PolicyOutcome::Promote);
        assert_eq!(d.reason.as_deref(), Some("reason"));
        assert_eq!(d.principal_id, "agent:x");
        assert_eq!(d.action, FlowAction::Propose);
        assert_eq!(d.resource_id, "flow:1");
    }

    #[test]
    fn delegation_decision_constructor_sets_mode() {
        let d = PolicyDecision::delegation(
            PolicyOutcome::Escalate,
            None,
            "agent:y",
            FlowAction::Commit,
            "flow:2",
        );
        assert_eq!(d.mode, DecisionMode::Delegation);
        assert_eq!(d.outcome, PolicyOutcome::Escalate);
        assert!(d.reason.is_none());
    }

    #[test]
    fn policy_outcome_serde_roundtrip() {
        for outcome in [
            PolicyOutcome::Promote,
            PolicyOutcome::Reject,
            PolicyOutcome::Escalate,
        ] {
            let json = serde_json::to_string(&outcome).unwrap();
            let back: PolicyOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(outcome, back);
        }
    }

    #[test]
    fn decision_mode_serde_roundtrip() {
        for mode in [DecisionMode::Policy, DecisionMode::Delegation] {
            let json = serde_json::to_string(&mode).unwrap();
            let back: DecisionMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, back);
        }
    }
}
