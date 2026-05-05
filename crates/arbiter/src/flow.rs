//! Cedar implementation of the neutral flow gate contract from `converge-core`.

use crate::{
    ContextIn, DecideRequest, PolicyEngine, PrincipalIn, ResourceIn,
    decision::{PolicyDecision, PolicyOutcome},
    engine::EngineError,
};
use converge_core::{
    FlowGateAuthorizer, FlowGateDecision, FlowGateError, FlowGateInput, FlowGateOutcome,
};

pub use converge_core::{FlowGateContext, FlowGatePrincipal, FlowGateResource};

fn to_decide_request(input: &FlowGateInput) -> DecideRequest {
    DecideRequest {
        principal: PrincipalIn {
            id: input.principal.id.clone(),
            authority: input.principal.authority,
            domains: input.principal.domains.clone(),
            policy_version: input.principal.policy_version.clone(),
        },
        resource: ResourceIn {
            id: input.resource.id.clone(),
            resource_type: Some(input.resource.kind.clone()),
            phase: Some(input.resource.phase),
            gates_passed: Some(input.resource.gates_passed.clone()),
        },
        action: input.action,
        context: Some(ContextIn {
            commitment_type: input
                .context
                .commitment_type
                .clone()
                .or_else(|| Some(input.resource.kind.clone().into())),
            amount: input.context.amount,
            human_approval_present: input.context.human_approval_present,
            required_gates_met: input.context.required_gates_met,
        }),
        delegation_b64: None,
    }
}

impl PolicyEngine {
    /// Evaluate a policy decision from the canonical flow-facing input.
    ///
    /// This is the preferred path for converging flows and application runtimes.
    pub fn evaluate_flow(&self, input: &FlowGateInput) -> Result<PolicyDecision, EngineError> {
        self.evaluate(&to_decide_request(input))
    }
}

impl FlowGateAuthorizer for PolicyEngine {
    fn decide(&self, input: &FlowGateInput) -> Result<FlowGateDecision, FlowGateError> {
        let decision = self
            .evaluate_flow(input)
            .map_err(|err| FlowGateError::Authorizer(err.to_string()))?;

        let outcome = match decision.outcome {
            PolicyOutcome::Promote => FlowGateOutcome::Promote,
            PolicyOutcome::Reject => FlowGateOutcome::Reject,
            PolicyOutcome::Escalate => FlowGateOutcome::Escalate,
        };

        Ok(FlowGateDecision {
            outcome,
            reason: decision.reason,
            source: Some("cedar".into()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use converge_core::FlowAction;

    #[test]
    fn flow_gate_input_projects_to_decide_request() {
        let input = FlowGateInput {
            principal: converge_core::FlowGatePrincipal {
                id: "agent:finance".into(),
                authority: converge_core::AuthorityLevel::Supervisory,
                domains: vec!["finance".into()],
                policy_version: Some("expense_v1".into()),
            },
            resource: converge_core::FlowGateResource {
                id: "expense:001".into(),
                kind: "expense".into(),
                phase: converge_core::FlowPhase::Commitment,
                gates_passed: vec!["receipt".into()],
            },
            action: FlowAction::Validate,
            context: converge_core::FlowGateContext {
                commitment_type: None,
                amount: Some(1_250),
                human_approval_present: Some(false),
                required_gates_met: Some(true),
            },
        };

        let request = to_decide_request(&input);
        assert_eq!(request.action, FlowAction::Validate);
        assert_eq!(request.principal.domains, vec!["finance"]);
        assert_eq!(request.resource.gates_passed, Some(vec!["receipt".into()]));
        assert_eq!(
            request
                .context
                .as_ref()
                .and_then(|ctx| ctx.commitment_type.as_deref()),
            Some("expense")
        );
    }

    #[test]
    fn policy_engine_implements_neutral_authorizer_contract() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("policies/expense_approval.cedar");
        let policy = std::fs::read_to_string(path).expect("policy should exist");
        let engine = PolicyEngine::from_policy_str(&policy).expect("policy should parse");

        let input = FlowGateInput {
            principal: converge_core::FlowGatePrincipal {
                id: "agent:finance".into(),
                authority: converge_core::AuthorityLevel::Supervisory,
                domains: vec!["finance".into()],
                policy_version: Some("expense_v1".into()),
            },
            resource: converge_core::FlowGateResource {
                id: "expense:001".into(),
                kind: "expense".into(),
                phase: converge_core::FlowPhase::Commitment,
                gates_passed: vec!["receipt".into()],
            },
            action: FlowAction::Validate,
            context: converge_core::FlowGateContext {
                commitment_type: Some("expense".into()),
                amount: Some(1_250),
                human_approval_present: Some(false),
                required_gates_met: Some(true),
            },
        };

        let decision = engine.decide(&input).expect("authorizer should succeed");
        assert_eq!(decision.outcome, FlowGateOutcome::Promote);
        assert_eq!(decision.source.as_deref(), Some("cedar"));
    }
}
