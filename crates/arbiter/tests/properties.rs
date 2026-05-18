mod common;

use ed25519_dalek::SigningKey;
use proptest::prelude::*;

use arbiter::{
    EpochSeconds, PolicyOutcome,
    delegation::{IssueDelegationReq, issue, verify},
};
use converge_core::AuthorityLevel;
use converge_pack::ResourceId;

use common::{make_request, test_engine};

fn fixed_signing_key() -> SigningKey {
    common::fixed_signing_key()
}

prop_compose! {
    fn valid_authority()(idx in 0usize..4) -> &'static str {
        match idx {
            0 => "advisory",
            1 => "supervisory",
            2 => "participatory",
            _ => "sovereign",
        }
    }
}

prop_compose! {
    fn valid_action()(idx in 0usize..5) -> &'static str {
        match idx {
            0 => "propose",
            1 => "validate",
            2 => "promote",
            3 => "commit",
            _ => "advance_phase",
        }
    }
}

proptest! {
    #[test]
    fn policy_evaluation_is_deterministic(
        authority in valid_authority(),
        action in valid_action(),
        amount in 0i64..100_000,
        human_approval in any::<bool>(),
        required_gates_met in any::<bool>(),
        is_spend in any::<bool>(),
    ) {
        let engine = test_engine();
        let mut req = make_request(authority, action);
        let ctx = req.context.as_mut().expect("context should exist");
        ctx.amount = Some(amount);
        ctx.human_approval_present = Some(human_approval);
        ctx.required_gates_met = Some(required_gates_met);
        ctx.commitment_type = Some(if is_spend { "spend" } else { "quote" }.into());

        let first = engine.evaluate(&req).expect("policy evaluation should succeed");
        let second = engine.evaluate(&req).expect("policy evaluation should succeed");

        prop_assert_eq!(first.outcome, second.outcome);
        prop_assert_eq!(first.mode, second.mode);
        prop_assert_eq!(first.reason, second.reason);
    }

    #[test]
    fn issued_delegation_verifies_when_request_matches(
        amount in 0i64..10_000,
        max_amount in 10_000i64..100_000,
        resource_suffix in "[a-z0-9-]{1,12}",
        jti in "[a-z0-9-]{1,16}",
    ) {
        let signing_key = fixed_signing_key();
        let verifying_key = signing_key.verifying_key();

        let mut req = make_request("supervisory", "commit");
        req.principal.id = "agent:test".into();
        req.resource.id = ResourceId::new(format!("flow:test-{resource_suffix}"));
        req.context.as_mut().expect("context should exist").amount = Some(amount);

        let issued = issue(
            &signing_key,
            IssueDelegationReq {
                sub: req.principal.id.clone(),
                issuer: "human:approver".into(),
                delegated_authority: AuthorityLevel::Supervisory,
                actions: vec![req.action],
                resource_pattern: "flow:test-*".into(),
                max_amount: Some(max_amount),
                nbf_epoch: EpochSeconds(0),
                exp_epoch: EpochSeconds(i64::MAX / 2),
                jti,
            },
        ).expect("delegation should issue");

        let verified = verify(&issued.delegation_b64, &verifying_key, &req)
            .expect("delegation verification should succeed");

        prop_assert!(verified);
    }

    #[test]
    fn delegation_respects_amount_cap(
        max_amount in 0i64..50_000,
        overage in 1i64..50_000,
        resource_suffix in "[a-z0-9-]{1,12}",
        jti in "[a-z0-9-]{1,16}",
    ) {
        let signing_key = fixed_signing_key();
        let verifying_key = signing_key.verifying_key();

        let mut req = make_request("supervisory", "commit");
        req.principal.id = "agent:test".into();
        req.resource.id = ResourceId::new(format!("flow:test-{resource_suffix}"));
        req.context.as_mut().expect("context should exist").amount = Some(max_amount + overage);

        let issued = issue(
            &signing_key,
            IssueDelegationReq {
                sub: req.principal.id.clone(),
                issuer: "human:approver".into(),
                delegated_authority: AuthorityLevel::Supervisory,
                actions: vec![req.action],
                resource_pattern: "flow:test-*".into(),
                max_amount: Some(max_amount),
                nbf_epoch: EpochSeconds(0),
                exp_epoch: EpochSeconds(i64::MAX / 2),
                jti,
            },
        ).expect("delegation should issue");

        let verified = verify(&issued.delegation_b64, &verifying_key, &req)
            .expect("delegation verification should succeed");

        prop_assert!(!verified);
    }
}

#[test]
fn escalation_is_not_terminal() {
    assert!(!PolicyOutcome::Escalate.is_terminal());
}
