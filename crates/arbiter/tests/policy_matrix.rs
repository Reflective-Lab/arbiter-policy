mod common;

use arbiter::PolicyOutcome;

use common::{make_request, test_engine};

#[test]
fn advisory_cannot_validate() {
    let engine = test_engine();
    let req = make_request("advisory", "validate");

    let decision = engine
        .evaluate(&req)
        .expect("policy evaluation should succeed");

    assert_eq!(decision.outcome, PolicyOutcome::Reject);
}

#[test]
fn supervisory_can_validate() {
    let engine = test_engine();
    let req = make_request("supervisory", "validate");

    let decision = engine
        .evaluate(&req)
        .expect("policy evaluation should succeed");

    assert_eq!(decision.outcome, PolicyOutcome::Promote);
}

#[test]
fn participatory_can_validate() {
    let engine = test_engine();
    let req = make_request("participatory", "validate");

    let decision = engine
        .evaluate(&req)
        .expect("policy evaluation should succeed");

    assert_eq!(decision.outcome, PolicyOutcome::Promote);
}

#[test]
fn supervisory_can_promote_without_approval() {
    let engine = test_engine();
    let req = make_request("supervisory", "promote");

    let decision = engine
        .evaluate(&req)
        .expect("policy evaluation should succeed");

    assert_eq!(decision.outcome, PolicyOutcome::Promote);
}

#[test]
fn participatory_promotion_without_approval_rejects_when_approval_would_not_allow() {
    let engine = test_engine();
    let req = make_request("participatory", "promote");

    let decision = engine
        .evaluate(&req)
        .expect("policy evaluation should succeed");

    assert_eq!(decision.outcome, PolicyOutcome::Reject);
}

#[test]
fn participatory_promotion_with_approval_still_rejects() {
    let engine = test_engine();
    let mut req = make_request("participatory", "promote");
    req.context
        .as_mut()
        .expect("context should exist")
        .human_approval_present = Some(true);

    let decision = engine
        .evaluate(&req)
        .expect("policy evaluation should succeed");

    assert_eq!(decision.outcome, PolicyOutcome::Reject);
}

#[test]
fn advisory_spend_proposal_above_cap_rejects() {
    let engine = test_engine();
    let mut req = make_request("advisory", "propose");
    let ctx = req.context.as_mut().expect("context should exist");
    ctx.commitment_type = Some("spend".into());
    ctx.amount = Some(10_001);

    let decision = engine
        .evaluate(&req)
        .expect("policy evaluation should succeed");

    assert_eq!(decision.outcome, PolicyOutcome::Reject);
}

#[test]
fn advisory_spend_proposal_at_cap_promotes() {
    let engine = test_engine();
    let mut req = make_request("advisory", "propose");
    let ctx = req.context.as_mut().expect("context should exist");
    ctx.commitment_type = Some("spend".into());
    ctx.amount = Some(10_000);

    let decision = engine
        .evaluate(&req)
        .expect("policy evaluation should succeed");

    assert_eq!(decision.outcome, PolicyOutcome::Promote);
}

#[test]
fn advance_phase_requires_gates() {
    let engine = test_engine();
    let mut req = make_request("supervisory", "advance_phase");
    req.context
        .as_mut()
        .expect("context should exist")
        .required_gates_met = Some(false);

    let decision = engine
        .evaluate(&req)
        .expect("policy evaluation should succeed");

    assert_eq!(decision.outcome, PolicyOutcome::Reject);
}

#[test]
fn supervisory_commit_over_fifty_thousand_with_approval_promotes() {
    let engine = test_engine();
    let mut req = make_request("supervisory", "commit");
    let ctx = req.context.as_mut().expect("context should exist");
    ctx.amount = Some(75_000);
    ctx.human_approval_present = Some(true);

    let decision = engine
        .evaluate(&req)
        .expect("policy evaluation should succeed");

    assert_eq!(decision.outcome, PolicyOutcome::Promote);
}
