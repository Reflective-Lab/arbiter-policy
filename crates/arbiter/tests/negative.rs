mod common;

use arbiter::{DecideRequest, PolicyEngine, delegation::verify, engine::EngineError};

use common::{fixed_signing_key, make_request};

#[test]
fn invalid_policy_source_is_rejected() {
    let err = match PolicyEngine::from_policy_str("this is not cedar") {
        Ok(_) => panic!("policy should fail"),
        Err(err) => err,
    };

    assert!(matches!(err, EngineError::PolicyParse(_)));
}

#[test]
fn invalid_action_identifier_is_rejected_during_deserialization() {
    let req: DecideRequest = make_request("advisory", "propose");
    let mut payload = serde_json::to_value(req).expect("request should serialize");
    payload["action"] = serde_json::Value::String("bad\"action".to_string());

    let err = serde_json::from_value::<DecideRequest>(payload).expect_err("action should fail");

    assert!(err.is_data());
}

#[test]
fn malformed_delegation_token_is_rejected() {
    let signing_key = fixed_signing_key();
    let verifying_key = signing_key.verifying_key();
    let req = make_request("supervisory", "commit");

    let err = verify("not-base64", &verifying_key, &req).expect_err("verify should fail");

    assert!(err.contains("delegation decode failed"));
}
