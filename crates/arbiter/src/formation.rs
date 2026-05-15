//! Formation-facing discovery metadata for Arbiter capabilities.
//!
//! These descriptors make Arbiter's Cedar gates easy for products and
//! formation builders to find without turning Arbiter into a generic solver
//! pack. Runtime gates remain Suggestors; offline analysis remains explicit
//! evidence.

use serde::Serialize;

/// Stable identifier for the Arbiter Cedar capability family.
pub const ARBITER_FORMATION_PACK_ID: &str = "arbiter.cedar";

/// Stable identifier for the generic Cedar policy suggestor.
pub const POLICY_GATE_CAPABILITY_ID: &str = "arbiter.cedar.policy_gate";

/// Stable identifier for the strict Cedar-backed HITL suggestor.
pub const HITL_GATE_CAPABILITY_ID: &str = "arbiter.cedar.hitl_gate";

/// Stable identifier for offline Cedar SymCC analysis evidence.
pub const ANALYSIS_EVIDENCE_CAPABILITY_ID: &str = "arbiter.cedar.analysis_evidence";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArbiterFormationCapabilityKind {
    RuntimeGate,
    AnalysisEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ArbiterFormationCapability {
    pub id: &'static str,
    pub pack_id: &'static str,
    pub kind: ArbiterFormationCapabilityKind,
    pub suggestor: Option<&'static str>,
    pub feature: Option<&'static str>,
    pub input: &'static str,
    pub output: &'static str,
    pub evidence_tier: &'static str,
    pub description: &'static str,
}

pub const ARBITER_FORMATION_CAPABILITIES: &[ArbiterFormationCapability] = &[
    ArbiterFormationCapability {
        id: POLICY_GATE_CAPABILITY_ID,
        pack_id: ARBITER_FORMATION_PACK_ID,
        kind: ArbiterFormationCapabilityKind::RuntimeGate,
        suggestor: Some("policy-gate"),
        feature: None,
        input: "arbiter::DecideRequest",
        output: "arbiter::PolicyDecision",
        evidence_tier: "decided",
        description: "Runtime Cedar policy gate over DecideRequest.",
    },
    ArbiterFormationCapability {
        id: HITL_GATE_CAPABILITY_ID,
        pack_id: ARBITER_FORMATION_PACK_ID,
        kind: ArbiterFormationCapabilityKind::RuntimeGate,
        suggestor: Some("cedar-hitl-gate"),
        feature: None,
        input: "converge_core::FlowGateInput",
        output: "converge_core::FlowGateDecision",
        evidence_tier: "decided",
        description: "Strict Cedar-backed HITL gate that escalates only when Cedar allows the approved request.",
    },
    ArbiterFormationCapability {
        id: ANALYSIS_EVIDENCE_CAPABILITY_ID,
        pack_id: ARBITER_FORMATION_PACK_ID,
        kind: ArbiterFormationCapabilityKind::AnalysisEvidence,
        suggestor: Some("cedar-analysis"),
        feature: Some("analysis"),
        input: "arbiter::CedarAnalysisInput",
        output: "arbiter::CedarAnalysisReport",
        evidence_tier: "searched",
        description: "Cedar SymCC analysis suggestor for searched policy-invariant evidence; not a runtime authorization gate.",
    },
];

#[must_use]
pub fn formation_capabilities() -> &'static [ArbiterFormationCapability] {
    ARBITER_FORMATION_CAPABILITIES
}

#[must_use]
pub fn find_formation_capability(id: &str) -> Option<&'static ArbiterFormationCapability> {
    ARBITER_FORMATION_CAPABILITIES
        .iter()
        .find(|capability| capability.id == id)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn exposes_cedar_hitl_gate_for_formations() {
        let capability = find_formation_capability(HITL_GATE_CAPABILITY_ID)
            .expect("HITL capability should be registered");

        assert_eq!(capability.pack_id, ARBITER_FORMATION_PACK_ID);
        assert_eq!(capability.kind, ArbiterFormationCapabilityKind::RuntimeGate);
        assert_eq!(capability.suggestor, Some("cedar-hitl-gate"));
        assert_eq!(capability.evidence_tier, "decided");
    }

    #[test]
    fn exposes_cedar_analysis_suggestor_for_formations() {
        let capability = find_formation_capability(ANALYSIS_EVIDENCE_CAPABILITY_ID)
            .expect("analysis capability should be registered");

        assert_eq!(capability.pack_id, ARBITER_FORMATION_PACK_ID);
        assert_eq!(
            capability.kind,
            ArbiterFormationCapabilityKind::AnalysisEvidence
        );
        assert_eq!(capability.suggestor, Some("cedar-analysis"));
        assert_eq!(capability.evidence_tier, "searched");
    }

    #[test]
    fn capability_ids_are_unique() {
        let mut ids = HashSet::new();

        for capability in formation_capabilities() {
            assert!(
                ids.insert(capability.id),
                "duplicate capability id: {}",
                capability.id
            );
        }
    }
}
