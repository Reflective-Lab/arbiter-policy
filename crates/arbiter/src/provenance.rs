//! Arbiter's `ProvenanceSource` marker.
//!
//! Migrated to the [`converge_pack::ProvenanceSource`] trait. Public
//! surface is unchanged at call sites:
//! `ARBITER_PROVENANCE.proposed_fact(...)` reads the same as the
//! prior `ProvenanceSource::Arbiter.proposed_fact(...)`.

use converge_pack::ProvenanceSource;

/// Marker type identifying arbiter-emitted facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Arbiter;

impl ProvenanceSource for Arbiter {
    fn as_str(&self) -> &'static str {
        "arbiter"
    }
}

/// Canonical provenance constant for arbiter.
pub const ARBITER_PROVENANCE: Arbiter = Arbiter;

#[cfg(test)]
mod tests {
    use super::*;
    use converge_pack::ContextKey;

    #[test]
    fn provenance_string_is_stable() {
        assert_eq!(ARBITER_PROVENANCE.as_str(), "arbiter");
    }

    #[test]
    fn proposed_fact_uses_canonical_source_string() {
        let fact = ARBITER_PROVENANCE.proposed_fact(
            ContextKey::Diagnostic,
            "diagnostic",
            converge_pack::TextPayload::new("content"),
        );
        assert_eq!(fact.provenance(), "arbiter");
    }
}
