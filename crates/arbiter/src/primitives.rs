use serde::{Deserialize, Serialize};

/// A confidence score in [0.0, 1.0].
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Confidence(f64);

impl Confidence {
    pub fn new(v: f64) -> Result<Self, String> {
        if (0.0..=1.0).contains(&v) {
            Ok(Self(v))
        } else {
            Err(format!("confidence {v} is outside [0.0, 1.0]"))
        }
    }
    pub fn value(self) -> f64 {
        self.0
    }
    /// Clamp rather than reject — useful for internal construction from trusted sources.
    pub fn clamped(v: f64) -> Self {
        Self(v.clamp(0.0, 1.0))
    }
}

/// A non-negative cost in USD.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CostUsd(f64);

impl CostUsd {
    pub fn new(v: f64) -> Result<Self, String> {
        if v >= 0.0 {
            Ok(Self(v))
        } else {
            Err(format!("cost {v} must be >= 0.0"))
        }
    }
    pub fn value(self) -> f64 {
        self.0
    }
    pub fn zero() -> Self {
        Self(0.0)
    }
    /// Clamp to non-negative — useful for internal construction from trusted sources.
    pub fn clamped(v: f64) -> Self {
        Self(v.max(0.0))
    }
}

/// Current number of proposals in a rate window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProposalCount(pub usize);

/// Maximum allowed proposals in a rate window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProposalLimit(pub usize);

/// Unix epoch timestamp in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EpochSeconds(pub i64);
