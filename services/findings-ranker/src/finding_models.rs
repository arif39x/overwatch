use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Metadata {
    pub trace_id: Option<String>,
    pub scanner_version: Option<String>,
    pub timestamp: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FindingEnvelope {
    pub metadata: Metadata,
    pub findings: Vec<Finding>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ConfidenceLevel(pub String);

impl ConfidenceLevel {
    pub fn multiplier(&self) -> f64 {
        match self.0.as_str() {
            "DEFINITE" => 1.0,
            "HIGH_CONFIDENCE" => 0.85,
            "MEDIUM_CONFIDENCE" => 0.65,
            "LOW_CONFIDENCE" => 0.45,
            _ => 0.5,
        }
    }

    pub fn ordinal(&self) -> u8 {
        match self.0.as_str() {
            "DEFINITE" => 4,
            "HIGH_CONFIDENCE" => 3,
            "MEDIUM_CONFIDENCE" => 2,
            "LOW_CONFIDENCE" => 1,
            _ => 0,
        }
    }
}

impl PartialOrd for ConfidenceLevel {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.ordinal().cmp(&other.ordinal()))
    }
}

impl Ord for ConfidenceLevel {
    fn cmp(&self, other: &Self) -> Ordering {
        self.ordinal().cmp(&other.ordinal())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct EvidenceItem {
    #[serde(rename = "type")]
    pub evidence_type: String,
    pub description: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Finding {
    pub rule_id: String,
    pub name: String,
    pub severity: String,
    pub file: String,
    pub line: u32,
    pub message: String,
    pub cwe: String,
    pub snippet: String,
    pub language: String,
    pub confidence: String,
    pub fix_guidance: String,
    pub references: Vec<String>,
    pub evidence: Option<Vec<EvidenceItem>>,
    pub taint_source_identifier: Option<String>,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RankedFinding {
    pub finding: Finding,
    pub final_score: f64,
    pub confidence_multiplier: f64,
    pub source_directness_bonus: f64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeedbackEntry {
    pub rule_id: String,
    pub false_positive_count: u32,
    pub total_count: u32,
    pub multiplier: f64,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeedbackStore {
    pub entries: Vec<FeedbackEntry>,
}