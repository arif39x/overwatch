use serde::{Deserialize, Serialize};

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

    