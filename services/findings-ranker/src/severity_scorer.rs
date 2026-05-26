use crate::finding_models::{ConfidenceLevel, EvidenceItem, Finding, FeedbackEntry};

pub fn severity_score(finding: &Finding) -> u8 {
    match finding.severity.as_str() {
        "CRITICAL" => 100,
        "HIGH" => 80,
        "MEDIUM" => 50,
        "LOW" => 20,
        _ => 0,
    }
}

pub fn confidence_multiplier(confidence: &str) -> f64 {
    ConfidenceLevel(confidence.to_string()).multiplier()
}

pub fn source_directness_bonus(evidence: &Option<Vec<EvidenceItem>>) -> f64 {
    let items = match evidence {
        Some(ref v) => v,
        None => return 1.0,
    };

    let mut has_direct = false;
    let mut has_indirect = false;
    let mut has_untraced = false;

    for item in items {
        match item.evidence_type.as_str() {
            "DIRECT_SOURCE" => has_direct = true,
            "INDIRECT_SOURCE" => has_indirect = true,
            "UNTRACED_SOURCE" => has_untraced = true,
            _ => {}
        }
    }

    if has_direct {
        1.2
    } else if has_indirect {
        1.0
    } else if has_untraced {
        0.8
    } else {
        1.0
    }
}

pub fn compute_final_score(finding: &Finding, feedback: &[FeedbackEntry]) -> f64 {
    let base = severity_score(finding) as f64;

    let fb_multiplier = feedback.iter()
        .find(|e| e.rule_id == finding.rule_id)
        .map(|e| e.multiplier)
        .unwrap_or(1.0);

    let conf_mult = confidence_multiplier(&finding.confidence);
    let src_bonus = source_directness_bonus(&finding.evidence);

    base * conf_mult * src_bonus * fb_multiplier
}
