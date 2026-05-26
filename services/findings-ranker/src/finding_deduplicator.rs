use std::collections::HashMap;
use crate::finding_models::{EvidenceItem, Finding};
use crate::severity_scorer::compute_final_score;

fn dedup_key(finding: &Finding) -> String {
    let source = finding.taint_source_identifier.as_deref().unwrap_or("");
    format!("{}:{}:{}:{}", finding.rule_id, finding.file, finding.line, source)
}

fn confidence_ordinal(confidence: &str) -> u8 {
    match confidence {
        "DEFINITE" => 4,
        "HIGH_CONFIDENCE" => 3,
        "MEDIUM_CONFIDENCE" => 2,
        "LOW_CONFIDENCE" => 1,
        _ => 0,
    }
}

fn merge_evidence(a: &mut Option<Vec<EvidenceItem>>, b: &Option<Vec<EvidenceItem>>) {
    match (a.as_mut(), b) {
        (Some(ref mut existing), Some(ref other)) => {
            for item in other {
                if !existing.iter().any(|e| e.evidence_type == item.evidence_type && e.description == item.description) {
                    existing.push(item.clone());
                }
            }
        }
        (None, Some(other)) => {
            *a = Some(other.clone());
        }
        _ => {}
    }
}

pub fn dedup_and_rank(findings: Vec<Finding>) -> Vec<Finding> {
    let mut groups: HashMap<String, Finding> = HashMap::new();

    for finding in findings {
        let key = dedup_key(&finding);
        groups.entry(key)
            .and_modify(|existing| {
                let existing_conf = confidence_ordinal(&existing.confidence);
                let incoming_conf = confidence_ordinal(&finding.confidence);

                if incoming_conf > existing_conf {
                    existing.confidence = finding.confidence.clone();
                    existing.evidence = finding.evidence.clone();
                    existing.taint_source_identifier = finding.taint_source_identifier.clone();
                } else if incoming_conf == existing_conf {
                    merge_evidence(&mut existing.evidence, &finding.evidence);
                }
            })
            .or_insert(finding);
    }

    let mut deduped: Vec<Finding> = groups.into_values().collect();

    deduped.sort_by(|a, b| {
        let score_a = compute_final_score(a, &[]);
        let score_b = compute_final_score(b, &[]);
        score_b.partial_cmp(&score_a).unwrap_or(std::cmp::Ordering::Equal)
    });

    deduped
}
