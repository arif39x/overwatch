use crate::finding_models::Finding;

pub fn severity_score(finding: &Finding) -> u8 {
    match finding.severity.as_str() {
        "CRITICAL" => 100,
        "HIGH" => 80,
        "MEDIUM" => 50,
        "LOW" => 20,
        _ => 0,
    }
}
