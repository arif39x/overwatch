mod finding_deduplicator;
mod finding_models;
mod severity_scorer;

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io::{self, Read, Write};

use finding_deduplicator::dedup_and_rank;
use finding_models::{Finding, FindingEnvelope, Metadata};
use severity_scorer::compute_final_score;

#[derive(Debug)]
struct ValidationError(String);

impl Display for ValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for ValidationError {}

fn main() {
    if let Err(err) = run() {
        let _ = writeln!(io::stderr(), "CRITICAL: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;

    let envelope: FindingEnvelope = match serde_json::from_str(&input) {
        Ok(env) => env,
        Err(_) => {
            #[derive(serde::Deserialize)]
            struct LegacyRequest { findings: Vec<Finding> }
            if let Ok(legacy) = serde_json::from_str::<LegacyRequest>(&input) {
                FindingEnvelope {
                    metadata: Metadata { trace_id: None, scanner_version: None, timestamp: None },
                    findings: legacy.findings,
                    error: None,
                }
            } else {
                return Err(Box::new(ValidationError("Failed to parse finding envelope or legacy request".to_string())));
            }
        }
    };

    if let Err(e) = validate_findings(&envelope.findings) {
        let response = FindingEnvelope {
            metadata: envelope.metadata,
            findings: vec![],
            error: Some(format!("Validation failed: {e}")),
        };
        serde_json::to_writer(io::stdout(), &response)?;
        return Ok(());
    }

    let ranked_findings = dedup_and_rank(envelope.findings);

    let scored: Vec<f64> = ranked_findings.iter().map(|f| {
        compute_final_score(f, &[])
    }).collect();

    let sorted: Vec<Finding> = {
        let mut paired: Vec<(&Finding, f64)> = ranked_findings.iter().zip(scored.iter()).map(|(f, s)| (f, *s)).collect();
        paired.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        paired.into_iter().map(|(f, _)| f.clone()).collect()
    };

    let response = FindingEnvelope {
        metadata: envelope.metadata,
        findings: sorted,
        error: None,
    };

    let stdout = io::stdout();
    let mut handle = stdout.lock();
    serde_json::to_writer(&mut handle, &response)?;
    handle.write_all(b"\n")?;
    Ok(())
}

fn validate_findings(findings: &[Finding]) -> Result<(), ValidationError> {
    for finding in findings {
        if finding.rule_id.trim().is_empty() {
            return Err(ValidationError("finding validation: missing rule_id".to_string()));
        }
        if finding.name.trim().is_empty() {
            return Err(ValidationError("finding validation: missing name".to_string()));
        }
        if finding.severity.trim().is_empty() {
            return Err(ValidationError("finding validation: missing severity".to_string()));
        }
        if finding.file.trim().is_empty() {
            return Err(ValidationError("finding validation: missing file".to_string()));
        }
        if finding.line == 0 {
            return Err(ValidationError("finding validation: invalid line".to_string()));
        }
        if finding.message.trim().is_empty() {
            return Err(ValidationError("finding validation: missing message".to_string()));
        }
        if finding.cwe.trim().is_empty() {
            return Err(ValidationError("finding validation: missing cwe".to_string()));
        }
        if finding.language.trim().is_empty() {
            return Err(ValidationError("finding validation: missing language".to_string()));
        }
        if finding.confidence.trim().is_empty() {
            return Err(ValidationError("finding validation: missing confidence".to_string()));
        }
        if !matches!(finding.confidence.as_str(), "DEFINITE" | "HIGH_CONFIDENCE" | "MEDIUM_CONFIDENCE" | "LOW_CONFIDENCE") {
            return Err(ValidationError(format!("finding validation: invalid confidence value '{}'", finding.confidence)));
        }
    }
    Ok(())
}
