use std::collections::HashMap;
use crate::finding_models::Finding;
use crate::severity_scorer::severity_score;

pub fn dedup_and_rank(findings: Vec<Finding>) -> Vec<Finding> {
    let mut groups: HashMap<String, Vec<Finding>> = HashMap::new();

    for finding in findings {
        