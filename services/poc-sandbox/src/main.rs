use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::process::Command;

#[derive(Debug, Deserialize)]
struct PoCSpec {
    template_id: String,
    params: HashMap<String, String>,
    expected_signal: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SandboxResult {
    verified: bool,
    signal_observed: Option<String>,
    execution_time_ms: u128,
    error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SynthesizedArtifact {
    script: String,
    expected_signal: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let dangerous = args.contains(&"--dangerous".to_string()) || std::env::var("OVERWATCH_DANGEROUS_OK").is_ok();
    
    let mode = if args.len() > 1 && !args[1].starts_with("--dangerous") {
        args[1].as_str()
    } else if args.len() > 2 {
        args[2].as_str()
    } else {
        "--all" 