# Overwatch: Core Vulnerability Engine

Overwatch is a high-performance, multi-language vulnerability scanning and analysis engine. This repository contains the standalone core components responsible for static analysis, findings prioritization, and proof-of-concept validation.

## Architecture

The engine is composed of three primary services:

*   **Scanner Engine (Go):** The heavy lifter. It performs deep static analysis using tree-sitter for precise vulnerability detection across multiple languages.
*   **Findings Ranker (Rust):** The brains. It takes raw findings, deduplicates them, and applies a scoring algorithm to highlight the most critical risks.
*   **PoC Sandbox (Rust/Python):** The validator. It generates and executes safe proof-of-concept scripts to verify findings and reduce false positives.

## Getting Started

### Prerequisites

*   **Go:** 1.26.2 or later
*   **Rust:** 1.70+ (Cargo)
*   **Python:** 3.10+
*   **Docker & Docker Compose:** For running infrastructure (Redis/Postgres)

### Building the Engine

You can build all core components using the provided Makefile:

```bash
# Build all Go and Rust binaries into the bin/ directory
make build-bins
```

### Infrastructure

The engine relies on Redis for task queuing and Postgres for persistent storage. You can spin these up easily:

```bash
# Start required services in the background
make infra-up
```

## Repository Structure

*   `services/`: Source code for the three core services.
*   `data/`: Wordlists, payloads, and temporary execution data.
*   `contracts/`: JSON schemas defining the data interchange format between services.
*   `sh/`: Utility scripts for build manifest generation and contract testing.

## Development

To run contract validation and ensure service compatibility:

```bash
make test-contracts
```

---
*This is an isolated core-engine-only workspace.*
