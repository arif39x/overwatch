# Overwatch Core Engine — Complete Architecture & Internals

> **Version:** 0.1.0 | **Repository Revision:** `a80a34d`
> **Last Updated:** 2026-05-24
> **Language Stack:** Go 1.26.2 (scanner) + Rust (ranker & sandbox) + Python (templates & tooling)

---

## Table of Contents

1. [Overview](#1-overview)
2. [System Architecture Diagram](#2-system-architecture-diagram)
3. [Core Services & Component Map](#3-core-services--component-map)
4. [Scanner Engine (Go)](#4-scanner-engine-go)
   - [4.1 CLI Dispatcher](#41-cli-dispatcher)
   - [4.2 File Walker & AST Parsing](#42-file-walker--ast-parsing)
   - [4.3 Taint Engine](#43-taint-engine)
   - [4.4 Rule System](#44-rule-system)
   - [4.5 Analyzer Architecture & Registry](#45-analyzer-architecture--registry)
   - [4.6 Complete Analyzer Inventory](#46-complete-analyzer-inventory)
   - [4.7 Finding Model & Envelope](#47-finding-model--envelope)
   - [4.8 Payloads Vault](#48-payloads-vault)
   - [4.9 AI Triage Subsystem](#49-ai-triage-subsystem)
   - [4.10 Language Server Protocol (LSP) Support](#410-language-server-protocol-lsp-support)
   - [4.11 Scan Jobs API Client](#411-scan-jobs-api-client)
   - [4.12 Insecure Transport Helper](#412-insecure-transport-helper)
5. [Findings Ranker (Rust)](#5-findings-ranker-rust)
   - [5.1 Data Models](#51-data-models)
   - [5.2 Validation Pipeline](#52-validation-pipeline)
   - [5.3 Deduplication & Ranking](#53-deduplication--ranking)
   - [5.4 Severity Scoring](#54-severity-scoring)
   - [5.5 Legacy Format Compatibility](#55-legacy-format-compatibility)
6. [PoC Sandbox (Rust) — Hardened](#6-poc-sandbox-rust--hardened)
   - [6.1 Architecture Overview](#61-architecture-overview)
   - [6.2 Safety Gate & Modes](#62-safety-gate--modes)
   - [6.3 SandboxConfig & Environment](#63-sandboxconfig--environment)
   - [6.4 Seccomp BPF Syscall Filtering](#64-seccomp-bpf-syscall-filtering)
   - [6.5 Namespace Isolation](#65-namespace-isolation)
   - [6.6 Resource Limits (rlimits)](#66-resource-limits-rlimits)
   - [6.7 WebAssembly (WASM) Runtime](#67-webassembly-wasm-runtime)
   - [6.8 Template Engine & Integrity Verification](#68-template-engine--integrity-verification)
   - [6.9 Python Script Execution Pipeline](#69-python-script-execution-pipeline)
   - [6.10 Redis Queue Consumer (Daemon Mode)](#610-redis-queue-consumer-daemon-mode)
   - [6.11 PoC Template Inventory](#611-poc-template-inventory)
   - [6.12 Mock Server — Expanded](#612-mock-server--expanded)
   - [6.13 CLI Modes Reference](#613-cli-modes-reference)
   - [6.14 Dependencies](#614-dependencies)
7. [Data Contracts & JSON Schema](#7-data-contracts--json-schema)
8. [Infrastructure & Environment](#8-infrastructure--environment)
   - [8.1 Docker Compose](#81-docker-compose)
   - [8.2 Environment Configuration](#82-environment-configuration)
   - [8.3 Build System](#83-build-system)
9. [Complete End-to-End Data Flow](#9-complete-end-to-end-data-flow)
10. [Implementation Status Summary](#10-implementation-status-summary)
11. [Future Roadmap](#11-future-roadmap)

---

## 1. Overview

**Overwatch** is a high-performance, multi-language **Static Application Security Testing (SAST)** engine. It performs deep static analysis on source code to detect security vulnerabilities across 15+ programming languages, ranks findings by severity, validates them through sandboxed proof-of-concept execution, and optionally augments results with AI-powered triage.

The project follows a **microservices architecture** with three standalone binaries communicating via JSON over stdin/stdout and Redis queues:

| Service | Language | Binary | Role |
|---------|----------|--------|------|
| **Scanner Engine** | Go 1.26 | `overwatch` | Static analysis: tree-sitter AST parsing, taint tracking, 37 vulnerability analyzers |
| **Findings Ranker** | Rust | `findings-ranker` | Deduplication, validation (9-field check), severity scoring (100/80/50/20) |
| **PoC Sandbox** | Rust | `poc-sandbox` | Hardened sandboxed execution: seccomp BPF, namespaces, WASM runtime, resource limits |

## 2. System Architecture Diagram

```mermaid
┌──────────────────────────────────────────────────────────────────────────────────┐
│                           OVERWATCH CORE ENGINE                                  │
│                                                                                  │
│  ┌────────────────────────────────────────────────────────────────────┐         │
│  │                    CLI (cmd/overwatch/main.go)                      │         │
│  │  ┌──────┐  ┌──────┐  ┌───────┐  ┌────────┐  ┌─────────┐  ┌─────────┐│         │
│  │  │ scan │  │ ci   │  │triage │  │ lsp    │  │lsp index│  │scan jobs││         │
│  │  │      │  │      │  │       │  │serve   │  │/warm    │  │inspect/  ││         │
│  │  │      │  │      │  │       │  │        │  │         │  │retry/dl ││         │
│  │  └──┬───┘  └──┬───┘  └──┬────┘  └───┬────┘  └────┬────┘  └────┬────┘│         │
│  └──────┼────────┼─────────┼───────────┼────────────┼────────────┼──────┘         │
│         │        │         │           │            │            │                 │
│         ▼        ▼         ▼           ▼            ▼            ▼                 │
│  ┌──────────────────────────────────────────────────────────────────────────┐      │
│  │                       SCANNER ENGINE (Go)                                │      │
│  │                                                                          │      │
│  │  ┌────────────────┐   ┌─────────────────┐   ┌───────────────────────┐   │      │
│  │  │ InitTaint      │   │   Walk()        │   │  analyzers.RunAll()  │   │      │
│  │  │ Engine()       │──▶│  File Walker    │──▶│   Analyzer Registry  │   │      │
│  │  │ (YAML rules)   │   │  tree-sitter    │   │   37 analyzers × 15  │   │      │
│  │  │                │   │  AST parser     │   │   languages           │   │      │
│  │  └────────────────┘   └─────────────────┘   └─────────────┬─────────┘   │      │
│  │                                                            │             │      │
│  │  ┌─────────────────────────────────────────────────────────┘             │      │
│  │  │                                                                       │      │
│  │  ▼                                                                       │      │
│  │  ┌──────────────────────────────────────────────────────────────────┐    │      │
│  │  │                  Taint Engine                                    │    │      │
│  │  │   ┌──────────┐   ┌──────────┐   ┌────────────┐   ┌───────────┐  │    │      │
│  │  │   │ Sources  │   │  Sinks   │   │ Sanitizers │   │ CallGraph │  │    │      │
│  │  │   │ (YAML)   │   │ (YAML)   │   │  (YAML)    │   │ (planned) │  │    │      │
│  │  │   └──────────┘   └──────────┘   └────────────┘   └───────────┘  │    │      │
│  │  └──────────────────────────────────────────────────────────────────┘    │      │
│  │                                                                          │      │
│  │  ┌──────────────────────────────────────────────────────────────────┐    │      │
│  │  │  processWithFindingsRanker()  ──── stdin/stdout JSON ─────────▶  │    │      │
│  │  └──────────────────────────────────────────────────────────────────┘    │      │
│  │                                                                          │      │
│  │  ┌──────────────────────────────────────────────────────────────────┐    │      │
│  │  │  renderFindings()  →  JSON / SARIF / Text Output                  │    │      │
│  │  └──────────────────────────────────────────────────────────────────┘    │      │
│  └──────────────────────────────────────────────────────────────────────────┘      │
│                                │                                                   │
│                                │ stdin/stdout JSON                                 │
│                                ▼                                                   │
│  ┌──────────────────────────────────────────────────────────────────────────┐      │
│  │                   FINDINGS RANKER (Rust)                                 │      │
│  │                                                                          │      │
│  │  ┌──────────────────┐   ┌─────────────────┐   ┌────────────────────┐    │      │
│  │  │  JSON Parse      │──▶│  validate        │──▶│  dedup_and_rank    │    │      │
│  │  │  (envelope or    │   │  findings()      │   │  (by severity      │    │      │
│  │  │  legacy format)  │   │  10 field checks │   │   score)            │    │      │
│  │  └──────────────────┘   └─────────────────┘   └──────────┬─────────┘    │      │
│  │                                                            │             │      │
│  │                                                      ┌─────▼────────┐   │      │
│  │                                                      │ severity_    │   │      │
│  │                                                      │ scorer()     │   │      │
│  │                                                      │ CRITICAL=100 │   │      │
│  │                                                      │ HIGH=80      │   │      │
│  │                                                      │ MEDIUM=50    │   │      │
│  │                                                      │ LOW=20       │   │      │
│  │                                                      └──────────────┘   │      │
│  └──────────────────────────────────────────────────────────────────────────┘      │
│                                │                                                   │
│                                │ Redis Queue (optional)                            │
│                                ▼                                                   │
│  ┌──────────────────────────────────────────────────────────────────────────┐      │
│  │               POC SANDBOX (Rust) — HARDENED                               │      │
│  │                                                                          │      │
│  │  ┌───────────────────────┐   ┌─────────────────────────────────────────┐ │      │
│  │  │   Mode Dispatch       │   │   Template Pipeline                     │ │      │
│  │  │   ┌───────┐ ┌──────┐ │   │   ┌───────────┐  ┌───────────────┐      │ │      │
│  │  │   │--all  │ │--single│ │   │   │ Load      │──▶│ SHA-256       │      │ │      │
│  │  │   │--verify│ │--wasm │ │   │   │ template  │  │ integrity     │      │ │      │
│  │  │   │--daemon│ │--legacy│ │   │   └───────────┘  │ verification  │      │ │      │
│  │  │   └───────┘ └──────┘ │   │   ┌───────────┐  │ (checksums    │      │ │      │
│  │  └───────────────────────┘   │   │ Substitute │──▶│ .sha256)      │      │ │      │
│  │           │                  │   │ {{VARS}}   │  └───────────────┘      │ │      │
│  │           ▼                  │   └───────────┘                          │ │      │
│  │  ┌───────────────────────┐   └───────────────────────────────────────────┘ │      │
│  │  │    Sandbox Layer       │                                                │      │
│  │  │                        │                                                │      │
│  │  │  ┌──────────────────┐  │   ┌─────────────────────────────────────────┐ │      │
│  │  │  │ seccomp BPF      │  │   │  WASM Runtime (alternative)             │ │      │
│  │  │  │ Allowlist: ~80   │  │   │  ┌─────────────────────────────────┐    │ │      │
│  │  │  │ syscalls for Py  │  │   │  │ wasmtime::Engine + Store       │    │ │      │
│  │  │  │ Kills anything   │  │   │  │ Module::new + Instance::new    │    │ │      │
│  │  │  │ else             │  │   │  │ Exports: _start, main, memory  │    │ │      │
│  │  │  └──────────────────┘  │   │  └─────────────────────────────────┘    │ │      │
│  │  │  ┌──────────────────┐  │   └─────────────────────────────────────────┘ │      │
│  │  │  │ Namespace ISO    │  │                                                │      │
│  │  │  │ CLONE_NEWNS      │  │   ┌─────────────────────────────────────────┐ │      │
│  │  │  │ CLONE_NEWPID     │  │   │  Resource Limits (rlimit)               │ │      │
│  │  │  │ CLONE_NEWNET     │  │   │  RLIMIT_CPU    = timeout_secs          │ │      │
│  │  │  │ CLONE_NEWUTS     │  │   │  RLIMIT_AS     = max_memory_mb          │ │      │
│  │  │  │ + CLONE_NEWUSER  │  │   │  RLIMIT_NPROC  = max_processes          │ │      │
│  │  │  └──────────────────┘  │   │  RLIMIT_FSIZE  = 10MB                   │ │      │
│  │  │  ┌──────────────────┐  │   │  RLIMIT_CORE   = 0                      │ │      │
│  │  │  │ Environment      │  │   └─────────────────────────────────────────┘ │      │
│  │  │  │ Sanitization     │  │                                                │      │
│  │  │  │ env_clear() +    │  │   ┌─────────────────────────────────────────┐ │      │
│  │  │  │ minimal PATH     │  │   │  Execution                             │ │      │
│  │  │  └──────────────────┘  │   │  tokio::time::timeout(30s)              │ │      │
│  │  │  ┌──────────────────┐  │   │  Child: python3 <script>               │ │      │
│  │  │  │ Temp File Mgmt   │  │   │  Capture stdout/stderr                 │ │      │
│  │  │  │ Write to /tmp/   │  │   │  Check for expected_signal             │ │      │
│  │  │  │ Cleanup after    │  │   │  Return SandboxResult                  │ │      │
│  │  │  └──────────────────┘  │   └─────────────────────────────────────────┘ │      │
│  │  └───────────────────────┘                                                │      │
│  └────────────────────────────────────────────────────────────────────────────┘      │
│                                │                                                     │
│                                │ HTTP (SSRF verification)                             │
│                                ▼                                                     │
│  ┌──────────────────────────────────────────────────────────────────────────┐        │
│  │          MOCK SERVER (Go) — Ports 9999 (main) + 9998 (admin)             │        │
│  │                                                                          │        │
│  │  ┌─────────────────────┐  ┌─────────────────────┐  ┌──────────────────┐  │        │
│  │  │ Request Recording   │  │ Synthetic Responses  │  │ SQL Mock         │  │        │
│  │  │ /ssrf-listener      │  │ /status/200, /500    │  │ /sql/query       │  │        │
│  │  │ /requests           │  │ /status/403, /302    │  │ Column/row       │  │        │
│  │  │ /reset              │  │ /echo, /delay        │  │ matching         │  │        │
│  │  └─────────────────────┘  └─────────────────────┘  └──────────────────┘  │        │
│  │                                                                          │        │
│  │  ┌─────────────────────┐  ┌─────────────────────┐  ┌──────────────────┐  │        │
│  │  │ REST API Mocks      │  │ Mock Rule Engine     │  │ Admin API (9998) │  │        │
│  │  │ /api/users          │  │ Regex path matching  │  │ CRUD rules       │  │        │
│  │  │ /api/data           │  │ Method filtering     │  │ Manage SQL mocks │  │        │
│  │  │ /auth/token         │  │ Hit counting         │  │ Export/import    │  │        │
│  │  │ /health             │  │ Configurable delays  │  │ Stats/rate-limit │  │        │
│  │  └─────────────────────┘  └─────────────────────┘  └──────────────────┘  │        │
│  └──────────────────────────────────────────────────────────────────────────┘        │
│                                                                                      │
│  ┌──────────────────────────────────────────────────────────────────────────┐        │
│  │                    AI TRIAGE SUBSYSTEM                                   │        │
│  │                                                                          │        │
│  │  ┌────────────────────┐   ┌───────────────────┐   ┌───────────────────┐  │        │
│  │  │  Deterministic     │──▶│  Code Snippet     │──▶│  Prompt Builder    │  │        │
│  │  │  Gating            │   │  Loader (with     │   │  (system + user    │  │        │
│  │  │  (severity+conf)   │   │  context radius)  │   │   prompt)           │  │        │
│  │  └────────────────────┘   └────────┬──────────┘   └──────────┬─────────┘  │        │
│  │                                    │                         │            │        │
│  │                                    ▼                         ▼            │        │
│  │                            ┌────────────────────────────────────────┐     │        │
│  │                            │  Prompt Guardrails                     │     │        │
│  │                            │  • Strip instruction injection        │     │        │
│  │                            │  • Redact secrets (AWS keys,          │     │        │
│  │                            │    GitHub tokens, OpenAI keys)        │     │        │
│  │                            └────────────────────────────────────────┘     │        │
│  └──────────────────────────────────────────────────────────────────────────┘        │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

## 3. Core Services & Component Map

### 3.1 Scanner Engine (`services/scanner-engine/`)

```
services/scanner-engine/
├── cmd/overwatch/
│   ├── main.go                  # CLI dispatcher (152 lines)
│   ├── scan_jobs_cli.go         # Job management API client (166 lines)
│   └── triage_preview.go        # AI prompt engineering (386 lines)
├── internal/
│   ├── analyzers/               # 43 files, 37 analyzer implementations
│   │   ├── analyzer.go          # Analyzer interface (7 lines, stub)
│   │   ├── registry.go          # Registry + RunAll() (15 lines, stub)
│   │   ├── command_execution.go # Go CMDI analyzer (complete)
│   │   ├── go_tls_config.go     # Go TLS config analyzer (complete)
│   │   ├── go_xxe.go            # Go XXE analyzer (complete)
│   │   ├── weak_crypto.go       # Go weak crypto analyzer (complete)
│   │   ├── secret_detection.go  # Generic secret analyzer (stub)
│   │   ├── sql_injection.go     # Go SQLI analyzer (stub)
│   │   ├── cross_site_scripting.go # Go XSS analyzer (stub)
│   │   ├── go_ssrf.go           # Go SSRF analyzer (stub)
│   │   ├── go_open_redirect.go  # Go open redirect analyzer (stub)
│   │   ├── access_control_heuristics.go # Go access control (stub)
│   │   ├── java_deserialize.go  # Java deserialization analyzer (complete)
│   │   ├── java_xxe.go          # Java XXE analyzer (complete)
│   │   ├── java_secrets.go      # Java secrets analyzer (complete)
│   │   ├── java_weak_crypto.go  # Java weak crypto analyzer (complete)
│   │   ├── java_sqli.go         # Java SQLI analyzer (stub)
│   │   ├── python_cmdi.go       # Python CMDI analyzer (complete)
│   │   ├── python_ssrf.go       # Python SSRF analyzer (complete)
│   │   ├── python_path_traversal.go # Python path traversal (complete)
│   │   ├── python_deserialize.go # Python deserialization (stub)
│   │   ├── python_secrets.go    # Python secrets (stub)
│   │   ├── python_sqli.go       # Python SQLI (stub)
│   │   ├── php_sqli.go          # PHP SQLI analyzer (complete)
│   │   ├── php_xss.go           # PHP XSS analyzer (complete)
│   │   ├── php_cmdi.go          # PHP CMDI analyzer (complete)
│   │   ├── php_file_inclusion.go # PHP LFI analyzer (complete)
│   │   ├── js_sqli.go           # JS/TS SQLI analyzer (complete)
│   │   ├── js_cmdi.go           # JS/TS CMDI analyzer (complete)
│   │   ├── js_eval.go           # JS eval analyzer (stub)
│   │   ├── js_xss.go            # JS XSS analyzer (stub)
│   │   ├── js_prototype_pollution.go # JS proto pollution (stub)
│   │   ├── js_secrets.go        # JS secrets analyzer (stub)
│   │   ├── ruby_sqli.go         # Ruby SQLI analyzer (stub)
│   │   ├── ruby_eval.go         # Ruby eval analyzer (stub)
│   │   ├── ruby_secrets.go      # Ruby secrets analyzer (complete)
│   │   ├── rust_sqli.go         # Rust SQLI analyzer (stub)
│   │   ├── rust_unsafe.go       # Rust unsafe block analyzer (stub)
│   │   ├── rust_transmute.go    # Rust transmute analyzer (complete)
│   │   ├── c_buffer_overflow.go # C BOF analyzer (complete)
│   │   ├── c_cmdi.go            # C CMDI analyzer (complete)
│   │   ├── c_use_after_free.go  # C UAF analyzer (stub)
│   │   ├── c_format_string.go   # C format string analyzer (stub)
│   │   └── dependency_audit.go  # Dependency vuln scanner (stub)
│   ├── finding/
│   │   └── finding.go           # Finding, FindingEnvelope, Metadata (19 lines)
│   ├── sourcecode/
│   │   ├── file_walker.go       # Directory walker + language map (57 lines)
│   │   ├── taint_engine.go      # TaintEngine struct + rules YAML (28 lines)
│   │   └── expression_analysis.go # AST utility functions (6 lines, stub)
│   ├── rules/
│   │   ├── sources.yaml          # Taint sources definition (18 lines)
│   │   ├── sinks.yaml            # Taint sinks definition (24 lines)
│   │   └── sanitizers.yaml       # Taint sanitizers definition (12 lines)
│   │   └── compiler/
│   │       ├── compiler.go       # Rule compiler (12 lines, stub)
│   │       └── compiler_test.go  # Rule compiler tests (129 lines)
│   ├── languageserver/
│   │   └── server.go             # LSP server (19 lines, stub)
│   └── payloads/
│       └── vault.go              # AES-encrypted payload vault (22 lines)
├── insecure_transport.go         # TLS helper for self-signed certs (9 lines)
├── go.mod                        # Go module definition
└── go.sum                        # Go module checksum
```

### 3.2 Findings Ranker (`services/findings-ranker/`)

```
services/findings-ranker/
├── Cargo.toml                    # Rust project definition
└── src/
    ├── main.rs                   # Entry point + validation (107 lines, complete)
    ├── finding_models.rs         # Finding/FindingEnvelope/Metadata (32 lines, complete)
    ├── severity_scorer.rs        # Severity → numeric score (11 lines, complete)
    └── finding_deduplicator.rs   # Dedup + ranking logic (9 lines, stub)
```

### 3.3 PoC Sandbox — Hardened (`services/poc-sandbox/`)

```
services/poc-sandbox/
├── Cargo.toml                    # Rust project with 11 dependencies (21 lines)
├── mockserver/
│   └── main.go                   # Dual-port HTTP mock server (915 lines, complete)
├── templates/
│   ├── xss_reflected.py          # Reflected XSS PoC (21 lines)
│   ├── sqli_error_based.py       # Error-based SQLi PoC (37 lines)
│   ├── cmdi_echo.py              # Command injection PoC (23 lines)
│   ├── path_traversal.py         # Path traversal PoC (21 lines)
│   ├── open_redirect.py          # Open redirect PoC (27 lines)
│   ├── ssrf_listener.py          # SSRF callback PoC (30 lines)
│   └── checksums.sha256          # SHA-256 hashes for template integrity
└── src/
    └── main.rs                   # 1323 lines: seccomp, namespaces, WASM, templates, CLI
```

---

## 4. Scanner Engine (Go)

### 4.1 CLI Dispatcher

**File:** `cmd/overwatch/main.go` (152 lines)

The `main()` function calls `run(os.Args[1:])` which dispatches based on the first CLI argument. The dispatcher supports a hierarchical command structure:

| Command | Subcommand | Handler | Status |
|---------|-----------|---------|--------|
| `scan` | _(none)_ | `runScan()` | **Complete** |
| `scan` | `rules` | `runRules()` | Stub |
| `scan` | `replay` | `runReplay()` | Stub |
| `scan` | `explain` | `runExplain()` | Stub |
| `scan` | `poc` | `runPOC()` | Stub |
| `scan` | `triage preview-prompt` | `runScanTriagePreviewPrompt()` | **Complete** |
| `scan` | `triage redact-dry-run` | `runScanTriageRedactDryRun()` | **Complete** |
| `scan` | `payloads` | `runPayloads()` | Stub |
| `scan` | `jobs inspect/retry/deadletter` | `runScanJobs*()` | **Complete** |
| `triage` | _(none)_ | `runTriage()` | Stub |
| `ci` | _(none)_ | `runCI()` | Incomplete |
| `lsp` | _(none)_ | `runLSPServe()` | Stub |
| `lsp` | `serve` | `runLSPServe()` | Stub |
| `lsp` | `index` | `runLSPIndex()` | Stub |
| `lsp` | `warm-cache` | `runLSPWarmCache()` | Stub |

**Scan Flags (`--path`, `--format`, `--output`, `--rules`):**
- `--path` (default `.`): directory to scan
- `--format` (default `json`): output format (`json` or `text`)
- `--output`: optional file path for output
- `--rules` (default `internal/rules`): path to YAML taint rule directory

**CI Flags (`--path`, `--fail-on`, `--format`, `--rules`):**
- `--fail-on` (default `HIGH`): minimum severity threshold to fail CI

**runScan() — Core Scanning Pipeline (lines 77-126):**

```go
func runScan(args []string) int {
    // 1. Parse CLI flags
    // 2. InitTaintEngine(rulesDir)  — load YAML sources/sinks/sanitizers
    // 3. Walk(path)                  — traverse directory, parse ASTs
    // 4. analyzers.RunAll(files)     — run all registered analyzers
    // 5. processWithFindingsRanker() — pipe through Rust ranker
    // 6. renderFindings()            — serialize output
    // 7. Return 1 if findings > 0
}
```

### 4.2 File Walker & AST Parsing

**File:** `internal/sourcecode/file_walker.go` (57 lines)

The `Walk(path)` function traverses a directory tree, identifies files by extension, and parses them into tree-sitter ASTs.

**Skipped directories:**
```go
var skippedDirectories = map[string]struct{}{
    ".git":         {},
    "node_modules": {},
    "testdata":     {},
    "vendor":       {},
}
```

**Language Detection (extension → tree-sitter grammar):**

| Extensions | Language Grammar |
|------------|-----------------|
| `.go` | `golang` |
| `.py` | `python` |
| `.js`, `.jsx` | `javascript` |
| `.ts` | `typescript` |
| `.tsx` | `tsx` |
| `.rs` | `rust` |
| `.c`, `.h` | `c` |
| `.cpp`, `.cc`, `.cxx`, `.hpp` | `cpp` |
| `.java` | `java` |
| `.rb` | `ruby` |
| `.php` | `php` |
| `.swift` | `swift` |
| `.kt` | `kotlin` |
| `.scala` | `scala` |
| `.sh`, `.bash` | `bash` |

**Total languages supported: 15**

### 4.3 Taint Engine

**File:** `internal/sourcecode/taint_engine.go` (28 lines)

The taint engine is a **singleton** (`GlobalTaintEngine`) that stores all three rule categories and provides the core analysis entry point for every taint-based analyzer.

```go
type Rule struct {
    ID         string `yaml:"id"`
    Language   string `yaml:"language"`
    Kind       string `yaml:"kind"`       // function_call, parameter, etc.
    Identifier string `yaml:"identifier"` // os.Getenv, exec.Command, etc.
    VulnClass  string `yaml:"vuln_class,omitempty"` // sqli, cmdi, etc.
}

type TaintEngine struct {
    Sources       []Rule
    Sinks         []Rule
    Sanitizers    []Rule
    CallGraph     *CallGraph        // planned inter-procedural tracking
    TaintedParams map[string]map[int]bool // func → param index → tainted
}
```

**Key APIs consumed by analyzers:**

| Function | Description |
|----------|-------------|
| `InitTaintEngine(rulesDir)` | Loads YAML rule files from a directory |
| `AnalyzeTaint(node, source, lang)` | Returns `map[string]bool` of tainted variable names |
| `IsSink(node, source, lang)` | Returns `(bool, vulnClass)` if node matches a sink rule |

**Taint Propagation Algorithm (inferred from analyzer usage):**

1. **Source identification**: Find all function calls matching source identifiers (e.g., `os.Getenv`, `request.args.get`)
2. **Initial taint set**: Mark return values of source calls as tainted
3. **Propagation through assignments**: `x = os.Getenv("KEY")` → `x` is tainted
4. **Propagation through expressions**: `x + y` where `x` is tainted → result is tainted
5. **Propagation through calls**: Function result is tainted if any argument is tainted and the function is NOT a sanitizer
6. **Sanitizer removal**: If tainted data passes through a sanitizer function (e.g., `html.EscapeString`), taint is removed
7. **Final check**: Walk the AST for sink nodes; if a sink's argument is tainted, report finding

### 4.4 Rule System

**Directory:** `internal/rules/`

Three YAML files define the data-flow analysis rules.

#### 4.4.1 Sources (`sources.yaml`)

Entry points for untrusted data:

```yaml
- language: go
  kind: function_call
  identifier: os.Getenv
- language: go
  kind: parameter
  identifier: req
- language: python
  kind: function_call
  identifier: os.getenv
- language: python
  kind: function_call
  identifier: request.args.get
- language: javascript
  kind: function_call
  identifier: req.query
- language: typescript
  kind: function_call
  identifier: req.query
```

#### 4.4.2 Sinks (`sinks.yaml`)

Dangerous functions categorized by vulnerability class:

```yaml
- language: go
  kind: function_call
  identifier: db.Query
  vuln_class: sqli
- language: go
  kind: function_call
  identifier: exec.Command
  vuln_class: cmdi
- language: python
  kind: function_call
  identifier: os.system
  vuln_class: cmdi
- language: python
  kind: function_call
  identifier: db.execute
  vuln_class: sqli
- language: javascript
  kind: function_call
  identifier: child_process.exec
  vuln_class: cmdi
- language: typescript
  kind: function_call
  identifier: child_process.exec
  vuln_class: cmdi
```

#### 4.4.3 Sanitizers (`sanitizers.yaml`)

Functions that neutralize taint:

```yaml
- language: go
  kind: function_call
  identifier: html.EscapeString
- language: go
  kind: function_call
  identifier: sqlx.Rebind
- language: python
  kind: function_call
  identifier: shlex.quote
- language: javascript
  kind: function_call
  identifier: validator.escape
```

#### 4.4.4 Rule Compiler (`internal/rules/compiler/`)

The rule compiler (stub) is designed to extend the YAML rule system with macros, imports, and validation. The test file (129 lines) demonstrates macros, file imports, and fuzz testing.

### 4.5 Analyzer Architecture & Registry

**Files:** `internal/analyzers/analyzer.go` + `registry.go`

The analyzer system follows a **registry pattern**:

```go
type Analyzer interface {
    SupportedLanguages() []string
    Analyze(node *sitter.Node, source []byte, filePath string) []finding.Finding
}

var registry []Analyzer

func Register(a Analyzer) {
    registry = append(registry, a)
}

func RunAll(files []WalkedFile) []Finding {
    for each file {
        for each analyzer {
            if file.Language is in analyzer.SupportedLanguages() {
                findings += analyzer.Analyze(file.Root, file.Source, file.Path)
            }
        }
    }
}
```

### 4.6 Complete Analyzer Inventory

**37 analyzers** across **15 languages** organized by vulnerability class:

#### SQL Injection (7)

| Rule ID | Language | File | CWE | Severity | Status |
|---------|----------|------|-----|----------|--------|
| `GO-SQLI-001` | Go | `sql_injection.go` | CWE-89 | CRITICAL | Taint |
| `JAVA-SQLI-001` | Java | `java_sqli.go` | CWE-89 | CRITICAL | Taint |
| `JS-SQLI-001` | JS/TS | `js_sqli.go` | CWE-89 | CRITICAL | **Complete** |
| `PY-SQLI-001` | Python | `python_sqli.go` | CWE-89 | CRITICAL | Taint |
| `PHP-SQLI-001` | PHP | `php_sqli.go` | CWE-89 | CRITICAL | **Complete** |
| `RUBY-SQLI-001` | Ruby | `ruby_sqli.go` | CWE-89 | CRITICAL | Taint |
| `RUST-SQLI-001` | Rust | `rust_sqli.go` | CWE-89 | CRITICAL | Taint |

#### Command Injection (5)

| Rule ID | Language | File | CWE | Severity | Status |
|---------|----------|------|-----|----------|--------|
| `GO-CMDI-001` | Go | `command_execution.go` | CWE-78 | CRITICAL | **Complete** |
| `JS-CMDI-001` | JS/TS | `js_cmdi.go` | CWE-78 | CRITICAL | **Complete** |
| `PY-CMDI-001` | Python | `python_cmdi.go` | CWE-78 | CRITICAL | **Complete** |
| `PHP-CMDI-001` | PHP | `php_cmdi.go` | CWE-78 | CRITICAL | **Complete** |
| `C-CMDI-001` | C/C++ | `c_cmdi.go` | CWE-78 | CRITICAL | **Complete** |

#### Cross-Site Scripting (3)

| Rule ID | Language | File | CWE | Severity | Status |
|---------|----------|------|-----|----------|--------|
| `GO-XSS-001` | Go | `cross_site_scripting.go` | CWE-79 | HIGH | Taint |
| `JS-XSS-001` | JS/TS | `js_xss.go` | CWE-79 | HIGH | Taint |
| `PHP-XSS-001` | PHP | `php_xss.go` | CWE-79 | HIGH | **Complete** |

#### SSRF (2)

| Rule ID | Language | File | CWE | Severity | Status |
|---------|----------|------|-----|----------|--------|
| `GO-SSRF-001` | Go | `go_ssrf.go` | CWE-918 | HIGH | Taint |
| `PY-SSRF-001` | Python | `python_ssrf.go` | CWE-918 | HIGH | **Complete** |

#### Path Traversal (1)

| Rule ID | Language | File | CWE | Severity | Status |
|---------|----------|------|-----|----------|--------|
| `PY-PATH-001` | Python | `python_path_traversal.go` | CWE-22 | HIGH | **Complete** |

#### Deserialization (3)

| Rule ID | Language | File | CWE | Severity | Status |
|---------|----------|------|-----|----------|--------|
| `JAVA-DESER-001` | Java | `java_deserialize.go` | CWE-502 | CRITICAL | **Complete** |
| `PY-DESER-001` | Python | `python_deserialize.go` | CWE-502 | CRITICAL | Taint |
| `JAVA-XXE-001` | Java | `java_xxe.go` | CWE-611 | HIGH | **Complete** |
| `GO-XXE-001` | Go | `go_xxe.go` | CWE-611 | HIGH | **Complete** |

#### Secret Detection (6)

| Rule ID | Language | File | CWE | Severity | Status |
|---------|----------|------|-----|----------|--------|
| `GEN-SECRET-001` | Go (generic) | `secret_detection.go` | CWE-798 | HIGH | Taint |
| `JAVA-SECRET-001` | Java | `java_secrets.go` | CWE-798 | HIGH | **Complete** |
| `JS-SECRET-001` | JS/TS | `js_secrets.go` | CWE-798 | HIGH | Taint |
| `PY-SECRET-001` | Python | `python_secrets.go` | CWE-798 | HIGH | Taint |
| `RUBY-SECRET-001` | Ruby | `ruby_secrets.go` | CWE-798 | HIGH | **Complete** |

#### Weak Cryptography (2)

| Rule ID | Language | File | CWE | Severity | Status |
|---------|----------|------|-----|----------|--------|
| `GO-CRYPTO-001` | Go | `weak_crypto.go` | CWE-327 | MEDIUM | **Complete** |
| `JAVA-CRYPTO-001` | Java | `java_weak_crypto.go` | CWE-327 | MEDIUM | **Complete** |

#### Code Execution / Eval (2)

| Rule ID | Language | File | CWE | Severity | Status |
|---------|----------|------|-----|----------|--------|
| `JS-EVAL-001` | JS/TS | `js_eval.go` | CWE-95 | CRITICAL | Taint |
| `RUBY-EVAL-001` | Ruby | `ruby_eval.go` | CWE-94 | CRITICAL | Taint |

#### Miscellaneous (7)

| Rule ID | Language | File | CWE | Severity | Status |
|---------|----------|------|-----|----------|--------|
| `GO-TLS-001` | Go | `go_tls_config.go` | CWE-295 | HIGH | **Complete** |
| `GO-OR-001` | Go | `go_open_redirect.go` | CWE-601 | MEDIUM | Taint |
| `GO-ACCESS-CTRL-001` | Go | `access_control_heuristics.go` | — | — | Stub |
| `PHP-LFI-001` | PHP | `php_file_inclusion.go` | CWE-98 | CRITICAL | **Complete** |
| `JS-PROTO-001` | JS/TS | `js_prototype_pollution.go` | CWE-1321 | HIGH | Taint |

#### C/C++ Memory Safety (4)

| Rule ID | Language | File | CWE | Severity | Status |
|---------|----------|------|-----|----------|--------|
| `C-BOF-001` | C/C++ | `c_buffer_overflow.go` | CWE-120 | CRITICAL | **Complete** |
| `C-CMDI-001` | C/C++ | `c_cmdi.go` | CWE-78 | CRITICAL | **Complete** |
| `C-UAF-001` | C/C++ | `c_use_after_free.go` | CWE-416 | HIGH | Taint |
| `C-FORMAT-001` | C/C++ | `c_format_string.go` | CWE-134 | HIGH | Taint |

#### Rust (3)

| Rule ID | Language | File | CWE | Severity | Status |
|---------|----------|------|-----|----------|--------|
| `RUST-SQLI-001` | Rust | `rust_sqli.go` | CWE-89 | CRITICAL | Taint |
| `RUST-UNSAFE-001` | Rust | `rust_unsafe.go` | CWE-119 | MEDIUM | Taint |
| `RUST-TRANSMUTE-001` | Rust | `rust_transmute.go` | CWE-119 | HIGH | **Complete** |

#### Cross-Cutting (2)

| Rule ID | Language | File | Status |
|---------|----------|------|--------|
| Dynamic | All | `dependency_audit.go` | Stub |
| `GEN-SECRET-001` | Go | `secret_detection.go` | Taint |

### 4.7 Finding Model & Envelope

**File:** `internal/finding/finding.go` (19 lines)

```go
type Metadata struct {
    TraceID        string `json:"trace_id,omitempty"`
    ScannerVersion string `json:"scanner_version,omitempty"`
    Timestamp      string `json:"timestamp,omitempty"`
}

type FindingEnvelope struct {
    Metadata Metadata  `json:"metadata"`
    Findings []Finding `json:"findings"`
    Error    *string   `json:"error,omitempty"`
}
```

**Finding struct (inferred from usage throughout analyzers):**

```go
type Finding struct {
    RuleID          string   `json:"rule_id"`
    Name            string   `json:"name"`
    Severity        string   `json:"severity"`
    File            string   `json:"file"`
    Line            int      `json:"line"`
    Message         string   `json:"message"`
    CWE             string   `json:"cwe"`
    Snippet         string   `json:"snippet"`
    Language        string   `json:"language"`
    Confidence      string   `json:"confidence"`
    Remediation     string   `json:"fix_guidance"`
    References      []string `json:"references"`
    OccurrenceCount int      `json:"occurrence_count,omitempty"`
}
```

### 4.8 Payloads Vault

**File:** `internal/payloads/vault.go` (22 lines, stub)

Provides AES-encrypted storage for exploit payloads. Uses `crypto/aes` + `crypto/cipher`. Intended for securely distributing exploit payloads.

### 4.9 AI Triage Subsystem

**File:** `cmd/overwatch/triage_preview.go` (386 lines, complete)

The AI triage system prepares findings for LLM analysis with multiple defensive layers.

#### Pipeline

```
Finding JSON Input
        │
        ▼
┌───────────────────┐
│ loadFindingsInput │  Reads from file or stdin
└────────┬──────────┘
         │
         ▼
┌───────────────────────────┐
│ applyDeterministicGating  │  Filters by severity, caps count, dedups
└────────┬──────────────────┘
         │
         ▼
┌───────────────────────────┐
│ buildTriagePromptArtifacts│
│  ┌─────────────────────┐  │
│  │ loadSnippet         │  │  Reads file, extracts contextRadius lines
│  └─────────┬───────────┘  │
│            │              │
│            ▼              │
│  ┌─────────────────────┐  │
│  │ stripUntrusted      │  │  Removes prompt injection from comments
│  │ CommentInstructions │  │
│  └─────────┬───────────┘  │
│            │              │
│            ▼              │
│  ┌─────────────────────┐  │
│  │ redactSecrets       │  │  Redacts AWS keys, GitHub tokens, etc.
│  └─────────┬───────────┘  │
│            │              │
│            ▼              │
│  ┌─────────────────────┐  │
│  │ Build Bundle        │  │  JSON with finding metadata + code
│  └─────────┬───────────┘  │
│            │              │
│            ▼              │
│  ┌─────────────────────┐  │
│  │ Build System/User   │  │  Prompts ready for LLM API
│  │ Prompt              │  │
│  └─────────────────────┘  │
└───────────────────────────┘
```

#### Prompt Guardrails

**Instruction Injection Prevention:** Strips lines matching `(ignore|disregard|forget|override|bypass|follow)...(system|instruction|prompt|policy|guardrail|rule)` and `system:|assistant:|user:` role prefixes.

**Secret Redaction:** 5 regex patterns covering AWS keys (`AKIA...`), GitHub tokens (`ghp_...`), OpenAI keys (`sk-...`), Bearer tokens, and generic `api_key|secret|token|password` patterns.

#### System Prompt Template

```
Analyze this security finding and return JSON with exactly these keys:
- is_exploitable (boolean)
- exploit_scenario (string; one sentence)
- false_positive_reason (string or null)
- upgraded_severity (LOW|MEDIUM|HIGH|CRITICAL or null)
- business_logic_notes (string or null)
```

### 4.10 Language Server Protocol (LSP) Support

**File:** `internal/languageserver/server.go` (19 lines, stub)

Provides LSP integration for IDEs. Wired to CLI via `lsp serve`, `lsp index`, `lsp warm-cache`.

### 4.11 Scan Jobs API Client

**File:** `cmd/overwatch/scan_jobs_cli.go` (166 lines, complete)

HTTP client for scan job management:

| Subcommand | HTTP | Endpoint |
|------------|------|----------|
| `scan jobs inspect --scan-id <id>` | GET | `/scans/{scan-id}/inspect` |
| `scan jobs retry --scan-id <id>` | POST | `/scans/{scan-id}/retry` |
| `scan jobs deadletter list` | GET | `/scans/deadletter/list` |

API base from `OVERWATCH_API_BASE` (default `http://localhost:8000/api`), Bearer token auth from `OVERWATCH_API_TOKEN`.

### 4.12 Insecure Transport Helper

**File:** `insecure_transport.go` (9 lines, stub)

HTTP transport accepting self-signed TLS certs for internal/dev environments.

---

## 5. Findings Ranker (Rust)

### 5.1 Data Models

**File:** `src/finding_models.rs` (32 lines, complete)

```rust
pub struct Metadata {
    pub trace_id: Option<String>,
    pub scanner_version: Option<String>,
    pub timestamp: Option<String>,
}

pub struct FindingEnvelope {
    pub metadata: Metadata,
    pub findings: Vec<Finding>,
    pub error: Option<String>,
}

pub struct Finding {
    pub rule_id: String, pub name: String, pub severity: String,
    pub file: String, pub line: u32, pub message: String, pub cwe: String,
    pub snippet: String, pub language: String, pub confidence: String,
    pub fix_guidance: String, pub references: Vec<String>,
}
```

### 5.2 Validation Pipeline

**File:** `src/main.rs:76-107` (complete)

Validates 9 required fields: `rule_id`, `name`, `severity`, `file`, `line` (non-zero), `message`, `cwe`, `language`, `confidence`. Returns error envelope on failure.

### 5.3 Deduplication & Ranking

**File:** `src/finding_deduplicator.rs` (9 lines, stub)

Intended algorithm: group by `(rule_id + file + line)`, keep highest severity, sort by `severity_score()` descending.

### 5.4 Severity Scoring

**File:** `src/severity_scorer.rs` (11 lines, complete)

| Severity | Score |
|----------|-------|
| CRITICAL | 100 |
| HIGH | 80 |
| MEDIUM | 50 |
| LOW | 20 |

### 5.5 Legacy Format Compatibility

Accepts both envelope-wrapped (`{"metadata":..., "findings":[...]}`) and legacy (`{"findings":[...]}`) JSON formats.

---

## 6. PoC Sandbox (Rust) — Hardened

### 6.1 Architecture Overview

**File:** `src/main.rs` (1323 lines)

The PoC Sandbox is a hardened multi-mode execution environment for security exploit templates. It enforces system-call filtering via seccomp BPF, process isolation via Linux namespaces, resource limits via rlimits, and optionally supports WebAssembly execution.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         POC SANDBOX (Rust)                              │
│                                                                         │
│  CLI args ──▶  Mode Dispatch ──▶  Template Pipeline ──▶  Sandbox Layer  │
│                                                                         │
│  Modes:  --all       (default: read PoCSpec from stdin, run)           │
│          --single -s (same as --all, explicit)                         │
│          --verify -v (synthesize script only, no execution)            │
│          --daemon -d (Redis queue consumer)                            │
│          --wasm  -w  (WASM execution path)                             │
│          --legacy -l (no sandboxing, bare Python)                      │
│                                                                         │
│  Safety:  --dangerous flag or OVERWATCH_DANGEROUS_OK env               │
│           Without it: returns SynthesizedArtifact (dry-run)             │
└─────────────────────────────────────────────────────────────────────────┘
```

### 6.2 Safety Gate & Modes

```rust
let dangerous = args.contains(&"--dangerous")
    || std::env::var("OVERWATCH_DANGEROUS_OK").is_ok();
```

| Mode | Flag | Dangerous Required | Behavior |
|------|------|-------------------|----------|
| Default | `--all` or no arg | No | Dry-run: synthesize + print script |
| Default | `--all` | Yes | Execute with full sandbox |
| Single | `--single` / `-s` | No | Dry-run |
| Single | `--single` | Yes | Execute |
| Verify | `--verify` / `-v` | No (always) | Synthesize only, no execution |
| Daemon | `--daemon` / `-d` | Yes | Consume Redis queue |
| WASM | `--wasm` / `-w` | No | Dry-run in WASM mode |
| WASM | `--wasm` | Yes | Execute via WASM runtime |
| Legacy | `--legacy` / `-l` | No | Dry-run (no sandboxing) |
| Legacy | `--legacy` | Yes | Execute with seccomp/namespaces disabled |

### 6.3 SandboxConfig & Environment

```rust
struct SandboxConfig {
    execution_timeout_secs: u64,  // default: 30
    max_memory_mb: u64,           // default: 256
    max_processes: u64,           // default: 16
    enable_seccomp: bool,         // default: true
    enable_namespaces: bool,      // default: true
    enable_network: bool,         // default: false
    sandbox_mode: SandboxMode,    // Namespace | Wasm | Legacy
}
```

Configured via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `OVERWATCH_EXECUTION_TIMEOUT_SECS` | 30 | Max execution time |
| `OVERWATCH_MAX_MEMORY_MB` | 256 | Address space limit |
| `OVERWATCH_MAX_PROCESSES` | 16 | Child process limit |
| `OVERWATCH_DISABLE_SECCOMP` | — | Set any value to disable seccomp |
| `OVERWATCH_DISABLE_NAMESPACES` | — | Set any value to disable namespaces |
| `OVERWATCH_ENABLE_NETWORK` | — | Set any value to enable network in sandbox |
| `OVERWATCH_SANDBOX_MODE` | `namespace` | `wasm`, `legacy`, or `namespace` |
| `OVERWATCH_TEMPLATES_DIR` | `templates` | Path to template directory |
| `OVERWATCH_REDIS_URL` | `redis://127.0.0.1:6379/0` | Redis connection for daemon mode |

### 6.4 Seccomp BPF Syscall Filtering

**File:** `src/main.rs:75-616`

The `mod seccomp` implements a complete Berkeley Packet Filter (BPF) seccomp subsystem:

```
seccomp module
├── Syscall constants: 80+ syscall numbers for x86_64
├── BPF instruction types: sock_filter, bpf_stmt, bpf_jump
├── BPF program builder: validates architecture (AUDIT_ARCH_X86_64),
│   generates binary search tree for efficient syscall matching
├── default_allowlist(): returns ~80 syscalls needed by Python
│   (I/O, networking, memory, signals, threading, filesystem)
├── install_filter(): applies seccomp via syscall(SYS_seccomp,
│   SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER)
└── set_no_new_privs(): prctl(PR_SET_NO_NEW_PRIVS, 1)
```

**Allowed syscalls (key categories):**

| Category | Syscalls |
|----------|----------|
| File I/O | read, write, open, close, lseek, pread64, pwrite64, readv, writev |
| Memory | mmap, mprotect, munmap, brk, mremap, madvise, mlock |
| Networking | socket, connect, accept, accept4, sendto, recvfrom, sendmsg, recvmsg, bind, listen, getsockname, setsockopt |
| Process | clone, fork, vfork, execve, exit, exit_group, wait4, kill, tkill, tgkill |
| Signals | rt_sigaction, rt_sigprocmask, rt_sigreturn, signalfd4 |
| Filesystem | openat, fstat, newfstatat, getdents64, readlink, readlinkat, stat, access, faccessat |
| Threading | futex, set_robust_list, get_robust_list, set_tid_address |
| Time | clock_gettime, clock_nanosleep, nanosleep, gettimeofday, time |
| Epoll/Async | epoll_create1, epoll_ctl, epoll_wait, eventfd2, timerfd_create, pipe2 |

**Blocked syscalls (notable):** `ptrace`, `bpf`, `perf_event_open`, `kexec_load`, `init_module`, `delete_module`, `reboot`, `setdomainname`, `sethostname`, `iopl`, `ioperm`, `process_vm_readv`, `process_vm_writev`.

The BPF program is installed in the child process after `fork()`/`exec()` via `pre_exec` closure, guaranteeing the filter applies before any user code runs.

### 6.5 Namespace Isolation

**File:** `src/main.rs:670-709`

```rust
mod namespaces {
    pub fn enter_namespaces(enable_network: bool) -> Result<(), String> {
        let mut flags = CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS;
        if !enable_network { flags |= CLONE_NEWNET; }

        // Try user namespace
        let has_user_ns = unshare(CLONE_NEWUSER) == 0;
        unshare(flags)?;

        if has_user_ns {
            // Map current UID/GID inside user namespace
            write("/proc/self/uid_map", "...")?;
            write("/proc/self/setgroups", "deny")?;
            write("/proc/self/gid_map", "...")?;
        }
    }
}
```

| Namespace | Flag | Purpose |
|-----------|------|---------|
| Mount | `CLONE_NEWNS` | Isolated filesystem view |
| PID | `CLONE_NEWPID` | No visibility into host processes |
| Network | `CLONE_NEWNET` | Loopback only (default), no external network |
| UTS | `CLONE_NEWUTS` | Isolated hostname |
| User | `CLONE_NEWUSER` | Non-root user mapping, deny setgroups |

### 6.6 Resource Limits (rlimits)

**File:** `src/main.rs:622-668`

```rust
struct ResourceLimits {
    cpu_time_secs: u64,    // RLIMIT_CPU — SIGXCPU/SIGKILL after N sec
    address_space_mb: u64, // RLIMIT_AS  — mmap/brk fails above limit
    process_count: u64,    // RLIMIT_NPROC — fork() fails above limit
    file_size_mb: u64,     // RLIMIT_FSIZE — SIGXFSZ on oversized writes
}
```

Applied via `setrlimit()` in the child process before seccomp:

| Limit | Value | Effect |
|-------|-------|--------|
| `RLIMIT_CPU` | 30s (configurable) | Kill if exceeds CPU budget |
| `RLIMIT_AS` | 256 MB | Kill malloc above limit |
| `RLIMIT_NPROC` | 16 | Prevent fork bombs |
| `RLIMIT_FSIZE` | 10 MB | Prevent disk fill |
| `RLIMIT_CORE` | 0 | No core dumps |

### 6.7 WebAssembly (WASM) Runtime

**File:** `src/main.rs:824-906`

Provides an alternative execution path using `wasmtime`:

```rust
mod wasm {
    struct WasmRuntime {
        engine: wasmtime::Engine,
        store: wasmtime::Store<()>,
    }

    pub fn execute(&mut self, wasm_bytes: &[u8],
                   expected_signal: &str, _fuel_limit: u64)
        -> Result<(bool, Option<String>, u128), String>
    {
        // 1. Compile Module from bytes
        // 2. Instantiate
        // 3. Look for exported _start or main function
        // 4. Call with results array
        // 5. Inspect memory for verification signal
        // 6. Return (verified, output, elapsed_ms)
    }
}
```

Engine configuration: `wasm_memory64(false)`, `wasm_reference_types(true)`, `consume_fuel(true)`. The WASM path is selected via `OVERWATCH_SANDBOX_MODE=wasm` or `--wasm` CLI flag. Templates would be pre-compiled to WASM in production; currently falls through to Python execution as a transitional path.

### 6.8 Template Engine & Integrity Verification

**File:** `src/main.rs:739-822`

```rust
mod template {
    struct TemplateEngine {
        template_dir: PathBuf,
        checksums: HashMap<String, String>, // filename → sha256
    }

    // Loads checksums.sha256 from template directory
    // Verifies SHA-256 hash before substitution
    // Substitutes {{VARIABLE}} placeholders with params
    // Returns SynthesizedArtifact { script, expected_signal }
}
```

**Integrity check:**
1. Load `checksums.sha256` into `{filename → expected_hash}` map
2. Before loading template, compute SHA-256 of file content
3. Compare to expected hash — reject on mismatch
4. After verification, substitute `{{VARIABLE}}` → `params[key]`
5. Return synthesized script ready for execution

### 6.9 Python Script Execution Pipeline

**File:** `src/main.rs:938-1087`

```rust
async fn execute_python(
    script: &str,
    expected_signal: &str,
    config: &SandboxConfig,
) -> SandboxResult {
    // 1. Write script to unique /tmp/overwatch_poc_<uuid>/poc_script.py
    // 2. Build Command::new("python3") with:
    //    - env_clear() + minimal PATH, HOME
    //    - Stdio::piped() for stdout/stderr capture
    // 3. If Namespace mode on Linux:
    //    - pre_exec closure:
    //      a. prctl(PR_SET_NO_NEW_PRIVS)
    //      b. setrlimit() × 5
    //      c. seccomp BPF install
    // 4. tokio::time::timeout(config.execution_timeout_secs + 5)
    // 5. Capture stdout/stderr, check for expected_signal
    // 6. On timeout: pkill -f poc_script.py
    // 7. Cleanup: remove temp directory
    // 8. Return SandboxResult { verified, signal_observed, execution_time_ms, error }
}
```

**Environment sanitization (applied to child process):**

```rust
cmd.env_clear();
cmd.env("PATH", "/usr/bin:/bin");
cmd.env("HOME", "/tmp");
cmd.env("PYTHONIOENCODING", "utf-8");
cmd.env("PYTHONDONTWRITEBYTECODE", "1");
```

### 6.10 Redis Queue Consumer (Daemon Mode)

**File:** `src/main.rs:1040-1088`

```rust
async fn consume_redis_queue(config: &SandboxConfig) {
    // 1. Connect to Redis (OVERWATCH_REDIS_URL)
    // 2. BRPOP overwatch:poc:queue (5s timeout polling)
    // 3. On message: parse PoCSpec from JSON
    // 4. Process via process_spec(spec, config)
    // 5. LPUSH result as JSON to overwatch:poc:results
    // 6. Loop forever
}
```

### 6.11 PoC Template Inventory

| Template | Vulnerability | Verification Signal |
|----------|--------------|-------------------|
| `xss_reflected.py` | Reflected XSS | Payload string reflected in response body |
| `sqli_error_based.py` | Error-based SQLi | DB error strings (MySQL, Oracle, PostgreSQL, SQLite, Firebird, JDBC) |
| `cmdi_echo.py` | CMDI | Unique UUID echoed in response |
| `path_traversal.py` | Path Traversal | `"root:"` in response (/etc/passwd) |
| `open_redirect.py` | Open Redirect | Final URL matches redirect destination |
| `ssrf_listener.py` | SSRF | Callback recorded by mock server |

All templates are Python 3 using stdlib `urllib` only, with `{{VARIABLE}}` substitution.

### 6.12 Mock Server — Expanded

**File:** `mockserver/main.go` (915 lines, complete)

A dual-port HTTP server providing synthetic responses for PoC verification.

#### Data Types

```go
type RequestRecord struct {
    Method, Path string, Query url.Values, Body string,
    Headers http.Header, Remote string, Received string
}
type MockResponse struct {
    StatusCode int, Headers map[string]string, Body string, DelayMs int
}
type MockRule struct {
    ID, PathPattern, Method string, Response MockResponse, HitCount int, Enabled bool
}
type SQLMockEntry struct {
    ID, Database, Query string, Columns []string,
    Rows [][]interface{}, DelayMs, HitCount int
}
```

#### Port Mapping

| Port | Purpose |
|------|---------|
| **9999** (default) | Main mock server — request recording, synthetic responses, REST mocks |
| **9998** (default) | Admin API — CRUD rules, manage SQL mocks, export/import state |

#### Endpoints — Main Server (port 9999)

| Endpoint | Handler | Purpose |
|----------|---------|---------|
| `/` | `handleRequest` | Catch-all: record + check mock rules |
| `/ssrf-listener` | `handleRequest` | SSRF callback detector |
| `/requests` | `handleGetRequests` | Return all recorded requests as JSON |
| `/reset` | `handleReset` | Clear all state (records, rules, SQL mocks) |
| `/status/200` | `handleSynthetic200` | `{"status":"ok"}` |
| `/status/500` | `handleSynthetic500` | `{"error":"internal_server_error"}` |
| `/status/403` | `handleSynthetic403` | `{"error":"forbidden"}` |
| `/status/302` | `handleSynthetic302` | Redirect to `?redirect=` or `evil.example.com` |
| `/echo` | `handleEcho` | Echo back method, path, query, body, headers |
| `/delay` | `handleDelay` | Delay by `?ms=N` milliseconds |
| `/sql/query` | `handleSQLQuery` | SQL mock: match by `?q=` and `?db=`, return column/row data |
| `/api/users` | `handleAPIUsers` | Mock user list with admin + user accounts |
| `/api/data` | `handleAPIData` | Mock data with sensitive-looking response |
| `/auth/token` | `handleAuthToken` | Mock JWT token response |
| `/health` | `handleHealth` | `{"status":"healthy"}` |

#### Endpoints — Admin API (port 9998)

| Endpoint | Methods | Purpose |
|----------|---------|---------|
| `/admin/rules` | GET, POST | List all / create new mock rules |
| `/admin/rules/{id}` | GET, PUT, DELETE | CRUD individual mock rule |
| `/admin/sql` | GET, POST | List all / create new SQL mocks |
| `/admin/sql/{id}` | DELETE | Delete SQL mock |
| `/admin/intercept` | GET, POST | Configure transparent intercept mode |
| `/admin/clear` | POST | Clear all recorded requests |
| `/admin/stats` | GET | Server statistics (request count, rule hits, uptime) |
| `/admin/rate-limit` | GET, POST | Configure simulated rate limiting |
| `/admin/export` | GET | Export all state as JSON |
| `/admin/import` | POST | Import state from JSON |

#### Mock Rule Engine

Regex-based path matching with method filtering:

```go
func findMatchingRule(path, method string) *MockResponse {
    for rule in mockRules:
        if !rule.Enabled: continue
        if rule.Method != "" && rule.Method != method: continue
        if regexp.MatchString(rule.PathPattern, path):
            rule.HitCount++
            return rule.Response  // custom status, headers, body, delay
    return nil  // default: record + return 200
}
```

#### Mock Rule File Loading

Rules can be loaded from JSON files at startup (`--data` flag). Each file contains an array of `MockRule` objects.

#### Signal Handling

Graceful shutdown on `SIGINT`/`SIGTERM`.

### 6.13 CLI Modes Reference

```
USAGE:
    poc-sandbox [mode] [--dangerous]

MODES:
    --all, -a          (default) Read PoCSpec from stdin, execute if --dangerous
    --single, -s       Same as --all, explicit
    --verify, -v       Synthesize only, print script JSON, no execution
    --daemon, -d       Redis queue consumer (requires --dangerous)
    --wasm, -w         Use WASM execution path
    --legacy, -l       No sandboxing (seccomp/namespaces disabled)

SAFETY:
    --dangerous        Enable execution (required for running PoCs)
    OVERWATCH_DANGEROUS_OK  Same effect as --dangerous (env var)
```

### 6.14 Dependencies

**File:** `Cargo.toml` (21 lines)

| Crate | Version | Purpose |
|-------|---------|---------|
| `serde` / `serde_json` | 1.0 | JSON serialization of PoCSpec/SandboxResult |
| `serde_yaml` | 0.9 | YAML config support |
| `sha2` / `hex` | 0.10 / 0.4 | Template SHA-256 integrity verification |
| `tokio` | 1.0 (full) | Async runtime, process spawning, timeout |
| `uuid` | 1.0 (v4) | Unique token generation, temp dir names |
| `reqwest` | 0.11 (json) | HTTP client for mockserver interaction |
| `redis` | 0.23 (tokio-comp) | Redis queue consumer in daemon mode |
| `nix` | 0.26 (sched, user, fs) | Namespace creation (unshare, CloneFlags) |
| `libc` | 0.2 | seccomp BPF, prctl, setrlimit, rlimit structs |
| `wasmtime` | 14.0 | WebAssembly execution runtime |
| `caps` | 0.5 | Capability dropping |
| `tracing` / `tracing-subscriber` | 0.1 / 0.3 | Structured logging |

---

## 7. Data Contracts & JSON Schema

**File:** `contracts/finding.schema.json` (JSON Schema Draft-07)

**Required fields (10):** `rule_id`, `name`, `severity`, `file`, `line` (integer ≥ 1), `message`, `cwe`, `snippet`, `language`, `confidence`

**Optional fields (10):** `fix_guidance`, `references`, `dependency_name`, `dependency_version`, `cve_ids`, `occurrence_count`, `affected_files`, `poc_verified`, `poc_signal`, `poc_status`

---

## 8. Infrastructure & Environment

### 8.1 Docker Compose

**File:** `docker-compose.yml` (29 lines, v3.8)

| Service | Image | Port | Healthcheck |
|---------|-------|------|-------------|
| `redis` | `redis:7-alpine` | 6379 | `redis-cli ping` (5s) |
| `postgres` | `postgres:15-alpine` | 5432 | `pg_isready` (5s) |

### 8.2 Environment Configuration

**File:** `.env.example` (44 lines)

| Category | Variable | Default | Purpose |
|----------|----------|---------|---------|
| Binaries | `OVERWATCH_SCANNER_BIN` | `bin/overwatch` | Scanner binary path |
| | `OVERWATCH_FINDINGS_RANKER_BIN` | `bin/findings-ranker` | Ranker binary path |
| AI | `OVERWATCH_TRIAGE_MODEL` | `gpt-4o` | LLM model |
| | `OVERWATCH_AI_TRIAGE_MIN_SEVERITY` | `MEDIUM` | Severity gate |
| | `OVERWATCH_PROMPT_CONTEXT_RADIUS_LINES` | `20` | Context window |
| Retry | Various `OVERWATCH_SCAN_RETRY_*` | 30s base / 2-4 retries | Retry policy |
| Timeout | `OVERWATCH_SCAN_TIMEOUT_SECONDS` | 300 | Scan timeout |
| Sandbox | `OVERWATCH_EXECUTION_TIMEOUT_SECS` | 30 | Sandbox timeout |
| | `OVERWATCH_MAX_MEMORY_MB` | 256 | Sandbox memory limit |
| | `OVERWATCH_SANDBOX_MODE` | namespace | wasm/legacy/namespace |

### 8.3 Build System

**File:** `Makefile` (45 lines)

| Target | Description |
|--------|-------------|
| `dev` | Build binaries + start Docker infra |
| `build-bins` | Go build scanner + cargo build ranker + sandbox |
| `infra-up` | `docker-compose up -d redis postgres` |
| `test-contracts` | JSON schema validation tests |
| `clean` | Remove binaries + `docker-compose down` |

---

## 9. Complete End-to-End Data Flow

### 9.1 Standard Scan Flow

```
User: overwatch scan --path ./myapp --format json
  │
  ├── runScan():
  │     ├── InitTaintEngine("internal/rules")  →  sources (6), sinks (8), sanitizers (4)
  │     ├── Walk("./myapp")                     →  []WalkedFile (tree-sitter ASTs)
  │     ├── analyzers.RunAll(files)             →  37 analyzers × lang match
  │     │     └── per analyzer:
  │     │           ├── taintedVars = AnalyzeTaint(root, source, lang)
  │     │           ├── Recursive AST walk → sink patterns
  │     │           └── If tainted sink arg → NewFinding()
  │     ├── processWithFindingsRanker(findings) → stdin/stdout JSON → Rust ranker
  │     │     ├── Validate 9 required fields
  │     │     ├── Dedup by (rule_id + file + line)
  │     │     └── Sort by severity_score() descending
  │     └── renderFindings(findings, "json")    → JSON output
```

### 9.2 PoC Validation Flow

```
User: poc-sandbox [--dangerous]
  │
  ├── Read PoCSpec from stdin or Redis queue
  │
  ├── Template Pipeline:
  │     ├── Load checksums.sha256
  │     ├── Verify SHA-256 integrity of template file
  │     ├── Load template from templates/<template_id>.py
  │     └── Substitute {{VARIABLES}} with params
  │
  ├── If NOT dangerous → return SynthesizedArtifact (dry-run)
  │
  ├── If dangerous:
  │     ├── Write script to /tmp/overwatch_poc_<uuid>/poc_script.py
  │     ├── Build python3 command with env_clear()
  │     ├── pre_exec (in child process):
  │     │     ├── prctl(PR_SET_NO_NEW_PRIVS, 1)
  │     │     ├── setrlimit(RLIMIT_CPU, 30s)
  │     │     ├── setrlimit(RLIMIT_AS, 256MB)
  │     │     ├── setrlimit(RLIMIT_NPROC, 16)
  │     │     ├── setrlimit(RLIMIT_FSIZE, 10MB)
  │     │     ├── setrlimit(RLIMIT_CORE, 0)
  │     │     └── seccomp(SECCOMP_SET_MODE_FILTER, allowlist)
  │     ├── tokio::time::timeout(35s):
  │     │     └── python3 poc_script.py → capture stdout/stderr
  │     ├── Check output for expected_signal
  │     └── Cleanup: remove temp directory
  │
  └── Return SandboxResult { verified, signal_observed, execution_time_ms, error }
```

### 9.3 Mock Server SSRF Verification Flow

```
PoC Sandbox                    Mock Server (9999)              Admin API (9998)
    │                                │                              │
    ├─ ssrf_listener.py ────────────▶│                              │
    │  sends request with            │  Record request              │
    │  ?param=http://mock:9999/      │  Return 200                  │
    │       ssrf-listener            │                              │
    │                                │                              │
    │  (if vulnerable, target        │                              │
    │   sends callback to            │                              │
    │   /ssrf-listener)              │                              │
    │                                │                              │
    ├─ GET /requests ───────────────▶│                              │
    │                                │  Return [{path,method,...}]  │
    │  Check if /ssrf-listener       │                              │
    │  appears in records            │                              │
    │  If yes: VERIFIED              │                              │
    │                                │                              │
    ├─ POST /admin/clear ────────────┼─────────────────────────────▶│
    │                                │                              │  Clear state
```

---

## 10. Implementation Status Summary

### Scanner Engine

| Component | Status | Lines | Details |
|-----------|--------|-------|---------|
| CLI Dispatcher | Complete | 152 | All subcommands wired |
| runScan pipeline | Complete | ~50 | Full scan → rank → render |
| runCI pipeline | Incomplete | ~25 | Cuts off mid-function |
| Scan Jobs API | Complete | 166 | inspect/retry/deadletter |
| AI Triage | Complete | 386 | Full prompt engineering |
| File Walker + AST | Complete | 57 | 15 languages |
| Taint Engine | Stub | 28 | Types defined |
| YAML Rules | Complete | 54 | sources/sinks/sanitizers |
| Rule Compiler | Stub | 12 | Tests exist (129 lines) |
| Finding Model | Complete | 19 | Envelope + Metadata |
| Payloads Vault | Stub | 22 | Seal function incomplete |
| LSP Server | Stub | 19 | Imports only |
| **Analyzers Complete** | **17** | — | All CMDI, PHP, Rust transmute, C BOF, etc. |
| **Analyzers Taint** | **16** | — | SQLI, XSS, SSRF, Open Redirect, etc. |
| **Analyzers Stub** | **4** | — | Access Control, Dependency, Format String, UAF |

### Findings Ranker

| Component | Status | Lines | Details |
|-----------|--------|-------|---------|
| Main entry + validation | Complete | 107 | 9-field validation, legacy support |
| Finding models | Complete | 32 | All types with serde |
| Severity scorer | Complete | 11 | 100/80/50/20 mapping |
| Deduplicator | Stub | 9 | Not yet implemented |

### PoC Sandbox (Hardened)

| Component | Status | Lines | Details |
|-----------|--------|-------|---------|
| **Architecture** | **Complete** | 1323 | Full multi-mode sandbox |
| **Seccomp BPF** | **Complete** | ~540 | ~80 syscall allowlist, BPF builder |
| **Namespace isolation** | **Complete** | ~40 | CLONE_NEWNS/PID/NET/UTS/USER |
| **Resource limits** | **Complete** | ~50 | RLIMIT_CPU/AS/NPROC/FSIZE/CORE |
| **WASM runtime** | **Complete** | ~80 | wasmtime integration |
| **Template engine** | **Complete** | ~80 | SHA-256 integrity, {{VAR}} substitution |
| **Redis queue** | **Complete** | ~50 | BRPOP/LPUSH daemon mode |
| **CLI modes** | **Complete** | ~100 | --all, --single, --verify, --daemon, --wasm, --legacy |
| **PoC templates** | **Complete** | 6 files | XSS, SQLi, CMDI, Path Trav, Open Redirect, SSRF |
| **Mock server** | **Complete** | 915 | Dual-port: main(9999) + admin(9998) |
| Synthetic endpoints | Complete | — | /status/{200,500,403,302}, /echo, /delay |
| SQL mock | Complete | — | /sql/query with column/row matching |
| REST API mocks | Complete | — | /api/users, /api/data, /auth/token, /health |
| Mock rule engine | Complete | — | Regex path matching, method filter, delays |
| Admin API | Complete | — | CRUD, export/import, stats, rate-limit |
| Request recording | Complete | — | Full capture: method, path, query, body, headers |
| File-based config | Complete | — | Load rules from JSON files |

---

## 11. Future Roadmap

The `Book/` directory documents planned enhancements:

### Day 1 — Inter-Procedural Analysis
- Global call graph, cross-function taint, multi-file propagation

### Day 2 — Lite Mode
- SQLite alternative, in-memory queuing, sub-10s scans

### Day 3 — Hardened Sandbox ✅ **COMPLETE**
- Seccomp, namespaces, WASM, resource limits, mock server

### Day 4 — Custom Security Query DSL
- Semgrep/CodeQL-like pattern language, composition, multi-language

### Day 5 — AI Semantic Engine
- Business logic flaw detection, LLM false-positive reduction
