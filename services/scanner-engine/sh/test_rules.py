#!/usr/bin/env python3
"""Rule regression test runner.

Scans each testdata/rules/<rule_id>/true_positive/ and true_negative/
directory and compares findings against expected_findings.json.

Usage:
    python3 sh/test_rules.py [--binary path/to/overwatch] [--rules-dir path/to/rules]

Returns exit code 0 if all rules pass, 1 if any failure.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_BINARY = os.path.join(PROJECT_ROOT, "overwatch")
TESTDATA_DIR = os.path.join(PROJECT_ROOT, "testdata", "rules")
RULES_DIR = os.path.join(PROJECT_ROOT, "internal", "rules")


def normalize_path(path):
    """Return just the filename for comparison, since test paths vary."""
    return os.path.basename(path)


def load_expected(expected_path):
    """Load expected_findings.json, return list of dicts."""
    if not os.path.isfile(expected_path):
        return []
    with open(expected_path) as f:
        return json.load(f)


def findings_match(actual, expected):
    """Check if actual findings match expected findings by rule_id and file."""
    keyed = {}
    for act in actual:
        key = (act.get("rule_id", ""), normalize_path(act.get("file", "")))
        keyed[key] = act

    matched = 0
    for exp in expected:
        key = (exp.get("rule_id", ""), normalize_path(exp.get("file", "")))
        found = keyed.get(key)
        if found is None:
            return False, f"Missing expected finding: rule_id={exp.get('rule_id')} file={exp.get('file')}"
        if "line" in exp and found.get("line") != exp.get("line"):
            return False, (
                f"Line mismatch for {key}: expected {exp['line']}, got {found.get('line')}"
            )
        if "severity" in exp and found.get("severity") != exp.get("severity"):
            return False, (
                f"Severity mismatch for {key}: expected {exp['severity']}, got {found.get('severity')}"
            )
        matched += 1

    if matched != len(expected):
        return False, f"Matched {matched}/{len(expected)} expected findings"

    return True, ""


def scan_directory(binary, directory, rules_dir):
    """Run scanner on a directory and return parsed JSON findings."""
    if not os.path.isdir(directory):
        return [], f"Directory not found: {directory}"

    files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
    if not files:
        return [], ""

    cmd = [
        binary,
        "scan",
        "--path", directory,
        "--rules", rules_dir,
        "--format", "json",
        "--local",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60, cwd=PROJECT_ROOT)
    if result.returncode not in (0, 1):
        return [], f"Scanner failed (exit {result.returncode}): {result.stderr.strip()}"

    if not result.stdout.strip():
        return [], ""

    try:
        findings = json.loads(result.stdout)
    except json.JSONDecodeError:
        return [], f"Invalid JSON output: {result.stdout[:500]}"

    if findings is None:
        return [], ""

    return findings, ""


def run_tests(binary, rules_dir, verbose):
    """Run all rule tests. Returns (passed, failed, results)."""
    import time

    binary = os.path.abspath(binary)
    if not os.path.isfile(binary):
        return 0, 1, [("ALL", f"Binary not found: {binary}")]

    if not os.path.isdir(TESTDATA_DIR):
        return 0, 1, [("ALL", f"Testdata directory not found: {TESTDATA_DIR}")]

    rule_dirs = sorted(
        d for d in os.listdir(TESTDATA_DIR)
        if os.path.isdir(os.path.join(TESTDATA_DIR, d))
    )

    passed = 0
    failed = 0
    results = []
    total_invoke_start = time.time()

    all_quality = {}

    for rule_id in rule_dirs:
        rule_dir = os.path.join(TESTDATA_DIR, rule_id)
        tp_dir = os.path.join(rule_dir, "true_positive")
        tn_dir = os.path.join(rule_dir, "true_negative")
        expected_file = os.path.join(rule_dir, "expected_findings.json")

        expected = load_expected(expected_file)

        tp_findings, tp_err = scan_directory(binary, tp_dir, rules_dir)
        if tp_err:
            results.append((rule_id, f"TP scan error: {tp_err}"))
            failed += 1
            continue

        tn_findings, tn_err = scan_directory(binary, tn_dir, rules_dir)
        if tn_err:
            results.append((rule_id, f"TN scan error: {tn_err}"))
            failed += 1
            continue

        if expected:
            match, msg = findings_match(tp_findings, expected)
            if not match:
                results.append((rule_id, f"TP mismatch: {msg}"))
                results.append((rule_id, f"  Got findings: {[(f.get('rule_id'), f.get('file')) for f in tp_findings]}"))
                failed += 1
                continue

        if tn_findings:
            tn_keys = [(f.get("rule_id"), normalize_path(f.get("file", ""))) for f in tn_findings]
            tp_key_set = set()
            for exp in expected:
                tp_key_set.add((exp.get("rule_id"), normalize_path(exp.get("file", ""))))
            unexpected = [(rid, fn) for (rid, fn) in tn_keys if (rid, fn) not in tp_key_set]
            if unexpected:
                results.append((rule_id, f"TN has unexpected findings: {unexpected}"))
                failed += 1
                continue

        precision = 1.0
        recall = 0.0
        if expected:
            match, _ = findings_match(tp_findings, expected)
            if match:
                recall = 1.0

        evals = []
        for exp in expected:
            match_found = any(
                f.get("rule_id") == exp.get("rule_id") and normalize_path(f.get("file", "")) == normalize_path(exp.get("file", ""))
                for f in tp_findings
            )
            evals.append(match_found)

        if evals:
            recall = sum(1 for e in evals if e) / len(evals)

        # calculate rule-local precision from findings
        all_tp = len(tp_findings) if tp_findings else 0
        all_tn_findings = len(tn_findings) if tn_findings else 0
        if all_tp + all_tn_findings > 0:
            precision = all_tp / (all_tp + all_tn_findings)

        all_quality[rule_id] = {
            "precision_local": round(precision, 4),
            "recall_corpus": round(recall, 4),
            "test_date": time.strftime("%Y-%m-%d"),
            "true_positive_count": len(expected),
            "detected_count": sum(1 for e in evals if e) if evals else 0,
            "false_positive_count": all_tn_findings,
        }

        results.append((rule_id, "PASS"))
        passed += 1

    quality_path = os.path.join(PROJECT_ROOT, "rules", "quality_metrics.json")
    os.makedirs(os.path.dirname(quality_path), exist_ok=True)
    try:
        existing = {}
        if os.path.isfile(quality_path):
            with open(quality_path) as f:
                existing = json.load(f)
        existing[time.strftime("%Y-%m-%dT%H:%M:%S")] = all_quality
        with open(quality_path, "w") as f:
            json.dump(existing, f, indent=2)
        if verbose:
            print(f"Wrote quality metrics to {quality_path}", file=sys.stderr)
    except Exception as e:
        print(f"Warning: could not write quality metrics: {e}", file=sys.stderr)

    return passed, failed, results


def main():
    parser = argparse.ArgumentParser(description="Run rule regression tests")
    parser.add_argument("--binary", default=DEFAULT_BINARY, help="Path to overwatch binary")
    parser.add_argument("--rules-dir", default=RULES_DIR, help="Path to rules directory")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    passed, failed, results = run_tests(args.binary, args.rules_dir, args.verbose)

    for rule_id, msg in results:
        if args.verbose or msg != "PASS":
            status = "OK" if msg == "PASS" else "FAIL"
            print(f"  [{status}] {rule_id}: {msg}")

    total = passed + failed
    print(f"\nResults: {passed}/{total} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
