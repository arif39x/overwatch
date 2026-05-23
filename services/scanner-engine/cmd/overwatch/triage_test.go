package main

import (
	"testing"

	"github.com/overwatch/scanner-engine/internal/finding"
)

func TestApplyDeterministicGating_SeverityFilter(t *testing.T) {
	findings := []finding.Finding{
		{RuleID: "r1", Severity: "LOW", Confidence: "MEDIUM", CWE: "CWE-1", Language: "python"},
		{RuleID: "r2", Severity: "MEDIUM", Confidence: "MEDIUM", CWE: "CWE-2", Language: "python"},
		{RuleID: "r3", Severity: "HIGH", Confidence: "MEDIUM", CWE: "CWE-3", Language: "python"},
		{RuleID: "r4", Severity: "CRITICAL", Confidence: "MEDIUM", CWE: "CWE-4", Language: "python"},
	}

	gated := applyDeterministicGating(findings, "HIGH", 50)

	if len(gated) != 2 {
		t.Errorf("expected 2 findings, got %d", len(gated))
	}
}

func TestApplyDeterministicGating_MaxFindings(t *testing.T) {
	findings := []finding.Finding{
		{RuleID: "r1", Severity: "HIGH", Confidence: "MEDIUM", CWE: "CWE-1", Language: "python"},
		{RuleID: "r2", Severity: "HIGH", Confidence: "MEDIUM", CWE: "CWE-2", Language: "javascript"},
		{RuleID: "r3", Severity: "HIGH", Confidence: "MEDIUM", CWE: "CWE-3", Language: "go"},
	}

	gated := applyDeterministicGating(findings, "MEDIUM", 2)

	if len(gated) > 2 {
		t.Errorf("expected at most 2 findings, got %d", len(gated))
	}
}

func TestApplyDeterministicGating_LowConfidenceGated(t *testing.T) {
	findings := []finding.Finding{
		{RuleID: "r1", Severity: "MEDIUM", Confidence: "LOW", CWE: "CWE-1", Language: "python"},
		{RuleID: "r2", Severity: "CRITICAL", Confidence: "LOW", CWE: "CWE-2", Language: "python"},
	}

	gated := applyDeterministicGating(findings, "MEDIUM", 50)

	if len(gated) != 1 {
		t.Errorf("expected 1 finding (CRITICAL passes despite LOW confidence), got %d", len(gated))
	}
	if gated[0].Severity != "CRITICAL" {
		t.Errorf("expected CRITICAL finding, got %s", gated[0].Severity)
	}
}

func TestApplyDeterministicGating_DedupSameSignature(t *testing.T) {
	findings := []finding.Finding{
		{RuleID: "sql-injection", Severity: "HIGH", Confidence: "MEDIUM", CWE: "CWE-89", Language: "python"},
		{RuleID: "sql-injection", Severity: "HIGH", Confidence: "MEDIUM", CWE: "CWE-89", Language: "python", OccurrenceCount: 2},
		{RuleID: "sql-injection", Severity: "HIGH", Confidence: "MEDIUM", CWE: "CWE-89", Language: "python", OccurrenceCount: 3},
	}

	gated := applyDeterministicGating(findings, "MEDIUM", 50)

	if len(gated) != 1 {
		t.Errorf("expected 1 finding after dedup, got %d", len(gated))
	}
}

func TestApplyDeterministicGating_EmptyInput(t *testing.T) {
	gated := applyDeterministicGating([]finding.Finding{}, "MEDIUM", 50)

	if len(gated) != 0 {
		t.Errorf("expected 0 findings, got %d", len(gated))
	}
}
