package analyzers

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type SecretAnalyzer struct{}

func init() {
	Register(&SecretAnalyzer{})
}

func (a *SecretAnalyzer) Name() string { return "GEN-SECRET-001" }
func (a *SecretAnalyzer) SupportedLanguages() []string {
	return []string{"go"}
}

func (a *SecretAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "GEN-SECRET-001"
		name     = "Hardcoded Secret"
		severity = "HIGH"
		message  = "Potential hardcoded secret detected"
		cwe      = "CWE-798"
	)

	findings := make([]finding.Finding, 0)
	secretKeywords := []string{"password", "secret", "token", "api_key", "private_key"}

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "identifier" {
			name := strings.ToLower(n.Content(source))
			for _, kw := range secretKeywords {
				if strings.Contains(name, kw) {
					parent := n.Parent()
					if parent != nil && parent.Type() == "assignment_statement" {
						right := parent.ChildByFieldName("right")
						if right != nil && right.Type() == "interpreted_string_literal" {
							f := finding.NewFinding(
								ruleID, name, severity, filePath,
								sourcecode.PositionToLine(n),
								message, cwe, right.Content(source),
								"go", finding.ConfidenceMedium,
								"Remove hardcoded secrets from source code. Use environment variables or a secrets manager.",
								[]string{"https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"},
							)
							f.Evidence = []finding.EvidenceItem{
								{Type: "SECRET_DETECTED", Description: "Potential hardcoded secret in Go source"},
							}
							findings = append(findings, f)
						}
					}
					break
				}
			}
		}

		for i := 0; i < int(n.ChildCount()); i++ {
			visit(n.Child(i))
		}
	}
	visit(node)

	return findings
}
