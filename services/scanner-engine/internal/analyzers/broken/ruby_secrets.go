package analyzers

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type RubySecretAnalyzer struct{}

func init() {
	Register(&RubySecretAnalyzer{})
}

func (a *RubySecretAnalyzer) SupportedLanguages() []string {
	return []string{"ruby"}
}

func (a *RubySecretAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "RUBY-SECRET-001"
		name     = "Hardcoded Secret (Ruby)"
		severity = "HIGH"
		message  = "Potential hardcoded secret detected in Ruby identifier"
		cwe      = "CWE-798"
	)

	findings := make([]finding.Finding, 0)
	secretKeywords := []string{"password", "secret", "token", "api_key", "private_key"}

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "identifier" || n.Type() == "symbol" {
			name := strings.ToLower(n.Content(source))
			for _, kw := range secretKeywords {
				if strings.Contains(name, kw) {
					parent := n.Parent()
					if parent != nil && (parent.Type() == "assignment" || parent.Type() == "pair") {
						for i := 0; i < int(parent.ChildCount()); i++ {
							child := parent.Child(i)
							if child.Type() == "string" {
								f := finding.NewFinding(
									ruleID, name, severity, filePath,
									sourcecode.PositionToLine(n),
									message, cwe, sourcecode.GetNodeText(parent, source),
									"ruby", finding.ConfidenceMedium, "Move secrets to environment variables.",
									[]string{"https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"},
								)
								f.Evidence = []finding.EvidenceItem{
									{Type: "SINK_CONFIRMED_BY_TYPE", Description: "Hard-coded secret detected via naming pattern"},
								}
								findings = append(findings, f)
							}
						}
					}
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
