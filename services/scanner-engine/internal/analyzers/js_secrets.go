package analyzers

import (
	"regexp"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type JSSecretsAnalyzer struct{}

func init() {
	Register(&JSSecretsAnalyzer{})
}

func (a *JSSecretsAnalyzer) Name() string { return "JS-SECRET-001" }
func (a *JSSecretsAnalyzer) SupportedLanguages() []string {
	return []string{"javascript", "typescript"}
}

func (a *JSSecretsAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "JS-SECRET-001"
		name     = "Hardcoded Secret"
		severity = "HIGH"
		message  = "Potential hardcoded secret assigned to identifier"
		cwe      = "CWE-798"
	)

	findings := make([]finding.Finding, 0)
	secretRegex := regexp.MustCompile(`(?i)(api_key|password|secret|token|credential|access_key)`)

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "variable_declarator" || n.Type() == "assignment_expression" {
			var left, right *sitter.Node
			if n.Type() == "variable_declarator" {
				left = n.ChildByFieldName("name")
				right = n.ChildByFieldName("value")
			} else {
				left = n.ChildByFieldName("left")
				right = n.ChildByFieldName("right")
			}

			if left != nil && right != nil {
				leftText := sourcecode.GetNodeText(left, source)
				if secretRegex.MatchString(leftText) {
					rightText := sourcecode.GetNodeText(right, source)
					if right.Type() == "string" || right.Type() == "template_string" {
						f := finding.NewFinding(
							ruleID, name, severity, filePath,
							sourcecode.PositionToLine(n),
							message, cwe, rightText,
							"javascript", finding.ConfidenceMedium,
							"Remove hardcoded secrets from source code and use environment variables or a secrets manager.",
							[]string{"https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"},
						)
						f.Evidence = []finding.EvidenceItem{
							{Type: "SECRET_DETECTED", Description: "Hardcoded string assigned to secret-related identifier"},
						}
						findings = append(findings, f)
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
