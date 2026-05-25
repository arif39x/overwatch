package analyzers

import (
	"regexp"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type JavaSecretsAnalyzer struct{}

func init() {
	Register(&JavaSecretsAnalyzer{})
}

func (a *JavaSecretsAnalyzer) SupportedLanguages() []string {
	return []string{"java"}
}

func (a *JavaSecretsAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "JAVA-SECRET-001"
		name     = "Java Hardcoded Secret"
		severity = "HIGH"
		message  = "Hardcoded secret found — possible security risk"
		cwe      = "CWE-798"
	)

	findings := make([]finding.Finding, 0)
	secretRegex := regexp.MustCompile(`(?i)(password|secret|api_key|token|access_key|private_key)`)

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "variable_declarator" {
			nameNode := n.ChildByFieldName("name")
			if nameNode != nil {
				varName := sourcecode.GetNodeText(nameNode, source)
				if secretRegex.MatchString(varName) {
					valNode := n.ChildByFieldName("value")
					if valNode != nil && valNode.Type() == "string_literal" {
						findings = append(findings, NewFinding(
							ruleID, name, severity, filePath,
							sourcecode.PositionToLine(n),
							message, cwe, varName,
							"java", "MEDIUM", "Use environment variables or a secret management service to store sensitive information.",
							[]string{"https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials"},
						))
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
