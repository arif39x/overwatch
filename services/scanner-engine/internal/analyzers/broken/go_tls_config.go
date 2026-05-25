package analyzers

import (
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type GoTLSConfigAnalyzer struct{}

func init() {
	Register(&GoTLSConfigAnalyzer{})
}

func (a *GoTLSConfigAnalyzer) SupportedLanguages() []string {
	return []string{"go"}
}

func (a *GoTLSConfigAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "GO-TLS-001"
		name     = "Go Insecure TLS Configuration"
		severity = "HIGH"
		message  = "InsecureSkipVerify set to true — disables TLS certificate validation"
		cwe      = "CWE-295"
	)

	findings := make([]finding.Finding, 0)

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "keyed_element" {
			keyNode := n.ChildByFieldName("key")
			if keyNode != nil && sourcecode.GetNodeText(keyNode, source) == "InsecureSkipVerify" {
				valNode := n.ChildByFieldName("value")
				if valNode != nil && sourcecode.GetNodeText(valNode, source) == "true" {
					findings = append(findings, NewFinding(
						ruleID, name, severity, filePath,
						sourcecode.PositionToLine(n),
						message, cwe, "InsecureSkipVerify: true",
						"go", "HIGH", "Set InsecureSkipVerify to false and properly configure RootCAs or use system certificates.",
						[]string{"https://pkg.go.dev/crypto/tls#Config"},
					))
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
