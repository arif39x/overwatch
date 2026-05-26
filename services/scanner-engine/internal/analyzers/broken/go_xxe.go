package analyzers

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type GoXXEAnalyzer struct{}

func init() {
	Register(&GoXXEAnalyzer{})
}

func (a *GoXXEAnalyzer) SupportedLanguages() []string {
	return []string{"go"}
}

func (a *GoXXEAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "GO-XXE-001"
		name     = "Go XXE"
		severity = "HIGH"
		message  = "Potential XXE vulnerability with xml.NewDecoder"
		cwe      = "CWE-611"
	)

	findings := make([]finding.Finding, 0)

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "call_expression" {
			fnNode := n.ChildByFieldName("function")
			if fnNode != nil {
				fnName := sourcecode.GetNodeText(fnNode, source)
				if strings.Contains(fnName, "xml.NewDecoder") {
					f := finding.NewFinding(
						ruleID, name, severity, filePath,
						sourcecode.PositionToLine(n),
						message, cwe, "xml.NewDecoder",
						"go", finding.ConfidenceMedium, "Ensure that the XML parser is configured to disallow external entities if using a custom entity resolver.",
						[]string{"https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"},
					)
					f.Evidence = []finding.EvidenceItem{
						{Type: "SINK_CONFIRMED_BY_TYPE", Description: "XML decoder without external entity protection"},
					}
					findings = append(findings, f)
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
