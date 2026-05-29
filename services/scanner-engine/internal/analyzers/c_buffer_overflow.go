package analyzers

import (

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type CBufferOverflowAnalyzer struct{}

func init() {
	Register(&CBufferOverflowAnalyzer{})
}

func (a *CBufferOverflowAnalyzer) Name() string { return "C-BOF-001" }
func (a *CBufferOverflowAnalyzer) SupportedLanguages() []string {
	return []string{"c", "cpp"}
}

func (a *CBufferOverflowAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "C-BOF-001"
		name     = "C/C++ Buffer Overflow"
		severity = "CRITICAL"
		message  = "Use of unsafe string function — possible buffer overflow"
		cwe      = "CWE-120"
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
				if fnName == "strcpy" || fnName == "strcat" || fnName == "gets" || fnName == "sprintf" || fnName == "scanf" {
					f := finding.NewFinding(
						ruleID, name, severity, filePath,
						sourcecode.PositionToLine(n),
						message, cwe, sourcecode.GetNodeText(n, source),
						"c", finding.ConfidenceHigh, "Use safer alternatives like strncpy, strncat, fgets, or snprintf.",
						[]string{"https://owasp.org/www-community/vulnerabilities/Buffer_Overflow"},
					)
					f.Evidence = []finding.EvidenceItem{
						{Type: "DIRECT_SOURCE", Description: "Unsafe string function called with potential user data"},
						{Type: "SANITIZER_ABSENT", Description: "No bounds checking applied before unsafe operation"},
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
