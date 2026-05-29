package analyzers

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type PythonDeserializeAnalyzer struct{}

func init() {
	Register(&PythonDeserializeAnalyzer{})
}

func (a *PythonDeserializeAnalyzer) Name() string { return "PY-DESER-001" }
func (a *PythonDeserializeAnalyzer) SupportedLanguages() []string {
	return []string{"python"}
}

func (a *PythonDeserializeAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "PY-DESER-001"
		name     = "Python Unsafe Deserialization"
		severity = "CRITICAL"
		message  = "Unsafe deserialization — possible remote code execution"
		cwe      = "CWE-502"
	)

	findings := make([]finding.Finding, 0)

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "call" {
			fnNode := n.ChildByFieldName("function")
			if fnNode != nil {
				fnName := sourcecode.GetNodeText(fnNode, source)
				if strings.Contains(fnName, "pickle.loads") ||
					strings.Contains(fnName, "yaml.load") ||
					strings.Contains(fnName, "marshal.loads") ||
					strings.Contains(fnName, "shelve.open") {
					f := finding.NewFinding(
						ruleID, name, severity, filePath,
						sourcecode.PositionToLine(n),
						message, cwe, fnName,
						"python", finding.ConfidenceHigh,
						"Use safe alternatives like json.loads() for untrusted data.",
						[]string{"https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"},
					)
					f.Evidence = []finding.EvidenceItem{
						{Type: "SINK_CONFIRMED_BY_TYPE", Description: "Unsafe deserialization function call"},
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
