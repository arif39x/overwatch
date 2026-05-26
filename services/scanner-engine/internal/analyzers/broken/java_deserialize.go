package analyzers

import (
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type JavaDeserializeAnalyzer struct{}

func init() {
	Register(&JavaDeserializeAnalyzer{})
}

func (a *JavaDeserializeAnalyzer) SupportedLanguages() []string {
	return []string{"java"}
}

func (a *JavaDeserializeAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "JAVA-DESER-001"
		name     = "Java Unsafe Deserialization"
		severity = "CRITICAL"
		message  = "Use of ObjectInputStream.readObject() — possible unsafe deserialization"
		cwe      = "CWE-502"
	)

	findings := make([]finding.Finding, 0)

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "method_invocation" {
			nameNode := n.ChildByFieldName("name")
			if nameNode != nil && sourcecode.GetNodeText(nameNode, source) == "readObject" {
				f := finding.NewFinding(
					ruleID, name, severity, filePath,
					sourcecode.PositionToLine(n),
					message, cwe, "readObject()",
					"java", finding.ConfidenceMedium, "Avoid deserializing untrusted data. Use safer alternatives like JSON or XML with proper security configurations, or use look-ahead deserialization.",
					[]string{"https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"},
				)
				f.Evidence = []finding.EvidenceItem{
					{Type: "SINK_CONFIRMED_BY_TYPE", Description: "Java deserialization via readObject()"},
				}
				findings = append(findings, f)
			}
		}

		for i := 0; i < int(n.ChildCount()); i++ {
			visit(n.Child(i))
		}
	}
	visit(node)

	return findings
}
