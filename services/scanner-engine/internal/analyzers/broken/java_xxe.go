package analyzers

import (

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type JavaXXEAnalyzer struct{}

func init() {
	Register(&JavaXXEAnalyzer{})
}

func (a *JavaXXEAnalyzer) SupportedLanguages() []string {
	return []string{"java"}
}

func (a *JavaXXEAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "JAVA-XXE-001"
		name     = "Java XXE"
		severity = "HIGH"
		message  = "Potential XXE vulnerability with DocumentBuilderFactory"
		cwe      = "CWE-611"
	)

	findings := make([]finding.Finding, 0)

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "method_invocation" {
			nameNode := n.ChildByFieldName("name")
			if nameNode != nil && sourcecode.GetNodeText(nameNode, source) == "newInstance" {
				objectNode := n.ChildByFieldName("object")
				if objectNode != nil && sourcecode.GetNodeText(objectNode, source) == "DocumentBuilderFactory" {
					findings = append(findings, NewFinding(
						ruleID, name, severity, filePath,
						sourcecode.PositionToLine(n),
						message, cwe, "DocumentBuilderFactory.newInstance()",
						"java", "MEDIUM", "Ensure that the DocumentBuilderFactory is configured to disallow DTDs and external entities.",
						[]string{"https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#java"},
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
