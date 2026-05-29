package analyzers

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type JSPrototypePollutionAnalyzer struct{}

func init() {
	Register(&JSPrototypePollutionAnalyzer{})
}

func (a *JSPrototypePollutionAnalyzer) Name() string { return "JS-PROTO-001" }
func (a *JSPrototypePollutionAnalyzer) SupportedLanguages() []string {
	return []string{"javascript", "typescript"}
}

func (a *JSPrototypePollutionAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "JS-PROTO-001"
		name     = "JavaScript Prototype Pollution"
		severity = "HIGH"
		message  = "Possible prototype pollution via unsafe object property access or assignment"
		cwe      = "CWE-1321"
	)

	findings := make([]finding.Finding, 0)
	taintedVars := sourcecode.GlobalTaintEngine.AnalyzeTaint(node, source, "javascript")

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "assignment_expression" {
			lhs := n.ChildByFieldName("left")
			rhs := n.ChildByFieldName("right")
			if lhs != nil && rhs != nil {
				lhsText := sourcecode.GetNodeText(lhs, source)
				rhsText := sourcecode.GetNodeText(rhs, source)
				if (strings.Contains(lhsText, "__proto__") || strings.Contains(lhsText, "constructor.prototype")) &&
					(rhs.Type() == "identifier" && taintedVars[rhsText]) {
					f := finding.NewFinding(
						ruleID, name, severity, filePath,
						sourcecode.PositionToLine(n),
						message, cwe, lhsText,
						"javascript", finding.ConfidenceHigh,
						"Avoid modifying __proto__ or constructor.prototype with user input.",
						[]string{"https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html"},
					)
					f.Evidence = []finding.EvidenceItem{
						{Type: "DIRECT_SOURCE", Description: "Prototype property modified with tainted data"},
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
