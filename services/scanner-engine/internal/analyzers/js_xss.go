package analyzers

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type JSXXSAnalyzer struct{}

func init() {
	Register(&JSXXSAnalyzer{})
}

func (a *JSXXSAnalyzer) Name() string { return "JS-XSS-001" }
func (a *JSXXSAnalyzer) SupportedLanguages() []string {
	return []string{"javascript", "typescript"}
}

func (a *JSXXSAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "JS-XSS-001"
		name     = "JavaScript Cross-Site Scripting"
		severity = "HIGH"
		message  = "Unsafe DOM manipulation — possible Cross-Site Scripting"
		cwe      = "CWE-79"
	)

	findings := make([]finding.Finding, 0)
	taintedVars := sourcecode.GlobalTaintEngine.AnalyzeTaint(node, source, "javascript")

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "call_expression" {
			fnNode := n.ChildByFieldName("function")
			if fnNode != nil {
				fnName := sourcecode.GetNodeText(fnNode, source)
				if strings.Contains(fnName, "innerHTML") || strings.Contains(fnName, "document.write") {
					args := n.ChildByFieldName("arguments")
					if args != nil && args.NamedChildCount() > 0 {
						firstArg := args.NamedChild(0)
						firstArgText := sourcecode.GetNodeText(firstArg, source)
						if firstArg.Type() == "identifier" && taintedVars[firstArgText] {
							f := finding.NewFinding(
								ruleID, name, severity, filePath,
								sourcecode.PositionToLine(n),
								message, cwe, firstArgText,
								"javascript", finding.ConfidenceHigh,
								"Sanitize user input before inserting into the DOM.",
								[]string{"https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html"},
							)
							f.Evidence = []finding.EvidenceItem{
								{Type: "DIRECT_SOURCE", Description: "Tainted variable reaches DOM API"},
							}
							findings = append(findings, f)
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
