package analyzers

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type XSSAnalyzer struct{}

func init() {
	Register(&XSSAnalyzer{})
}

func (a *XSSAnalyzer) Name() string { return "GO-XSS-001" }
func (a *XSSAnalyzer) SupportedLanguages() []string {
	return []string{"go"}
}

func (a *XSSAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "GO-XSS-001"
		name     = "Potential Cross-Site Scripting"
		severity = "HIGH"
		message  = "User input rendered directly to HTML — possible XSS"
		cwe      = "CWE-79"
	)

	findings := make([]finding.Finding, 0)
	taintedVars := sourcecode.GlobalTaintEngine.AnalyzeTaint(node, source, "go")

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "call_expression" {
			fnNode := n.ChildByFieldName("function")
			if fnNode != nil {
				fnName := sourcecode.GetNodeText(fnNode, source)
				if strings.Contains(fnName, "Write") || fnName == "w.Write" || fnName == "fmt.Fprint" {
					args := n.ChildByFieldName("arguments")
					if args != nil && args.NamedChildCount() > 0 {
						firstArg := args.NamedChild(0)
						firstArgText := sourcecode.GetNodeText(firstArg, source)
						if firstArg.Type() == "identifier" && taintedVars[firstArgText] {
							f := finding.NewFinding(
								ruleID, name, severity, filePath,
								sourcecode.PositionToLine(n),
								message, cwe, firstArgText,
								"go", finding.ConfidenceHigh,
								"Sanitize user input before rendering in HTTP responses.",
								[]string{"https://owasp.org/www-community/attacks/xss/"},
							)
							f.Evidence = []finding.EvidenceItem{
								{Type: "DIRECT_SOURCE", Description: "Tainted variable reaches HTTP response writer"},
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
