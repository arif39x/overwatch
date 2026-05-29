package analyzers

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type GoOpenRedirectAnalyzer struct{}

func init() {
	Register(&GoOpenRedirectAnalyzer{})
}

func (a *GoOpenRedirectAnalyzer) Name() string { return "GO-OR-001" }
func (a *GoOpenRedirectAnalyzer) SupportedLanguages() []string {
	return []string{"go"}
}

func (a *GoOpenRedirectAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "GO-OR-001"
		name     = "Go Open Redirect"
		severity = "MEDIUM"
		message  = "HTTP redirect with tainted URL — possible open redirect"
		cwe      = "CWE-601"
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
				if strings.Contains(fnName, "http.Redirect") {
					args := n.ChildByFieldName("arguments")
					if args != nil && args.NamedChildCount() > 2 {
						urlArg := args.NamedChild(2)
						urlText := sourcecode.GetNodeText(urlArg, source)
						if urlArg.Type() == "identifier" && taintedVars[urlText] {
							f := finding.NewFinding(
								ruleID, name, severity, filePath,
								sourcecode.PositionToLine(n),
								message, cwe, urlText,
								"go", finding.ConfidenceMedium,
								"Validate and whitelist redirect URLs to prevent open redirects.",
								[]string{"https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"},
							)
							f.Evidence = []finding.EvidenceItem{
								{Type: "DIRECT_SOURCE", Description: "Tainted URL reaches http.Redirect"},
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
