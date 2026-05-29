package analyzers

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type GoSSRFAnalyzer struct{}

func init() {
	Register(&GoSSRFAnalyzer{})
}

func (a *GoSSRFAnalyzer) Name() string { return "GO-SSRF-001" }
func (a *GoSSRFAnalyzer) SupportedLanguages() []string {
	return []string{"go"}
}

func (a *GoSSRFAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "GO-SSRF-001"
		name     = "Go SSRF"
		severity = "HIGH"
		message  = "HTTP request with tainted URL — possible SSRF"
		cwe      = "CWE-918"
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
				if strings.Contains(fnName, "http.Get") ||
					strings.Contains(fnName, "http.Post") ||
					strings.Contains(fnName, "http.Head") ||
					strings.Contains(fnName, "http.NewRequest") {

					args := n.ChildByFieldName("arguments")
					if args != nil && args.NamedChildCount() > 0 {
						urlArg := args.NamedChild(0)
						urlText := sourcecode.GetNodeText(urlArg, source)
						if urlArg.Type() == "identifier" && taintedVars[urlText] {
							f := finding.NewFinding(
								ruleID, name, severity, filePath,
								sourcecode.PositionToLine(n),
								message, cwe, urlText,
								"go", finding.ConfidenceMedium,
								"Validate URLs against a whitelist of allowed hosts before making requests.",
								[]string{"https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"},
							)
							f.Evidence = []finding.EvidenceItem{
								{Type: "DIRECT_SOURCE", Description: "Tainted URL reaches HTTP client"},
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
