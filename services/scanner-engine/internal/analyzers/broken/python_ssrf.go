package analyzers

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type PythonSSRFAnalyzer struct{}

func init() {
	Register(&PythonSSRFAnalyzer{})
}

func (a *PythonSSRFAnalyzer) SupportedLanguages() []string {
	return []string{"python"}
}

func (a *PythonSSRFAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "PY-SSRF-001"
		name     = "Python SSRF"
		severity = "HIGH"
		message  = "Request made with tainted URL — possible Server-Side Request Forgery"
		cwe      = "CWE-918"
	)

	findings := make([]finding.Finding, 0)
	taintedVars := sourcecode.GlobalTaintEngine.AnalyzeTaint(node, source, "python")

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "call" {
			fnNode := n.ChildByFieldName("function")
			if fnNode != nil {
				fnName := sourcecode.GetNodeText(fnNode, source)
				if strings.Contains(fnName, "requests.") || 
				   strings.Contains(fnName, "urllib.request.urlopen") || 
				   strings.Contains(fnName, "httpx.") {
					
					args := n.ChildByFieldName("arguments")
					if args != nil {
						for i := 0; i < int(args.NamedChildCount()); i++ {
							arg := args.NamedChild(i)
							argText := sourcecode.GetNodeText(arg, source)
							
							if (arg.Type() == "identifier" && taintedVars[argText]) ||
							   arg.Type() == "binary_operator" ||
							   arg.Type() == "f_string" {
								
								findings = append(findings, NewFinding(
									ruleID, name, severity, filePath,
									sourcecode.PositionToLine(n),
									message, cwe, argText,
									"python", "HIGH", "Validate and whitelist allowed domains/IPs for outgoing requests.",
									[]string{"https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"},
								))
								break
							}
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
