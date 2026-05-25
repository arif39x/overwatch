package analyzers

import (

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type CCMDIAnalyzer struct{}

func init() {
	Register(&CCMDIAnalyzer{})
}

func (a *CCMDIAnalyzer) SupportedLanguages() []string {
	return []string{"c", "cpp"}
}

func (a *CCMDIAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "C-CMDI-001"
		name     = "C/C++ Command Injection"
		severity = "CRITICAL"
		message  = "OS command built with tainted data — possible command injection"
		cwe      = "CWE-78"
	)

	findings := make([]finding.Finding, 0)
	taintedVars := sourcecode.GlobalTaintEngine.AnalyzeTaint(node, source, "c")

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "call_expression" {
			fnNode := n.ChildByFieldName("function")
			if fnNode != nil {
				fnName := sourcecode.GetNodeText(fnNode, source)
				if fnName == "system" || fnName == "popen" {
					args := n.ChildByFieldName("arguments")
					if args != nil && args.NamedChildCount() > 0 {
						firstArg := args.NamedChild(0)
						firstArgText := sourcecode.GetNodeText(firstArg, source)

						if (firstArg.Type() == "identifier" && taintedVars[firstArgText]) ||
						   firstArg.Type() == "binary_expression" {
							
							findings = append(findings, NewFinding(
								ruleID, name, severity, filePath,
								sourcecode.PositionToLine(n),
								message, cwe, firstArgText,
								"c", "HIGH", "Avoid using system() or popen() with user-controlled input. Use exec*() family of functions with arguments passed as an array.",
								[]string{"https://owasp.org/www-community/attacks/Command_Injection"},
							))
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
