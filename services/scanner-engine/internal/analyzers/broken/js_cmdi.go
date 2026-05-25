package analyzers

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type JSCMDIAnalyzer struct{}

func init() {
	Register(&JSCMDIAnalyzer{})
}

func (a *JSCMDIAnalyzer) SupportedLanguages() []string {
	return []string{"javascript", "typescript"}
}

func (a *JSCMDIAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "JS-CMDI-001"
		name     = "JavaScript Command Injection"
		severity = "CRITICAL"
		message  = "OS command built with tainted data — possible command injection"
		cwe      = "CWE-78"
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
				if strings.Contains(fnName, "exec") || strings.Contains(fnName, "spawn") {
					args := n.ChildByFieldName("arguments")
					if args != nil && args.NamedChildCount() > 0 {
						firstArg := args.NamedChild(0)
						firstArgText := sourcecode.GetNodeText(firstArg, source)

						if (firstArg.Type() == "identifier" && taintedVars[firstArgText]) ||
						   firstArg.Type() == "binary_expression" ||
						   firstArg.Type() == "template_string" {
							
							findings = append(findings, NewFinding(
								ruleID, name, severity, filePath,
								sourcecode.PositionToLine(n),
								message, cwe, firstArgText,
								"javascript", "HIGH", "Use child_process.execFile or child_process.spawn without shell: true, and pass arguments as an array.",
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
