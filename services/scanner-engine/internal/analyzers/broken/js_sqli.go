package analyzers

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type JSSQLIAnalyzer struct{}

func init() {
	Register(&JSSQLIAnalyzer{})
}

func (a *JSSQLIAnalyzer) SupportedLanguages() []string {
	return []string{"javascript", "typescript"}
}

func (a *JSSQLIAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "JS-SQLI-001"
		name     = "JavaScript SQL Injection"
		severity = "CRITICAL"
		message  = "SQL query built with string concatenation — possible SQL injection"
		cwe      = "CWE-89"
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
				if strings.Contains(fnName, "query") || strings.Contains(fnName, "execute") || strings.Contains(fnName, "raw") {
					args := n.ChildByFieldName("arguments")
					if args != nil {
						for i := 0; i < int(args.NamedChildCount()); i++ {
							arg := args.NamedChild(i)
							argText := sourcecode.GetNodeText(arg, source)
							
							if (arg.Type() == "identifier" && taintedVars[argText]) ||
							   arg.Type() == "binary_expression" ||
							   arg.Type() == "template_string" {
								
								findings = append(findings, NewFinding(
									ruleID, name, severity, filePath,
									sourcecode.PositionToLine(n),
									message, cwe, argText,
									"javascript", "HIGH", "Use parameterized queries or ORM features to handle user input safely.",
									[]string{"https://owasp.org/www-community/attacks/SQL_Injection"},
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
