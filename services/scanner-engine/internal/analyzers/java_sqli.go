package analyzers

import (
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type JavaSQLIAnalyzer struct{}

func init() {
	Register(&JavaSQLIAnalyzer{})
}

func (a *JavaSQLIAnalyzer) Name() string { return "JAVA-SQLI-001" }
func (a *JavaSQLIAnalyzer) SupportedLanguages() []string {
	return []string{"java"}
}

func (a *JavaSQLIAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "JAVA-SQLI-001"
		name     = "Java SQL Injection"
		severity = "CRITICAL"
		message  = "SQL query built with string concatenation — possible SQL injection"
		cwe      = "CWE-89"
	)

	findings := make([]finding.Finding, 0)
	taintedVars := sourcecode.GlobalTaintEngine.AnalyzeTaint(node, source, "java")

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "method_invocation" {
			nameNode := n.ChildByFieldName("name")
			if nameNode != nil {
				fnName := sourcecode.GetNodeText(nameNode, source)
				if fnName == "execute" || fnName == "executeQuery" || fnName == "executeUpdate" {
					args := n.ChildByFieldName("arguments")
					if args != nil && args.NamedChildCount() > 0 {
						queryArg := args.NamedChild(0)
						queryText := sourcecode.GetNodeText(queryArg, source)

						if (queryArg.Type() == "identifier" && taintedVars[queryText]) ||
							queryArg.Type() == "binary_expression" {
							f := finding.NewFinding(
								ruleID, name, severity, filePath,
								sourcecode.PositionToLine(n),
								message, cwe, queryText,
								"java", finding.ConfidenceHigh,
								"Use prepared statements (parameterized queries) instead of string concatenation.",
								[]string{"https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"},
							)
							f.Evidence = []finding.EvidenceItem{
								{Type: "SINK_CONFIRMED_BY_TYPE", Description: "SQL query built with string concatenation"},
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
