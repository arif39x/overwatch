package analyzers

import (
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type PHPSQLIAnalyzer struct{}

func init() {
	Register(&PHPSQLIAnalyzer{})
}

func (a *PHPSQLIAnalyzer) Name() string { return "PHP-SQLI-001" }
func (a *PHPSQLIAnalyzer) SupportedLanguages() []string {
	return []string{"php"}
}

func (a *PHPSQLIAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "PHP-SQLI-001"
		name     = "SQL Injection (PHP)"
		severity = "CRITICAL"
		message  = "SQL query built with tainted string in PHP"
		cwe      = "CWE-89"
	)

	findings := make([]finding.Finding, 0)
	taintedVars := sourcecode.GlobalTaintEngine.AnalyzeTaint(node, source, "php")

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		isSink, vulnClass := sourcecode.GlobalTaintEngine.IsSink(n, source, "php")
		if isSink && vulnClass == "sqli" {
			for i := 0; i < int(n.ChildCount()); i++ {
				child := n.Child(i)
				if child.Type() == "argument_list" {
					for j := 0; j < int(child.ChildCount()); j++ {
						arg := child.Child(j)
						if arg.Type() == "variable_name" && taintedVars[arg.Content(source)] {
							f := finding.NewFinding(
								ruleID, name, severity, filePath,
								sourcecode.PositionToLine(n),
								message, cwe, sourcecode.GetNodeText(arg, source),
								"php", finding.ConfidenceHigh, "Use PDO or MySQLi parameterized queries.",
								[]string{"https://www.php.net/manual/en/security.database.sql-injection.php"},
							)
							f.Evidence = []finding.EvidenceItem{
								{Type: "DIRECT_SOURCE", Description: "Tainted data reaches SQL query"},
								{Type: "SINK_CONFIRMED_BY_TYPE", Description: "SQL injection sink identified via taint analysis"},
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
