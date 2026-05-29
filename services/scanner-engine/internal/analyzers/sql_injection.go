package analyzers

import (
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type SQLIAnalyzer struct{}

func init() {
	Register(&SQLIAnalyzer{})
}

func (a *SQLIAnalyzer) Name() string { return "GO-SQLI-001" }

func (a *SQLIAnalyzer) SupportedLanguages() []string {
	return []string{"go"}
}

func (a *SQLIAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "GO-SQLI-001"
		name     = "Potential SQL Injection"
		severity = "CRITICAL"
		message  = "SQL query built with tainted string — possible SQL injection"
		cwe      = "CWE-89"
	)

	findings := make([]finding.Finding, 0)
	taintedVars := sourcecode.GlobalTaintEngine.AnalyzeTaint(node, source, "go")

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		isSink, vulnClass := sourcecode.GlobalTaintEngine.IsSink(n, source, "go")
		if isSink && vulnClass == "sqli" {
			args := n.ChildByFieldName("arguments")
			if args != nil && args.NamedChildCount() > 0 {
				queryArg := args.NamedChild(0)
				queryText := sourcecode.GetNodeText(queryArg, source)
				if queryArg.Type() == "identifier" && taintedVars[queryText] {
					f := finding.NewFinding(
						ruleID, name, severity, filePath,
						sourcecode.PositionToLine(n),
						message, cwe, queryText,
						"go", finding.ConfidenceHigh,
						"Use parameterized queries with placeholders instead of string concatenation.",
						[]string{"https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"},
					)
					f.Evidence = []finding.EvidenceItem{
						{Type: "SINK_CONFIRMED_BY_TYPE", Description: sourcecode.GetNodeText(n, source) + " called with tainted argument"},
					}
					findings = append(findings, f)
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
