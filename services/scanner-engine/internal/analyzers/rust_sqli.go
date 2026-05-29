package analyzers

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type RustSQLIAnalyzer struct{}

func init() {
	Register(&RustSQLIAnalyzer{})
}

func (a *RustSQLIAnalyzer) Name() string { return "RUST-SQLI-001" }
func (a *RustSQLIAnalyzer) SupportedLanguages() []string {
	return []string{"rust"}
}

func (a *RustSQLIAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "RUST-SQLI-001"
		name     = "Rust SQL Injection"
		severity = "CRITICAL"
		message  = "SQL query built with format! macro — possible SQL injection"
		cwe      = "CWE-89"
	)

	findings := make([]finding.Finding, 0)
	taintedVars := sourcecode.GlobalTaintEngine.AnalyzeTaint(node, source, "rust")

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "call_expression" || n.Type() == "method_invocation" {
			fnNode := n.ChildByFieldName("function")
			if fnNode == nil {
				fnNode = n.ChildByFieldName("method")
			}

			if fnNode != nil {
				fnName := sourcecode.GetNodeText(fnNode, source)
				if strings.Contains(fnName, "query") || strings.Contains(fnName, "execute") {
					args := n.ChildByFieldName("arguments")
					if args != nil && args.NamedChildCount() > 0 {
						for i := 0; i < int(args.NamedChildCount()); i++ {
							arg := args.NamedChild(i)
							argText := sourcecode.GetNodeText(arg, source)
							if arg.Type() == "identifier" && taintedVars[argText] {
								f := finding.NewFinding(
									ruleID, name, severity, filePath,
									sourcecode.PositionToLine(n),
									message, cwe, argText,
									"rust", finding.ConfidenceHigh,
									"Use parameterized queries with sqlx or diesel to prevent SQL injection.",
									[]string{"https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"},
								)
								f.Evidence = []finding.EvidenceItem{
									{Type: "SINK_CONFIRMED_BY_TYPE", Description: "SQL query with potentially tainted argument"},
								}
								findings = append(findings, f)
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
