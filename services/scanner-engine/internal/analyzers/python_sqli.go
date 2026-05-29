package analyzers

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type PythonSQLIAnalyzer struct{}

func init() {
	Register(&PythonSQLIAnalyzer{})
}

func (a *PythonSQLIAnalyzer) Name() string { return "PY-SQLI-001" }
func (a *PythonSQLIAnalyzer) SupportedLanguages() []string {
	return []string{"python"}
}

func (a *PythonSQLIAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "PY-SQLI-001"
		name     = "Python SQL Injection"
		severity = "CRITICAL"
		message  = "SQL query built with string formatting or tainted data — possible SQL injection"
		cwe      = "CWE-89"
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
				if strings.Contains(fnName, "execute") {
					args := n.ChildByFieldName("arguments")
					if args != nil {
						for i := 0; i < int(args.NamedChildCount()); i++ {
							arg := args.NamedChild(i)
							argText := sourcecode.GetNodeText(arg, source)

							isUnsafe := false
							if arg.Type() == "identifier" && taintedVars[argText] {
								isUnsafe = true
							}
							if arg.Type() == "binary_operator" || arg.Type() == "string" {
								content := sourcecode.GetNodeText(arg, source)
								if strings.Contains(content, "%s") || strings.Contains(content, "{") {
									isUnsafe = true
								}
							}

							if isUnsafe {
								f := finding.NewFinding(
									ruleID, name, severity, filePath,
									sourcecode.PositionToLine(n),
									message, cwe, argText,
									"python", finding.ConfidenceHigh,
									"Use parameterized queries instead of string formatting.",
									[]string{"https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"},
								)
								f.Evidence = []finding.EvidenceItem{
									{Type: "SINK_CONFIRMED_BY_TYPE", Description: "SQL execute with potentially tainted argument"},
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
