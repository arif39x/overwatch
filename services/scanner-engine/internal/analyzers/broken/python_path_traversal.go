package analyzers

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type PythonPathTraversalAnalyzer struct{}

func init() {
	Register(&PythonPathTraversalAnalyzer{})
}

func (a *PythonPathTraversalAnalyzer) SupportedLanguages() []string {
	return []string{"python"}
}

func (a *PythonPathTraversalAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "PY-PATH-001"
		name     = "Python Path Traversal"
		severity = "HIGH"
		message  = "File path built with tainted data — possible path traversal"
		cwe      = "CWE-22"
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
				if fnName == "open" || strings.Contains(fnName, "os.path.join") || strings.Contains(fnName, "os.listdir") {
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
									"python", "HIGH", "Validate file paths and use os.path.basename() on user input.",
									[]string{"https://owasp.org/www-community/attacks/Path_Traversal"},
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
