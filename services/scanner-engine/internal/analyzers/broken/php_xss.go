package analyzers

import (
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type PHPXSSAnalyzer struct{}

func init() {
	Register(&PHPXSSAnalyzer{})
}

func (a *PHPXSSAnalyzer) SupportedLanguages() []string {
	return []string{"php"}
}

func (a *PHPXSSAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string) []finding.Finding {
	const (
		ruleID   = "PHP-XSS-001"
		name     = "Cross-Site Scripting (PHP)"
		severity = "HIGH"
		message  = "Tainted variable echoed directly in PHP"
		cwe      = "CWE-79"
	)

	findings := make([]finding.Finding, 0)
	taintedVars := sourcecode.GlobalTaintEngine.AnalyzeTaint(node, source, "php")

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "echo_statement" || n.Type() == "print_statement" {
			for i := 0; i < int(n.ChildCount()); i++ {
				child := n.Child(i)
				if child.Type() == "variable_name" && taintedVars[child.Content(source)] {
					findings = append(findings, NewFinding(
						ruleID, name, severity, filePath,
						sourcecode.PositionToLine(n),
						message, cwe, sourcecode.GetNodeText(child, source),
						"php", "HIGH", "Use htmlspecialchars() before echoing user input.",
						[]string{"https://www.php.net/manual/en/function.htmlspecialchars.php"},
					))
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
