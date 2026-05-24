package analyzers

import (
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type PHPFileInclusionAnalyzer struct{}

func init() {
	Register(&PHPFileInclusionAnalyzer{})
}

func (a *PHPFileInclusionAnalyzer) SupportedLanguages() []string {
	return []string{"php"}
}

func (a *PHPFileInclusionAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string) []finding.Finding {
	const (
		ruleID   = "PHP-LFI-001"
		name     = "File Inclusion (PHP)"
		severity = "CRITICAL"
		message  = "Tainted variable used in include/require in PHP"
		cwe      = "CWE-98"
	)

	findings := make([]finding.Finding, 0)
	taintedVars := sourcecode.GlobalTaintEngine.AnalyzeTaint(node, source, "php")

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "include_expression" || n.Type() == "require_expression" || 
		   n.Type() == "include_once_expression" || n.Type() == "require_once_expression" {
			for i := 0; i < int(n.ChildCount()); i++ {
				child := n.Child(i)
				if child.Type() == "variable_name" && taintedVars[child.Content(source)] {
					findings = append(findings, NewFinding(
						ruleID, name, severity, filePath,
						sourcecode.PositionToLine(n),
						message, cwe, sourcecode.GetNodeText(child, source),
						"php", "HIGH", "Do not use user input to construct file paths for inclusion.",
						[]string{"https://owasp.org/www-project-top-ten/2017/A1_2017-Injection"},
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
