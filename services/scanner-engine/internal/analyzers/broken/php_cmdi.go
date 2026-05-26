package analyzers

import (
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type PHPCmdIAnalyzer struct{}

func init() {
	Register(&PHPCmdIAnalyzer{})
}

func (a *PHPCmdIAnalyzer) SupportedLanguages() []string {
	return []string{"php"}
}

func (a *PHPCmdIAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "PHP-CMDI-001"
		name     = "Command Injection (PHP)"
		severity = "CRITICAL"
		message  = "Command executed with tainted string in PHP"
		cwe      = "CWE-78"
	)

	findings := make([]finding.Finding, 0)
	taintedVars := sourcecode.GlobalTaintEngine.AnalyzeTaint(node, source, "php")

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		isSink, vulnClass := sourcecode.GlobalTaintEngine.IsSink(n, source, "php")
		if isSink && vulnClass == "cmdi" {
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
								"php", finding.ConfidenceHigh, "Avoid executing shell commands with user input. Use escapeshellarg().",
								[]string{"https://www.php.net/manual/en/function.escapeshellarg.php"},
							)
							f.Evidence = []finding.EvidenceItem{
								{Type: "DIRECT_SOURCE", Description: "Tainted variable reaches command execution sink"},
								{Type: "SANITIZER_ABSENT", Description: "No sanitizer applied to command argument"},
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
