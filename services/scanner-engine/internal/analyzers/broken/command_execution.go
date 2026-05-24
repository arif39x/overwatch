package analyzers

import (
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type CmdIAnalyzer struct{}

func init() {
	Register(&CmdIAnalyzer{})
}

func (a *CmdIAnalyzer) SupportedLanguages() []string {
	return []string{"go"}
}

func (a *CmdIAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string) []finding.Finding {
	const (
		ruleID   = "GO-CMDI-001"
		name     = "Potential Command Injection"
		severity = "CRITICAL"
		message  = "Command executed with tainted string — possible command injection"
		cwe      = "CWE-78"
	)

	findings := make([]finding.Finding, 0)
	taintedVars := sourcecode.GlobalTaintEngine.AnalyzeTaint(node, source, "go")

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		isSink, vulnClass := sourcecode.GlobalTaintEngine.IsSink(n, source, "go")
		if isSink && vulnClass == "cmdi" {
			for i := 0; i < int(n.ChildCount()); i++ {
				child := n.Child(i)
				if child.Type() == "argument_list" {
					for j := 0; j < int(child.ChildCount()); j++ {
						arg := child.Child(j)
						if arg.Type() == "identifier" && taintedVars[arg.Content(source)] {
							findings = append(findings, NewFinding(
								ruleID, name, severity, filePath,
								sourcecode.PositionToLine(n),
								message, cwe, sourcecode.GetNodeText(arg, source),
								"go", "HIGH", "Avoid executing shell commands with user input.",
								[]string{"https://owasp.org/www-community/attacks/Command_Injection"},
							))
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
