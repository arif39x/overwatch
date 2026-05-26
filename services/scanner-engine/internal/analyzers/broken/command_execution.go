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

func (a *CmdIAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
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
							f := finding.NewFinding(
								ruleID, name, severity, filePath,
								sourcecode.PositionToLine(n),
								message, cwe, sourcecode.GetNodeText(arg, source),
								"go", finding.ConfidenceHigh, "Avoid executing shell commands with user input.",
								[]string{"https://owasp.org/www-community/attacks/Command_Injection"},
							)
							f.Evidence = []finding.EvidenceItem{
								{Type: "DIRECT_SOURCE", Description: "Tainted variable reaches command execution sink"},
								{Type: "SINK_CONFIRMED_BY_TYPE", Description: "Command execution function identified via taint analysis"},
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
