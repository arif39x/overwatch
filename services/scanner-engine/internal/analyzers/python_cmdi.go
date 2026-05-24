package analyzers

import (
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type PythonCMDIAnalyzer struct{}

func init() {
	Register(&PythonCMDIAnalyzer{})
}

func (a *PythonCMDIAnalyzer) Name() string {
	return "Python Command Injection"
}

func (a *PythonCMDIAnalyzer) SupportedLanguages() []string {
	return []string{"python"}
}

func (a *PythonCMDIAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string) []finding.Finding {
	findings := make([]finding.Finding, 0)
	if node == nil {
		return findings
	}

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n.Type() == "call" {
			
			findings = append(findings, finding.NewFinding(
				"PY-CMDI-001", "Python Command Injection", "CRITICAL", filePath,
				sourcecode.PositionToLine(n),
				"OS command built with tainted data", "CWE-78", n.Content(source),
				"python", "HIGH", "Avoid using shell=True",
				[]string{"https://owasp.org/www-community/attacks/Command_Injection"},
			))
		}
		for i := 0; i < int(n.ChildCount()); i++ {
			visit(n.Child(i))
		}
	}
	visit(node)
	return findings
}
