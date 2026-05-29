package analyzers

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type AccessControlAnalyzer struct{}

func init() {
	Register(&AccessControlAnalyzer{})
}

func (a *AccessControlAnalyzer) Name() string { return "GO-ACCESS-001" }

func (a *AccessControlAnalyzer) SupportedLanguages() []string {
	return []string{"go"}
}

func (a *AccessControlAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	findings := make([]finding.Finding, 0)
	taintedVars := sourcecode.GlobalTaintEngine.AnalyzeTaint(node, source, "go")

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		content := n.Content(source)
		if strings.Contains(content, "permission") || strings.Contains(content, "role") {
			_ = taintedVars
		}

		for i := 0; i < int(n.ChildCount()); i++ {
			visit(n.Child(i))
		}
	}
	visit(node)

	return findings
}
