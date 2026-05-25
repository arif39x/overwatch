package analyzers

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type XSSAnalyzer struct{}

func init() {
	Register(&XSSAnalyzer{})
}

func (a *XSSAnalyzer) SupportedLanguages() []string {
	return []string{"go"}
}

func (a *XSSAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "GO-XSS-001"
		name     = "Potential Cross-Site Scripting"
		severity = "HIGH"
		message  = "User input rendered directly to HTML — possible XSS"
		cwe      = "CWE-79"
	)

	findings := make([]finding.Finding, 0)
	taintedVars := sourcecode.GlobalTaintEngine.AnalyzeTaint(node, source, "go")

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		