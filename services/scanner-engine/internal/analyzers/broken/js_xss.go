package analyzers

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type JSXXSAnalyzer struct{}

func init() {
	Register(&JSXXSAnalyzer{})
}

func (a *JSXXSAnalyzer) SupportedLanguages() []string {
	return []string{"javascript", "typescript"}
}

func (a *JSXXSAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string) []finding.Finding {
	const (
		ruleID   = "JS-XSS-001"
		name     = "JavaScript Cross-Site Scripting"
		severity = "HIGH"
		message  = "Unsafe DOM manipulation — possible Cross-Site Scripting"
		cwe      = "CWE-79"
	)

	findings := make([]finding.Finding, 0)
	taintedVars := sourcecode.GlobalTaintEngine.AnalyzeTaint(node, source, "javascript")

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		