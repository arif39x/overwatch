package analyzers

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type JSPrototypePollutionAnalyzer struct{}

func init() {
	Register(&JSPrototypePollutionAnalyzer{})
}

func (a *JSPrototypePollutionAnalyzer) SupportedLanguages() []string {
	return []string{"javascript", "typescript"}
}

func (a *JSPrototypePollutionAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string) []finding.Finding {
	const (
		ruleID   = "JS-PROTO-001"
		name     = "JavaScript Prototype Pollution"
		severity = "HIGH"
		message  = "Possible prototype pollution via unsafe object property access or assignment"
		cwe      = "CWE-1321"
	)

	findings := make([]finding.Finding, 0)
	taintedVars := sourcecode.GlobalTaintEngine.AnalyzeTaint(node, source, "javascript")

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		