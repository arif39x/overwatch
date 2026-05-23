package analyzers

import (
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type CUseAfterFreeAnalyzer struct{}

func init() {
	Register(&CUseAfterFreeAnalyzer{})
}

func (a *CUseAfterFreeAnalyzer) SupportedLanguages() []string {
	return []string{"c", "cpp"}
}

func (a *CUseAfterFreeAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string) []finding.Finding {
	const (
		ruleID   = "C-UAF-001"
		name     = "C/C++ Use After Free"
		severity = "HIGH"
		message  = "Variable used after being freed — possible use-after-free vulnerability"
		cwe      = "CWE-416"
	)

	findings := make([]finding.Finding, 0)

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		