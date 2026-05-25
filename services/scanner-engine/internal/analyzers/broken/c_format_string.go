package analyzers

import (

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type CFormatStringAnalyzer struct{}

func init() {
	Register(&CFormatStringAnalyzer{})
}

func (a *CFormatStringAnalyzer) SupportedLanguages() []string {
	return []string{"c", "cpp"}
}

func (a *CFormatStringAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "C-FORMAT-001"
		name     = "C/C++ Format String Vulnerability"
		severity = "HIGH"
		message  = "Unsafe format string — possible information leak or code execution"
		cwe      = "CWE-134"
	)

	findings := make([]finding.Finding, 0)

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "call_expression" {
			fnNode := n.ChildByFieldName("function")
			if fnNode != nil {
				fnName := sourcecode.GetNodeText(fnNode, source)
				if fnName == "printf" || fnName == "fprintf" || fnName == "sprintf" || fnName == "snprintf" {
					args := n.ChildByFieldName("arguments")
					if args != nil && args.NamedChildCount() > 0 {
						