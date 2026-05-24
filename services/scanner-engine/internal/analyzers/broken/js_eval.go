package analyzers

import (

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type JSEvalAnalyzer struct{}

func init() {
	Register(&JSEvalAnalyzer{})
}

func (a *JSEvalAnalyzer) SupportedLanguages() []string {
	return []string{"javascript", "typescript"}
}

func (a *JSEvalAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string) []finding.Finding {
	const (
		ruleID   = "JS-EVAL-001"
		name     = "JavaScript Unsafe Eval"
		severity = "CRITICAL"
		message  = "Use of eval() or similar constructs with potentially tainted data"
		cwe      = "CWE-95"
	)

	findings := make([]finding.Finding, 0)
	taintedVars := sourcecode.GlobalTaintEngine.AnalyzeTaint(node, source, "javascript")

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "call_expression" {
			fnNode := n.ChildByFieldName("function")
			if fnNode != nil {
				fnName := sourcecode.GetNodeText(fnNode, source)
				if fnName == "eval" || fnName == "Function" || fnName == "setTimeout" || fnName == "setInterval" {
					args := n.ChildByFieldName("arguments")
					if args != nil && args.NamedChildCount() > 0 {
						firstArg := args.NamedChild(0)
						firstArgText := sourcecode.GetNodeText(firstArg, source)

						isUnsafe := false
						if (firstArg.Type() == "identifier" && taintedVars[firstArgText]) ||
						   firstArg.Type() == "binary_expression" ||
						   firstArg.Type() == "template_string" {
							isUnsafe = true
						}

						