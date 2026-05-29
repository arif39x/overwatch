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

func (a *JSEvalAnalyzer) Name() string { return "JS-EVAL-001" }
func (a *JSEvalAnalyzer) SupportedLanguages() []string {
	return []string{"javascript", "typescript"}
}

func (a *JSEvalAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
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

						if isUnsafe || firstArg.Type() == "binary_expression" {
							f := finding.NewFinding(
								ruleID, name, severity, filePath,
								sourcecode.PositionToLine(n),
								message, cwe, firstArgText,
								"javascript", finding.ConfidenceHigh,
								"Avoid eval() and similar functions with tainted data.",
								[]string{"https://owasp.org/www-community/attacks/Direct_Dynamic_Code_Evaluation_Eval%20injection"},
							)
							f.Evidence = []finding.EvidenceItem{
								{Type: "SINK_CONFIRMED_BY_TYPE", Description: "eval() call with potentially tainted data"},
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
