package analyzers

import (
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type RubyEvalAnalyzer struct{}

func init() {
	Register(&RubyEvalAnalyzer{})
}

func (a *RubyEvalAnalyzer) Name() string { return "RUBY-EVAL-001" }
func (a *RubyEvalAnalyzer) SupportedLanguages() []string {
	return []string{"ruby"}
}

func (a *RubyEvalAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "RUBY-EVAL-001"
		name     = "Ruby Code Execution"
		severity = "CRITICAL"
		message  = "Use of eval or instance_eval — possible code execution"
		cwe      = "CWE-94"
	)

	findings := make([]finding.Finding, 0)
	taintedVars := sourcecode.GlobalTaintEngine.AnalyzeTaint(node, source, "ruby")

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "call" || n.Type() == "method_call" {
			methodNode := n.ChildByFieldName("method")
			if methodNode != nil {
				methodName := sourcecode.GetNodeText(methodNode, source)
				if methodName == "eval" || methodName == "instance_eval" || methodName == "class_eval" || methodName == "module_eval" {
					args := n.ChildByFieldName("arguments")
					if args != nil && args.NamedChildCount() > 0 {
						arg := args.NamedChild(0)
						argText := sourcecode.GetNodeText(arg, source)
						if (arg.Type() == "identifier" && taintedVars[argText]) ||
							arg.Type() == "interpolation" {
							f := finding.NewFinding(
								ruleID, name, severity, filePath,
								sourcecode.PositionToLine(n),
								message, cwe, argText,
								"ruby", finding.ConfidenceHigh,
								"Avoid eval() with tainted data.",
								[]string{"https://owasp.org/www-community/attacks/Direct_Dynamic_Code_Evaluation_Eval%20injection"},
							)
							f.Evidence = []finding.EvidenceItem{
								{Type: "SINK_CONFIRMED_BY_TYPE", Description: "eval() call with potentially tainted argument"},
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
