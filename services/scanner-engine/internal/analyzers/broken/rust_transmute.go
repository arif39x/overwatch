package analyzers

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type RustTransmuteAnalyzer struct{}

func init() {
	Register(&RustTransmuteAnalyzer{})
}

func (a *RustTransmuteAnalyzer) SupportedLanguages() []string {
	return []string{"rust"}
}

func (a *RustTransmuteAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "RUST-TRANSMUTE-001"
		name     = "Rust Dangerous Transmute"
		severity = "HIGH"
		message  = "Use of std::mem::transmute — extremely unsafe and can lead to undefined behavior"
		cwe      = "CWE-119"
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
				if strings.Contains(fnName, "transmute") {
					findings = append(findings, NewFinding(
						ruleID, name, severity, filePath,
						sourcecode.PositionToLine(n),
						message, cwe, fnName,
						"rust", "HIGH", "Prefer safer alternatives like 'as' casts, or specific conversion methods like 'from_bits', 'from_ne_bytes', etc.",
						[]string{"https://doc.rust-lang.org/std/mem/fn.transmute.html"},
					))
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
