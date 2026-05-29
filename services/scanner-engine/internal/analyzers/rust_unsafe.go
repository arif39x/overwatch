package analyzers

import (
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type RustUnsafeAnalyzer struct{}

func init() {
	Register(&RustUnsafeAnalyzer{})
}

func (a *RustUnsafeAnalyzer) Name() string { return "RUST-UNSAFE-001" }
func (a *RustUnsafeAnalyzer) SupportedLanguages() []string {
	return []string{"rust"}
}

func (a *RustUnsafeAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "RUST-UNSAFE-001"
		name     = "Rust Unsafe Block with Raw Pointer Dereference"
		severity = "MEDIUM"
		message  = "Unsafe block contains raw pointer dereference — potentially memory unsafe"
		cwe      = "CWE-119"
	)

	findings := make([]finding.Finding, 0)

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "unsafe_block" {
			var checkDereference func(*sitter.Node)
			checkDereference = func(cn *sitter.Node) {
				if cn == nil {
					return
				}
				if cn.Type() == "pointer_dereference_expression" {
					f := finding.NewFinding(
						ruleID, name, severity, filePath,
						sourcecode.PositionToLine(cn),
						message, cwe, sourcecode.GetNodeText(cn, source),
						"rust", finding.ConfidenceMedium,
						"Minimize use of unsafe blocks and raw pointer dereferences.",
						[]string{"https://doc.rust-lang.org/book/ch19-01-unsafe-rust.html"},
					)
					f.Evidence = []finding.EvidenceItem{
						{Type: "SINK_CONFIRMED_BY_TYPE", Description: "Raw pointer dereference inside unsafe block"},
					}
					findings = append(findings, f)
				}
				for i := 0; i < int(cn.ChildCount()); i++ {
					checkDereference(cn.Child(i))
				}
			}
			checkDereference(n)
		}

		for i := 0; i < int(n.ChildCount()); i++ {
			visit(n.Child(i))
		}
	}
	visit(node)

	return findings
}
