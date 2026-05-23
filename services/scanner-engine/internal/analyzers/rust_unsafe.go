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

func (a *RustUnsafeAnalyzer) SupportedLanguages() []string {
	return []string{"rust"}
}

func (a *RustUnsafeAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string) []finding.Finding {
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
				