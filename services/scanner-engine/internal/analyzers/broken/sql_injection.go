package analyzers

import (
	"strconv"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type SQLIAnalyzer struct{}

func init() {
	Register(&SQLIAnalyzer{})
}

func (a *SQLIAnalyzer) SupportedLanguages() []string {
	return []string{"go"}
}

func (a *SQLIAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string) []finding.Finding {
	const (
		ruleID   = "GO-SQLI-001"
		name     = "Potential SQL Injection"
		severity = "CRITICAL"
		message  = "SQL query built with tainted string — possible SQL injection"
		cwe      = "CWE-89"
	)

	findings := make([]finding.Finding, 0)
	taintedVars := sourcecode.GlobalTaintEngine.AnalyzeTaint(node, source, "go")

	var currentFunc string
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "function_declaration" || n.Type() == "method_declaration" {
			oldFunc := currentFunc
			for i := 0; i < int(n.ChildCount()); i++ {
				child := n.Child(i)
				if child.Type() == "identifier" || child.Type() == "field_identifier" {
					currentFunc = child.Content(source)
					break
				}
			}
			
			