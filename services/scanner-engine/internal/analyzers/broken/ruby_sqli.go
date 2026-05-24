package analyzers

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type RubySQLIAnalyzer struct{}

func init() {
	Register(&RubySQLIAnalyzer{})
}

func (a *RubySQLIAnalyzer) SupportedLanguages() []string {
	return []string{"ruby"}
}

func (a *RubySQLIAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string) []finding.Finding {
	const (
		ruleID   = "RUBY-SQLI-001"
		name     = "Ruby SQL Injection"
		severity = "CRITICAL"
		message  = "SQL query built with string interpolation — possible SQL injection"
		cwe      = "CWE-89"
	)

	findings := make([]finding.Finding, 0)

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "call" || n.Type() == "method_call" {
			methodNode := n.ChildByFieldName("method")
			if methodNode != nil {
				methodName := sourcecode.GetNodeText(methodNode, source)
				if methodName == "where" || methodName == "find_by" || methodName == "execute" {
					args := n.ChildByFieldName("arguments")
					if args != nil && args.NamedChildCount() > 0 {
						queryArg := args.NamedChild(0)
						