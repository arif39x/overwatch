package analyzers

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type JavaSQLIAnalyzer struct{}

func init() {
	Register(&JavaSQLIAnalyzer{})
}

func (a *JavaSQLIAnalyzer) SupportedLanguages() []string {
	return []string{"java"}
}

func (a *JavaSQLIAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "JAVA-SQLI-001"
		name     = "Java SQL Injection"
		severity = "CRITICAL"
		message  = "SQL query built with string concatenation — possible SQL injection"
		cwe      = "CWE-89"
	)

	findings := make([]finding.Finding, 0)
	taintedVars := sourcecode.GlobalTaintEngine.AnalyzeTaint(node, source, "java")

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "method_invocation" {
			nameNode := n.ChildByFieldName("name")
			if nameNode != nil {
				fnName := sourcecode.GetNodeText(nameNode, source)
				if fnName == "execute" || fnName == "executeQuery" || fnName == "executeUpdate" {
					args := n.ChildByFieldName("arguments")
					if args != nil && args.NamedChildCount() > 0 {
						queryArg := args.NamedChild(0)
						queryText := sourcecode.GetNodeText(queryArg, source)

						if (queryArg.Type() == "identifier" && taintedVars[queryText]) ||
						   queryArg.Type() == "binary_expression" || 