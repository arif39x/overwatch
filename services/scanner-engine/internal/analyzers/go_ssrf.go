package analyzers

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type GoSSRFAnalyzer struct{}

func init() {
	Register(&GoSSRFAnalyzer{})
}

func (a *GoSSRFAnalyzer) SupportedLanguages() []string {
	return []string{"go"}
}

func (a *GoSSRFAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string) []finding.Finding {
	const (
		ruleID   = "GO-SSRF-001"
		name     = "Go SSRF"
		severity = "HIGH"
		message  = "HTTP request with tainted URL — possible SSRF"
		cwe      = "CWE-918"
	)

	findings := make([]finding.Finding, 0)
	taintedVars := sourcecode.GlobalTaintEngine.AnalyzeTaint(node, source, "go")

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "call_expression" {
			fnNode := n.ChildByFieldName("function")
			if fnNode != nil {
				fnName := sourcecode.GetNodeText(fnNode, source)
				if strings.Contains(fnName, "http.Get") || 
				   strings.Contains(fnName, "http.Post") || 
				   strings.Contains(fnName, "http.Head") ||
				   strings.Contains(fnName, "http.NewRequest") {
					
					args := n.ChildByFieldName("arguments")
					if args != nil && args.NamedChildCount() > 0 {
						urlArg := args.NamedChild(0)
						