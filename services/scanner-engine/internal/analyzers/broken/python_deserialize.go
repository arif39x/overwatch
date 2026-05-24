package analyzers

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type PythonDeserializeAnalyzer struct{}

func init() {
	Register(&PythonDeserializeAnalyzer{})
}

func (a *PythonDeserializeAnalyzer) SupportedLanguages() []string {
	return []string{"python"}
}

func (a *PythonDeserializeAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string) []finding.Finding {
	const (
		ruleID   = "PY-DESER-001"
		name     = "Python Unsafe Deserialization"
		severity = "CRITICAL"
		message  = "Unsafe deserialization — possible remote code execution"
		cwe      = "CWE-502"
	)

	findings := make([]finding.Finding, 0)

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "call" {
			fnNode := n.ChildByFieldName("function")
			if fnNode != nil {
				fnName := sourcecode.GetNodeText(fnNode, source)
				if strings.Contains(fnName, "pickle.loads") || 
				   strings.Contains(fnName, "yaml.load") || 
				   strings.Contains(fnName, "marshal.loads") ||
				   strings.Contains(fnName, "shelve.open") {
					
					