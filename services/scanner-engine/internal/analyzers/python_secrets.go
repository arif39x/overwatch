package analyzers

import (
	"regexp"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type PythonSecretsAnalyzer struct{}

func init() {
	Register(&PythonSecretsAnalyzer{})
}

func (a *PythonSecretsAnalyzer) SupportedLanguages() []string {
	return []string{"python"}
}

func (a *PythonSecretsAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string) []finding.Finding {
	const (
		ruleID   = "PY-SECRET-001"
		name     = "Hardcoded Secret"
		severity = "HIGH"
		message  = "Potential hardcoded secret assigned to identifier"
		cwe      = "CWE-798"
	)

	findings := make([]finding.Finding, 0)
	secretRegex := regexp.MustCompile(`(?i)(api_key|password|secret|token|credential|access_key)`)

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "assignment" {
			left := n.ChildByFieldName("left")
			right := n.ChildByFieldName("right")
			if left != nil && right != nil {
				leftText := sourcecode.GetNodeText(left, source)
				if secretRegex.MatchString(leftText) {
					rightText := sourcecode.GetNodeText(right, source)
					