package analyzers

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type SecretAnalyzer struct{}

func init() {
	Register(&SecretAnalyzer{})
}

func (a *SecretAnalyzer) SupportedLanguages() []string {
	return []string{"go"}
}

func (a *SecretAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string) []finding.Finding {
	const (
		ruleID   = "GEN-SECRET-001"
		name     = "Hardcoded Secret"
		severity = "HIGH"
		message  = "Potential hardcoded secret detected"
		cwe      = "CWE-798"
	)

	findings := make([]finding.Finding, 0)
	secretKeywords := []string{"password", "secret", "token", "api_key", "private_key"}

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "identifier" {
			name := strings.ToLower(n.Content(source))
			for _, kw := range secretKeywords {
				if strings.Contains(name, kw) {
					