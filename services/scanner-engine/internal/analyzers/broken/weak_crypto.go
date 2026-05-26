package analyzers

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type WeakCryptoAnalyzer struct{}

func init() {
	Register(&WeakCryptoAnalyzer{})
}

func (a *WeakCryptoAnalyzer) SupportedLanguages() []string {
	return []string{"go"}
}

func (a *WeakCryptoAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	const (
		ruleID   = "GO-CRYPTO-001"
		name     = "Weak Cryptographic Algorithm"
		severity = "MEDIUM"
		message  = "Use of weak cryptographic algorithm (MD5 or SHA1)"
		cwe      = "CWE-327"
	)

	findings := make([]finding.Finding, 0)
	weakAlgos := []string{"md5.New", "sha1.New"}

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		content := n.Content(source)
		for _, algo := range weakAlgos {
			if strings.Contains(content, algo) {
				f := finding.NewFinding(
					ruleID, name, severity, filePath,
					sourcecode.PositionToLine(n),
					message, cwe, sourcecode.GetNodeText(n, source),
					"go", finding.ConfidenceHigh, "Use stronger algorithms like SHA-256 or SHA-3.",
					[]string{"https://owasp.org/www-community/vulnerabilities/Insecure_Cryptographic_Storage"},
				)
				f.Evidence = []finding.EvidenceItem{
					{Type: "SINK_CONFIRMED_BY_TYPE", Description: "Weak cryptographic algorithm referenced"},
				}
				findings = append(findings, f)
			}
		}

		for i := 0; i < int(n.ChildCount()); i++ {
			visit(n.Child(i))
		}
	}
	visit(node)

	return findings
}
