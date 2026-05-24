package analyzers

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type JavaWeakCryptoAnalyzer struct{}

func init() {
	Register(&JavaWeakCryptoAnalyzer{})
}

func (a *JavaWeakCryptoAnalyzer) SupportedLanguages() []string {
	return []string{"java"}
}

func (a *JavaWeakCryptoAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string) []finding.Finding {
	const (
		ruleID   = "JAVA-CRYPTO-001"
		name     = "Java Weak Cryptographic Algorithm"
		severity = "MEDIUM"
		message  = "Use of weak cryptographic algorithm — possible security risk"
		cwe      = "CWE-327"
	)

	findings := make([]finding.Finding, 0)

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "string_literal" {
			text := sourcecode.GetNodeText(n, source)
			if strings.Contains(strings.ToUpper(text), "MD5") || 
			   strings.Contains(strings.ToUpper(text), "SHA1") ||
			   strings.Contains(strings.ToUpper(text), "SHA-1") {
				
				findings = append(findings, NewFinding(
					ruleID, name, severity, filePath,
					sourcecode.PositionToLine(n),
					message, cwe, text,
					"java", "MEDIUM", "Use stronger cryptographic algorithms like SHA-256 or SHA-3.",
					[]string{"https://owasp.org/www-community/vulnerabilities/Insecure_Cryptographic_Storage"},
				))
			}
		}

		for i := 0; i < int(n.ChildCount()); i++ {
			visit(n.Child(i))
		}
	}
	visit(node)

	return findings
}
