package analyzers

import (
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
)

type Analyzer interface {
	Name() string
	SupportedLanguages() []string
	Analyze(node *sitter.Node, source []byte, filePath string) []finding.Finding
}
