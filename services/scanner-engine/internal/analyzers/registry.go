package analyzers

import (
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

var (
	registry []Analyzer
)

func Register(a Analyzer) {
	registry = append(registry, a)
}

func RunAll(files []*sourcecode.File) []finding.Finding {
	var allFindings []finding.Finding
	for _, f := range files {
		var st *sourcecode.SymbolTable
		if f.Semantics != nil {
			st = f.Semantics.SymbolTable
		}
		for _, a := range registry {
			findings := a.Analyze(f.AST, f.Content, f.Path, st)
			allFindings = append(allFindings, findings...)
		}
	}
	return allFindings
}
