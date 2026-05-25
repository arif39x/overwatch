package sourcecode

import (
	"github.com/overwatch/scanner-engine/internal/rules/compiler"
	sitter "github.com/smacker/go-tree-sitter"
)

type Rule struct {
	ID         string `yaml:"id"`
	Language   string `yaml:"language"`
	Kind       string `yaml:"kind"`
	Identifier string `yaml:"identifier"`
	VulnClass  string `yaml:"vuln_class,omitempty"`
}

type CallGraph struct {
	Edges      map[string][]CallGraphEdge
	Speculative bool
}

type CallGraphEdge struct {
	Callee      string
	Speculative bool
}

func NewCallGraph() *CallGraph {
	return &CallGraph{
		Edges: make(map[string][]CallGraphEdge),
	}
}

func (cg *CallGraph) AddEdge(caller, callee string, speculative bool) {
	for _, e := range cg.Edges[caller] {
		if e.Callee == callee && e.Speculative == speculative {
			return
		}
	}
	cg.Edges[caller] = append(cg.Edges[caller], CallGraphEdge{
		Callee:      callee,
		Speculative: speculative,
	})
}

func (cg *CallGraph) GetCallees(caller string) []CallGraphEdge {
	return cg.Edges[caller]
}

func (cg *CallGraph) Callers() []string {
	var callers []string
	for caller := range cg.Edges {
		callers = append(callers, caller)
	}
	return callers
}

type TaintEngine struct {
	Sources       []Rule
	Sinks         []Rule
	Sanitizers    []Rule
	CallGraph     *CallGraph
	SymbolTable   *SymbolTable
	TaintedParams map[string]map[int]bool
}

var GlobalTaintEngine *TaintEngine

func InitTaintEngine(rulesDir string) error {
	GlobalTaintEngine = &TaintEngine{}
	return nil
}

func (e *TaintEngine) Resolve(identifier string, symbolTable *SymbolTable) string {
	if symbolTable == nil {
		return ""
	}
	sym := symbolTable.Lookup(identifier)
	if sym == nil {
		return ""
	}
	return sym.DeclaredType
}

func (e *TaintEngine) IsTypeCompatible(declaredType, sinkType string) bool {
	if declaredType == "" {
		return true
	}
	polyTypes := map[string]bool{
		"interface{}": true,
		"any":         true,
		"Object":      true,
		"interface":   true,
		"var":         true,
	}
	if polyTypes[declaredType] {
		return true
	}
	if sinkType == "" {
		return true
	}
	return declaredType == sinkType
}

func (e *TaintEngine) AnalyzeTaint(node *sitter.Node, source []byte, lang string) map[string]bool {
	return make(map[string]bool)
}

func (e *TaintEngine) ExecuteOQL(file *File, query *compiler.Query) bool {
	return false
}

func GetNodeText(n *sitter.Node, source []byte) string {
	return n.Content(source)
}

func PositionToLine(n *sitter.Node) int {
	return int(n.StartPoint().Row) + 1
}
