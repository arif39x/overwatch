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

type CallGraph struct{}

type TaintEngine struct {
	Sources       []Rule
	Sinks         []Rule
	Sanitizers    []Rule
	CallGraph     *CallGraph
	TaintedParams map[string]map[int]bool
}

var GlobalTaintEngine *TaintEngine

func InitTaintEngine(rulesDir string) error {
	GlobalTaintEngine = &TaintEngine{}
	return nil
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
