package sourcecode

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	sitter "github.com/smacker/go-tree-sitter"
	"gopkg.in/yaml.v3"

	"github.com/overwatch/scanner-engine/internal/rules/compiler"
)

type Rule struct {
	ID                 string `yaml:"id"`
	Language           string `yaml:"language"`
	Kind               string `yaml:"kind"`
	Identifier         string `yaml:"identifier"`
	VulnClass          string `yaml:"vuln_class,omitempty"`
	RuleVersion        int    `yaml:"rule_version"`
	IntroducedAt       string `yaml:"introduced_at"`
	LastValidatedAt    string `yaml:"last_validated_at"`
	Framework          string `yaml:"framework,omitempty"`
	MinFrameworkVersion string `yaml:"min_framework_version,omitempty"`
	MaxFrameworkVersion string `yaml:"max_framework_version,omitempty"`
}

type RuleMeta struct {
	RuleVersion        int
	IntroducedAt       string
	LastValidatedAt    string
	Framework          string
	MinFrameworkVersion string
	MaxFrameworkVersion string
}

type CallGraph struct {
	Edges       map[string][]CallGraphEdge
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
	SourceMeta    []RuleMeta
	SinkMeta      []RuleMeta
	SanitizerMeta []RuleMeta
	CallGraph     *CallGraph
	SymbolTable   *SymbolTable
	TaintedParams map[string]map[int]bool
}

var GlobalTaintEngine *TaintEngine

func InitTaintEngine(rulesDir string) error {
	te := &TaintEngine{
		CallGraph:     NewCallGraph(),
		TaintedParams: make(map[string]map[int]bool),
	}

	sourcesPath := filepath.Join(rulesDir, "sources.yaml")
	sinksPath := filepath.Join(rulesDir, "sinks.yaml")
	sanitizersPath := filepath.Join(rulesDir, "sanitizers.yaml")

	sources, sourceMeta, err := loadRulesFile(sourcesPath)
	if err != nil {
		return fmt.Errorf("load sources: %w", err)
	}
	te.Sources = sources
	te.SourceMeta = sourceMeta

	sinks, sinkMeta, err := loadRulesFile(sinksPath)
	if err != nil {
		return fmt.Errorf("load sinks: %w", err)
	}
	te.Sinks = sinks
	te.SinkMeta = sinkMeta

	sanitizers, sanitizerMeta, err := loadRulesFile(sanitizersPath)
	if err != nil {
		return fmt.Errorf("load sanitizers: %w", err)
	}
	te.Sanitizers = sanitizers
	te.SanitizerMeta = sanitizerMeta

	GlobalTaintEngine = te
	return nil
}

func loadRulesFile(path string) ([]Rule, []RuleMeta, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	var rules []Rule
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, nil, fmt.Errorf("unmarshal %s: %w", path, err)
	}

	meta := make([]RuleMeta, len(rules))
	for i, r := range rules {
		if r.ID == "" {
			return nil, nil, fmt.Errorf("%s: rule %d missing 'id' field", path, i)
		}
		if r.RuleVersion == 0 {
			return nil, nil, fmt.Errorf("%s: rule %s missing 'rule_version'", path, r.ID)
		}
		if r.IntroducedAt == "" {
			return nil, nil, fmt.Errorf("%s: rule %s missing 'introduced_at'", path, r.ID)
		}
		if r.LastValidatedAt == "" {
			return nil, nil, fmt.Errorf("%s: rule %s missing 'last_validated_at'", path, r.ID)
		}
		meta[i] = RuleMeta{
			RuleVersion:        r.RuleVersion,
			IntroducedAt:       r.IntroducedAt,
			LastValidatedAt:    r.LastValidatedAt,
			Framework:          r.Framework,
			MinFrameworkVersion: r.MinFrameworkVersion,
			MaxFrameworkVersion: r.MaxFrameworkVersion,
		}
	}

	return rules, meta, nil
}

func GetQualityMetrics() map[string]map[string]any {
	metrics := map[string]map[string]any{}
	if GlobalTaintEngine == nil {
		return metrics
	}

	allRules := append(append(GlobalTaintEngine.Sources, GlobalTaintEngine.Sinks...), GlobalTaintEngine.Sanitizers...)
	allMeta := append(append(GlobalTaintEngine.SourceMeta, GlobalTaintEngine.SinkMeta...), GlobalTaintEngine.SanitizerMeta...)

	for i, r := range allRules {
		id := r.ID
		if id == "" {
			id = fmt.Sprintf("rule_%d", i)
		}
		validated, _ := time.Parse("2006-01-02", allMeta[i].LastValidatedAt)
		daysSinceValidation := int(time.Since(validated).Hours() / 24)

		metrics[id] = map[string]any{
			"rule_version":           allMeta[i].RuleVersion,
			"last_validated_at":      allMeta[i].LastValidatedAt,
			"days_since_validation":  daysSinceValidation,
			"framework":              allMeta[i].Framework,
			"min_framework_version":  allMeta[i].MinFrameworkVersion,
			"max_framework_version":  allMeta[i].MaxFrameworkVersion,
			"stale":                  daysSinceValidation > 90,
			"language":               r.Language,
			"kind":                   r.Kind,
			"identifier":             r.Identifier,
			"vuln_class":             r.VulnClass,
		}
	}
	return metrics
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
	tainted := make(map[string]bool)
	if node == nil {
		return tainted
	}

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}
		if isSource, _ := e.IsSource(n, source, lang); isSource {
			parent := n.Parent()
			if parent != nil {
				var lhsNode *sitter.Node
				if parent.Type() == "short_var_declaration" || parent.Type() == "assignment_statement" {
					lhsNode = parent.ChildByFieldName("left")
				} else if parent.Type() == "variable_declarator" {
					lhsNode = parent.ChildByFieldName("name")
				} else if parent.Type() == "assignment" {
					lhsNode = parent.ChildByFieldName("left")
				}
				if lhsNode != nil {
					markTaintedIdentifiers(lhsNode, source, tainted)
				}
			}
		}

		if n.Type() == "short_var_declaration" || n.Type() == "assignment_statement" ||
			n.Type() == "variable_declaration" || n.Type() == "assignment" {
			rhs := n.ChildByFieldName("right")
			src := n.ChildByFieldName("source")
			valueNode := rhs
			if valueNode == nil {
				valueNode = src
			}
			if valueNode != nil {
				if containsTaintedCall(valueNode, source, lang, e) {
					lhs := n.ChildByFieldName("left")
					if lhs != nil {
						markTaintedIdentifiers(lhs, source, tainted)
					}
				}
			}
		}

		for i := 0; i < int(n.ChildCount()); i++ {
			visit(n.Child(i))
		}
	}
	visit(node)

	return tainted
}

func markTaintedIdentifiers(n *sitter.Node, source []byte, tainted map[string]bool) {
	if n == nil {
		return
	}
	if n.Type() == "identifier" {
		tainted[n.Content(source)] = true
		return
	}
	for i := 0; i < int(n.ChildCount()); i++ {
		markTaintedIdentifiers(n.Child(i), source, tainted)
	}
}

func containsTaintedCall(n *sitter.Node, source []byte, lang string, e *TaintEngine) bool {
	if n == nil {
		return false
	}
	if n.Type() == "call_expression" {
		if ok, _ := e.IsSource(n, source, lang); ok {
			return true
		}
	}
	for i := 0; i < int(n.ChildCount()); i++ {
		if containsTaintedCall(n.Child(i), source, lang, e) {
			return true
		}
	}
	return false
}

func extractCallName(n *sitter.Node, source []byte, lang string) string {
	if n == nil {
		return ""
	}

	switch lang {
	case "go", "c", "cpp", "javascript", "typescript", "rust":
		if n.Type() == "call_expression" {
			fnNode := n.ChildByFieldName("function")
			if fnNode != nil {
				return fnNode.Content(source)
			}
		}
	case "python":
		if n.Type() == "call" {
			fnNode := n.ChildByFieldName("function")
			if fnNode != nil {
				return fnNode.Content(source)
			}
		}
	case "java":
		if n.Type() == "method_invocation" {
			nameNode := n.ChildByFieldName("name")
			if nameNode != nil {
				return nameNode.Content(source)
			}
			objNode := n.ChildByFieldName("object")
			if objNode != nil {
				return objNode.Content(source)
			}
		}
	case "php":
		if n.Type() == "function_call_expression" {
			fnNode := n.ChildByFieldName("function")
			if fnNode != nil {
				return fnNode.Content(source)
			}
		}
	case "ruby":
		if n.Type() == "call" || n.Type() == "method_call" {
			fnNode := n.ChildByFieldName("method")
			if fnNode != nil {
				return fnNode.Content(source)
			}
			fnNode = n.ChildByFieldName("receiver")
			if fnNode != nil {
				return fnNode.Content(source)
			}
		}
	}
	return ""
}

func (e *TaintEngine) IsSink(n *sitter.Node, source []byte, lang string) (bool, string) {
	if n == nil {
		return false, ""
	}
	fnName := extractCallName(n, source, lang)
	if fnName == "" {
		return false, ""
	}
	for _, sink := range e.Sinks {
		if sink.Language == lang && fnName == sink.Identifier {
			return true, sink.VulnClass
		}
	}
	return false, ""
}

func (e *TaintEngine) IsSource(n *sitter.Node, source []byte, lang string) (bool, string) {
	if n == nil {
		return false, ""
	}

	// Check parameter-like sources (kind: parameter) for any node type
	for _, src := range e.Sources {
		if src.Kind == "parameter" && src.Language == lang {
			if n.Type() == "identifier" || n.Type() == "parameter" {
				nodeText := n.Content(source)
				if nodeText == src.Identifier {
					return true, ""
				}
			}
		}
	}

	// Check function call sources (kind: function_call)
	fnName := extractCallName(n, source, lang)
	if fnName != "" {
		for _, src := range e.Sources {
			if src.Kind == "function_call" && src.Language == lang && fnName == src.Identifier {
				return true, ""
			}
		}
	}
	return false, ""
}

func (e *TaintEngine) IsSanitizer(n *sitter.Node, source []byte, lang string) (bool, string) {
	if n == nil {
		return false, ""
	}
	fnName := extractCallName(n, source, lang)
	if fnName == "" {
		return false, ""
	}
	for _, san := range e.Sanitizers {
		if san.Language == lang && fnName == san.Identifier {
			return true, san.ID
		}
	}
	return false, ""
}

func findMatchingRule(identifier, lang, kind string, rules []Rule) *Rule {
	for _, r := range rules {
		if r.Language == lang && r.Kind == kind && r.Identifier == identifier {
			return &r
		}
	}
	return nil
}

func (e *TaintEngine) GetSourceByID(id string) *Rule {
	for i := range e.Sources {
		if e.Sources[i].ID == id {
			return &e.Sources[i]
		}
	}
	return nil
}

func (e *TaintEngine) GetSinkByID(id string) *Rule {
	for i := range e.Sinks {
		if e.Sinks[i].ID == id {
			return &e.Sinks[i]
		}
	}
	return nil
}

func (e *TaintEngine) GetSanitizerByID(id string) *Rule {
	for i := range e.Sanitizers {
		if e.Sanitizers[i].ID == id {
			return &e.Sanitizers[i]
		}
	}
	return nil
}

func GetStaleRuleWarnings() []string {
	var warnings []string
	if GlobalTaintEngine == nil {
		return warnings
	}
	allMeta := append(
		append(GlobalTaintEngine.SourceMeta, GlobalTaintEngine.SinkMeta...),
		GlobalTaintEngine.SanitizerMeta...,
	)
	allIDs := make([]string, 0, len(GlobalTaintEngine.Sources)+len(GlobalTaintEngine.Sinks)+len(GlobalTaintEngine.Sanitizers))
	for _, r := range GlobalTaintEngine.Sources {
		allIDs = append(allIDs, r.ID)
	}
	for _, r := range GlobalTaintEngine.Sinks {
		allIDs = append(allIDs, r.ID)
	}
	for _, r := range GlobalTaintEngine.Sanitizers {
		allIDs = append(allIDs, r.ID)
	}

	for i, m := range allMeta {
		validated, err := time.Parse("2006-01-02", m.LastValidatedAt)
		if err != nil {
			continue
		}
		daysSince := int(time.Since(validated).Hours() / 24)
		if daysSince > 90 {
			id := ""
			if i < len(allIDs) {
				id = allIDs[i]
			}
			warnings = append(warnings, fmt.Sprintf(
				"RULE_POSSIBLY_STALE: rule %s last validated %s (%d days ago)",
				id, m.LastValidatedAt, daysSince,
			))
		}
	}
	return warnings
}

func (e *TaintEngine) EvaluateFireRate(ruleID string, findingsCount int, linesScanned int) float64 {
	if linesScanned == 0 {
		return 0
	}
	return float64(findingsCount) / float64(linesScanned) * 1000
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
