package sourcecode

import (
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/overwatch/scanner-engine/internal/rules/compiler"
	sitter "github.com/smacker/go-tree-sitter"
	"gopkg.in/yaml.v3"
)

type Rule struct {
	ID         string `yaml:"id"`
	Language   string `yaml:"language"`
	Kind       string `yaml:"kind"`
	Identifier string `yaml:"identifier"`
	VulnClass  string `yaml:"vuln_class,omitempty"`
}

type TaintEngine struct {
	Sources       []Rule
	Sinks         []Rule
	Sanitizers    []Rule
	CallGraph     *CallGraph
	TaintedParams map[string]map[int]bool 