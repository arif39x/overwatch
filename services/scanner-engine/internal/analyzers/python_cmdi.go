package analyzers

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type PythonCMDIAnalyzer struct{}

func init() {
	Register(&PythonCMDIAnalyzer{})
}

func (a *PythonCMDIAnalyzer) SupportedLanguages() []string {
	return []string{"python"}
}

func (a *PythonCMDIAnalyzer) Analyze(node *sitter.Node, source []byte, filePath string) []finding.Finding {
	const (
		ruleID   = "PY-CMDI-001"
		name     = "Python Command Injection"
		severity = "CRITICAL"
		message  = "OS command built with tainted data — possible command injection"
		cwe      = "CWE-78"
	)

	findings := make([]finding.Finding, 0)
	taintedVars := sourcecode.GlobalTaintEngine.AnalyzeTaint(node, source, "python")

	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "call" {
			fnNode := n.ChildByFieldName("function")
			if fnNode != nil {
				fnName := sourcecode.GetNodeText(fnNode, source)
				if strings.Contains(fnName, "os.system") || 
				   strings.Contains(fnName, "subprocess.run") || 
				   strings.Contains(fnName, "subprocess.Popen") || 
				   strings.Contains(fnName, "os.popen") {
					
					args := n.ChildByFieldName("arguments")
					if args != nil {
						for i := 0; i < int(args.NamedChildCount()); i++ {
							arg := args.NamedChild(i)
							argText := sourcecode.GetNodeText(arg, source)
							
							if (arg.Type() == "identifier" && taintedVars[argText]) ||
							   arg.Type() == "binary_operator" ||
							   arg.Type() == "f_string" ||
							   strings.Contains(argText, ".format(") {
								
								findings = append(findings, NewFinding(
									ruleID, name, severity, filePath,
									sourcecode.PositionToLine(n),
									message, cwe, argText,
									"python", "HIGH", "Avoid using shell=True and ensure all arguments are properly sanitized or passed as a list.",
									[]string{"https://owasp.org/www-community/attacks/Command_Injection"},
								))
								break
							}
						}
					}
				}
			}
		}

		for i := 0; i < int(n.ChildCount()); i++ {
			visit(n.Child(i))
		}
	}
	visit(node)

	return findings
}
