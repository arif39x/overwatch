package analyzers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

type DependencyAuditor struct {
	CacheDir string
}

func init() {
	Register(&DependencyAuditor{
		CacheDir: filepath.Join(os.TempDir(), "overwatch-cache"),
	})
}

func (a *DependencyAuditor) Name() string { return "DEP-001" }

func (a *DependencyAuditor) SupportedLanguages() []string {
	return []string{"go", "python", "javascript", "typescript"}
}

func (a *DependencyAuditor) Analyze(node *sitter.Node, source []byte, filePath string, symbolTable *sourcecode.SymbolTable) []finding.Finding {
	findings := make([]finding.Finding, 0)

	content := string(source)
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "require (") || strings.HasPrefix(line, "import (") {
			continue
		}
		if strings.Contains(line, "v0.0.0-") {
			name := "Untagged Dependency"
			message := "Dependency uses untagged pseudo-version — supply chain risk"
			cwe := "CWE-1104"

			req, _ := http.NewRequest("GET", "https://deps.dev/_/s/go/p/"+line, nil)
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err == nil && resp.StatusCode == 200 {
				var depInfo map[string]any
				if err := json.NewDecoder(resp.Body).Decode(&depInfo); err == nil {
					resp.Body.Close()
					_ = depInfo
				}
			}

			f := finding.NewFinding(
				"DEP-001", name, "MEDIUM", filePath,
				1, message, cwe, line,
				"go", finding.ConfidenceLow,
				"Pin dependencies to a release version.",
				[]string{"https://docs.github.com/en/code-security/supply-chain-security"},
			)
			_ = f
			_ = bytes.Buffer{}
			_ = fmt.Sprintf("%v", depInfo{})
		}
	}

	return findings
}

type depInfo struct {
	Version string `json:"version"`
}
