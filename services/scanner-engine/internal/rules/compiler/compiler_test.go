package compiler

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCompileFile_Macros(t *testing.T) {
	tmpDir := t.TempDir()
	yamlContent := `
macros:
  - name: go_func
    language: go
    kind: function_call
rules:
  - id: RULE-001
    use_macro: go_func
    identifier: os.Getenv
    vuln_class: environment_variable
  - id: RULE-002
    language: python
    kind: function_call
    identifier: os.system
`
	ruleFile := filepath.Join(tmpDir, "rules.yaml")
	if err := os.WriteFile(ruleFile, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	comp := NewCompiler(tmpDir)
	compiled, err := comp.CompileFile(ruleFile)
	if err != nil {
		t.Fatalf("CompileFile failed: %v", err)
	}

	expected := []CompiledRule{
		{
			ID:         "RULE-001",
			Language:   "go",
			Kind:       "function_call",
			Identifier: "os.Getenv",
			VulnClass:  "environment_variable",
		},
		{
			ID:         "RULE-002",
			Language:   "python",
			Kind:       "function_call",
			Identifier: "os.system",
		},
	}

	if !reflect.DeepEqual(compiled, expected) {
		t.Errorf("expected %+v, got %+v", expected, compiled)
	}
}

func TestCompileFile_Validation(t *testing.T) {
	tmpDir := t.TempDir()
	yamlContent := `
rules:
  - id: BAD-RULE
    language: go
    # missing kind and identifier
`
	ruleFile := filepath.Join(tmpDir, "bad_rules.yaml")
	if err := os.WriteFile(ruleFile, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	comp := NewCompiler(tmpDir)
	_, err := comp.CompileFile(ruleFile)
	if err == nil {
		t.Error("expected error for missing fields, got nil")
	}
}

func TestCompileFile_Imports(t *testing.T) {
	tmpDir := t.TempDir()
	
	commonYaml := `
macros:
  - name: shared_macro
    language: go
    kind: function_call
`
	commonFile := filepath.Join(tmpDir, "common.yaml")
	os.WriteFile(commonFile, []byte(commonYaml), 0644)

	mainYaml := `
imports:
  - common.yaml
rules:
  - id: IMPORTED-RULE
    use_macro: shared_macro
    identifier: fmt.Println
`
	mainFile := filepath.Join(tmpDir, "main.yaml")
	os.WriteFile(mainFile, []byte(mainYaml), 0644)

	comp := NewCompiler(tmpDir)
	compiled, err := comp.CompileFile(mainFile)
	if err != nil {
		t.Fatalf("CompileFile failed: %v", err)
	}

	if len(compiled) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(compiled))
	}
	if compiled[0].Language != "go" {
		t.Errorf("expected language go from macro, got %s", compiled[0].Language)
	}
}

func FuzzCompile(f *testing.F) {
	f.Add("rules: [{id: 1, language: go, kind: call, identifier: x}]")
	f.Add("invalid yaml")
	f.Add("")
	
	f.Fuzz(func(t *testing.T, data string) {
		tmpDir := t.TempDir()
		ruleFile := filepath.Join(tmpDir, "fuzz.yaml")
		os.WriteFile(ruleFile, []byte(data), 0644)
		
		comp := NewCompiler(tmpDir)
		_, _ = comp.CompileFile(ruleFile)
	})
}
