package compiler

import (
	"testing"
)

func TestCompile(t *testing.T) {
	input := `
		FIND path 
		WHERE source(name="request.args.get", kind="function_call") 
		  -> NOT sanitized(name="shlex.quote") 
		  -> sink(name="os.system")
		  AND lang="python"
	`

	query, err := Compile(input)
	if err != nil {
		t.Fatalf("failed to compile: %v", err)
	}

	if query.Target != "path" {
		t.Errorf("expected target path, got %v", query.Target)
	}

	if len(query.Sources) != 1 {
		t.Errorf("expected 1 source, got %v", len(query.Sources))
	}

	if query.Sources[0].Attributes["name"] != "request.args.get" {
		t.Errorf("expected source name request.args.get, got %v", query.Sources[0].Attributes["name"])
	}

	if len(query.Filters) != 1 || !query.Filters[0].Negated {
		t.Errorf("expected 1 negated filter, got %v", len(query.Filters))
	}

	if query.Language != "python" {
		t.Errorf("expected language python, got %v", query.Language)
	}
}
