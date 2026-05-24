package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/overwatch/scanner-engine/internal/analyzers"
	"github.com/overwatch/scanner-engine/internal/db"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/languageserver"
	"github.com/overwatch/scanner-engine/internal/queue"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		printUsage(os.Stderr)
		return 2
	}

	switch args[0] {
	case "scan":
		if len(args) > 1 {
			switch args[1] {
			case "rules":
				return runRules(args[2:])
			case "replay":
				return runReplay(args[2:])
			case "explain":
				return runExplain(args[2:])
			case "poc":
				return runPOC(args[2:])
			case "triage":
				return runScanTriage(args[2:])
			case "payloads":
				return runPayloads(args[2:])
			case "jobs":
				return runScanJobs(args[2:])
			}
		}
		return runScan(args[1:])
	case "triage":
		return runTriage(args[1:])
	case "ci":
		return runCI(args[1:])
	case "lsp":
		if len(args) > 1 {
			switch args[1] {
			case "serve":
				return runLSPServe()
			case "index":
				return runLSPIndex(args[2:])
			case "warm-cache":
				return runLSPWarmCache(args[2:])
			}
		}
		return runLSPServe()
	default:
		printUsage(os.Stderr)
		return 2
	}
}

func runScan(args []string) int {
	command := flag.NewFlagSet("scan", flag.ContinueOnError)
	command.SetOutput(os.Stderr)

	path := command.String("path", ".", "Path to scan")
	format := command.String("format", "json", "Output format (json or text)")
	output := command.String("output", "", "Optional output file")
	rulesDir := command.String("rules", "internal/rules", "Path to taint rules directory")
	local := command.Bool("local", false, "Run in Lite mode (no Redis/Postgres)")

	if err := command.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "parse scan flags: %v\n", err)
		return 2
	}

	if err := sourcecode.InitTaintEngine(*rulesDir); err != nil {
		fmt.Fprintf(os.Stderr, "init taint engine: %v\n", err)
	}

	files, err := sourcecode.Walk(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan walk failed: %v\n", err)
		return 2
	}

	findings := analyzers.RunAll(files)

	var q queue.Queue
	var s db.Store
	var errRanker error

	if *local {
		fmt.Fprintln(os.Stderr, "Lite mode: using in-memory queue and SQLite")
		q = queue.NewMemoryQueue(100)
		s, err = db.NewSQLiteStore("overwatch_local.sqlite")
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to init sqlite: %v\n", err)
			return 2
		}
		findings, errRanker = processWithFindingsRanker(findings)
	} else {
		redisURL := os.Getenv("OVERWATCH_REDIS_URL")
		if redisURL == "" {
			redisURL = "localhost:6379"
		}
		q = queue.NewRedisQueue(redisURL, "", 0, "findings_queue")

		pgURL := os.Getenv("OVERWATCH_POSTGRES_URL")
		if pgURL != "" {
			s, err = db.NewPostgresStore(pgURL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to init postgres: %v\n", err)
			}
		}
		findings, errRanker = processWithFindingsRanker(findings)
	}

	if errRanker != nil {
		fmt.Fprintf(os.Stderr, "findings ranker failed: %v\n", errRanker)
		return 2
	}

	
	if s != nil {
		if err := s.SaveFindings(context.Background(), findings); err != nil {
			fmt.Fprintf(os.Stderr, "failed to save findings: %v\n", err)
		}
		s.Close()
	}

	if q != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		for _, f := range findings {
			data, _ := json.Marshal(f)
			q.Push(ctx, &queue.Task{Type: "FINDING", Payload: data})
		}
		cancel()
		q.Close()
	}

	rendered, err := renderFindings(findings, *format)

	if err != nil {
		fmt.Fprintf(os.Stderr, "render findings: %v\n", err)
		return 2
	}

	if *output != "" {
		if err := os.WriteFile(*output, rendered, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write output file: %v\n", err)
			return 2
		}
	} else {
		fmt.Println(string(rendered))
	}

	if len(findings) > 0 {
		return 1
	}
	return 0
}

func processWithFindingsRanker(findings []finding.Finding) ([]finding.Finding, error) {
	if len(findings) == 0 {
		return findings, nil
	}

	
	input, err := json.Marshal(map[string]any{"findings": findings})
	if err != nil {
		return nil, fmt.Errorf("marshal findings for ranker: %w", err)
	}

	
	rankerPath := "findings-ranker"
	if _, err := exec.LookPath(rankerPath); err != nil {
		
		rankerPath = "./bin/findings-ranker"
		if _, err := os.Stat(rankerPath); err != nil {
			return nil, fmt.Errorf("findings-ranker not found in PATH or ./bin/")
		}
	}

	cmd := exec.Command(rankerPath)
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ranker execution failed: %w (stderr: %s)", err, stderr.String())
	}

	var envelope finding.FindingEnvelope
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		return nil, fmt.Errorf("unmarshal ranker output: %w", err)
	}

	return envelope.Findings, nil
}

func renderFindings(findings []finding.Finding, format string) ([]byte, error) {
	if format == "text" {
		var buf bytes.Buffer
		for _, f := range findings {
			fmt.Fprintf(&buf, "[%s] %s in %s:%d\n  %s\n\n", f.Severity, f.Name, f.File, f.Line, f.Message)
		}
		return buf.Bytes(), nil
	}
	return json.MarshalIndent(findings, "", "  ")
}

func runCI(args []string) int {
	command := flag.NewFlagSet("ci", flag.ContinueOnError)
	command.SetOutput(os.Stderr)

	path := command.String("path", ".", "Path to scan")
	failOn := command.String("fail-on", "HIGH", "Severity threshold to fail the scan")
	format := command.String("format", "json", "Output format (json or sarif)")
	rulesDir := command.String("rules", "internal/rules", "Path to taint rules directory")

	if err := command.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "parse ci flags: %v\n", err)
		return 2
	}

	if err := sourcecode.InitTaintEngine(*rulesDir); err != nil {
		fmt.Fprintf(os.Stderr, "init taint engine: %v\n", err)
	}

	files, err := sourcecode.Walk(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ci walk failed: %v\n", err)
		return 2
	}

	findings := analyzers.RunAll(files)
	findings, err = processWithFindingsRanker(findings)
	if err != nil {
		fmt.Fprintf(os.Stderr, "findings ranker failed: %v\n", err)
		return 2
	}

	severityMap := map[string]int{
		"LOW":      1,
		"MEDIUM":   2,
		"HIGH":     3,
		"CRITICAL": 4,
	}

	threshold := severityMap[*failOn]
	failed := false
	for _, f := range findings {
		if severityMap[f.Severity] >= threshold {
			failed = true
			break
		}
	}

	rendered, err := renderFindings(findings, *format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "render findings: %v\n", err)
		return 2
	}
	fmt.Println(string(rendered))

	if failed {
		return 1
	}
	return 0
}

func runRules(args []string) int {
	fmt.Fprintln(os.Stderr, "rules command not yet implemented")
	return 0
}

func runReplay(args []string) int {
	fmt.Fprintln(os.Stderr, "replay command not yet implemented")
	return 0
}

func runExplain(args []string) int {
	fmt.Fprintln(os.Stderr, "explain command not yet implemented")
	return 0
}

func runPOC(args []string) int {
	fmt.Fprintln(os.Stderr, "poc command not yet implemented")
	return 0
}

func runPayloads(args []string) int {
	fmt.Fprintln(os.Stderr, "payloads command not yet implemented")
	return 0
}

func runLSPServe() int {
	return languageserver.Serve()
}

func runLSPIndex(args []string) int {
	return languageserver.Index(args)
}

func runLSPWarmCache(args []string) int {
	return languageserver.WarmCache(args)
}

func runTriage(args []string) int {
	fmt.Fprintln(os.Stderr, "triage command not yet implemented")
	return 0
}

func writeOutput(data []byte, path string) error {
	if path == "" {
		fmt.Println(string(data))
		return nil
	}
	return os.WriteFile(path, data, 0644)
}

func applyDeterministicGating(findings []finding.Finding, minSeverity string, maxFindings int) []finding.Finding {
	
	return findings
}

func printUsage(w io.Writer) {

	fmt.Fprintln(w, "Usage: overwatch <command> [args]")
	fmt.Fprintln(w, "Commands: scan, triage, ci, lsp")
}


	