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
	"strings"
	"time"

	"github.com/overwatch/scanner-engine/internal/analyzers"
	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/languageserver"
	"github.com/overwatch/scanner-engine/internal/payloads"
	"github.com/overwatch/scanner-engine/internal/rules/compiler"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
	"github.com/redis/go-redis/v9"
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
	if findings, err = processWithFindingsRanker(findings); err != nil {
		fmt.Fprintf(os.Stderr, "findings ranker failed: %v\n", err)
		return 2
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

func runCI(args []string) int {
	command := flag.NewFlagSet("ci", flag.ContinueOnError)
	command.SetOutput(os.Stderr)

	path := command.String("path", ".", "Path to scan")
	failOn := command.String("fail-on", "HIGH", "Severity threshold to fail the scan")
	format := command.String("format", "sarif", "Output format (json or sarif)")
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

	