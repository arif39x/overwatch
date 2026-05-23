package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func runScanJobs(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: overwatch scan jobs <inspect|retry|deadletter list> [flags]")
		return 2
	}

	switch args[0] {
	case "inspect":
		return runScanJobsInspect(args[1:])
	case "retry":
		return runScanJobsRetry(args[1:])
	case "deadletter":
		if len(args) > 1 && args[1] == "list" {
			return runScanJobsDeadletterList(args[2:])
		}
		fmt.Fprintln(os.Stderr, "Usage: overwatch scan jobs deadletter list [--api-base <url>] [--token <jwt>]")
		return 2
	default:
		fmt.Fprintf(os.Stderr, "Unknown jobs subcommand %q\n", args[0])
		return 2
	}
}

func runScanJobsInspect(args []string) int {
	command := flag.NewFlagSet("scan-jobs-inspect", flag.ContinueOnError)
	command.SetOutput(os.Stderr)

	scanID := command.String("scan-id", "", "Scan ID to inspect")
	apiBase := command.String("api-base", defaultAPIBase(), "Backend API base URL")
	token := command.String("token", defaultAPIToken(), "Bearer token for API auth")
	output := command.String("output", "", "Optional output file")

	if err := command.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*scanID) == "" {
		fmt.Fprintln(os.Stderr, "scan-id is required")
		return 2
	}

	url := strings.TrimRight(*apiBase, "/") + "/scans/" + *scanID + "/inspect"
	body, err := callScanAPI("GET", url, *token, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "inspect failed: %v\n", err)
		return 1
	}

	writeOutput(body, *output)
	return 0
}

func runScanJobsRetry(args []string) int {
	command := flag.NewFlagSet("scan-jobs-retry", flag.ContinueOnError)
	command.SetOutput(os.Stderr)

	scanID := command.String("scan-id", "", "Scan ID to retry")
	apiBase := command.String("api-base", defaultAPIBase(), "Backend API base URL")
	token := command.String("token", defaultAPIToken(), "Bearer token for API auth")
	output := command.String("output", "", "Optional output file")

	if err := command.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*scanID) == "" {
		fmt.Fprintln(os.Stderr, "scan-id is required")
		return 2
	}

	url := strings.TrimRight(*apiBase, "/") + "/scans/" + *scanID + "/retry"
	body, err := callScanAPI("POST", url, *token, []byte("{}"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "retry failed: %v\n", err)
		return 1
	}

	writeOutput(body, *output)
	return 0
}

func runScanJobsDeadletterList(args []string) int {
	command := flag.NewFlagSet("scan-jobs-deadletter-list", flag.ContinueOnError)
	command.SetOutput(os.Stderr)

	apiBase := command.String("api-base", defaultAPIBase(), "Backend API base URL")
	token := command.String("token", defaultAPIToken(), "Bearer token for API auth")
	output := command.String("output", "", "Optional output file")

	if err := command.Parse(args); err != nil {
		return 2
	}

	url := strings.TrimRight(*apiBase, "/") + "/scans/deadletter/list"
	body, err := callScanAPI("GET", url, *token, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "deadletter list failed: %v\n", err)
		return 1
	}

	writeOutput(body, *output)
	return 0
}

func callScanAPI(method string, url string, token string, payload []byte) ([]byte, error) {
	var bodyReader io.Reader
	if len(payload) > 0 {
		bodyReader = bytes.NewReader(payload)
	}
	request, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	if len(payload) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	rawBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 300 {
		return nil, fmt.Errorf("status %d: %s", response.StatusCode, strings.TrimSpace(string(rawBody)))
	}

	var pretty bytes.Buffer
	if json.Indent(&pretty, rawBody, "", "  ") == nil {
		return pretty.Bytes(), nil
	}
	return rawBody, nil
}

func defaultAPIBase() string {
	base := strings.TrimSpace(os.Getenv("OVERWATCH_API_BASE"))
	if base == "" {
		return "http://localhost:8000/api"
	}
	return base
}

func defaultAPIToken() string {
	return strings.TrimSpace(os.Getenv("OVERWATCH_API_TOKEN"))
}
