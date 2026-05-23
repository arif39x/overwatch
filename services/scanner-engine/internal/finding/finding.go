package finding

import (
	"fmt"
	"strings"
)

type Metadata struct {
	TraceID     string `json:"trace_id,omitempty"`
	ScannerVersion string `json:"scanner_version,omitempty"`
	Timestamp   string `json:"timestamp,omitempty"`
}

type FindingEnvelope struct {
	Metadata Metadata  `json:"metadata"`
	Findings []Finding `json:"findings"`
	Error    *string   `json:"error,omitempty"`
}

