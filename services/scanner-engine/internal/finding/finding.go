package finding

type ConfidenceLevel string

const (
	ConfidenceDefinite       ConfidenceLevel = "DEFINITE"
	ConfidenceHigh           ConfidenceLevel = "HIGH_CONFIDENCE"
	ConfidenceMedium         ConfidenceLevel = "MEDIUM_CONFIDENCE"
	ConfidenceLow            ConfidenceLevel = "LOW_CONFIDENCE"
)

type EvidenceItem struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

type Metadata struct {
	TraceID        string `json:"trace_id,omitempty"`
	ScannerVersion string `json:"scanner_version,omitempty"`
	Timestamp      string `json:"timestamp,omitempty"`
}

type Finding struct {
	RuleID               string          `json:"rule_id"`
	Name                 string          `json:"name"`
	Severity             string          `json:"severity"`
	File                 string          `json:"file"`
	Line                 int             `json:"line"`
	Message              string          `json:"message"`
	CWE                  string          `json:"cwe"`
	Snippet              string          `json:"snippet"`
	Language             string          `json:"language"`
	Confidence           ConfidenceLevel `json:"confidence"`
	Recommendation       string          `json:"recommendation"`
	References           []string        `json:"references"`
	OccurrenceCount      int             `json:"occurrence_count,omitempty"`
	Evidence             []EvidenceItem  `json:"evidence,omitempty"`
	TaintSourceIdentifier string         `json:"taint_source_identifier,omitempty"`
}

type FindingEnvelope struct {
	Metadata Metadata  `json:"metadata"`
	Findings []Finding `json:"findings"`
	Error    *string   `json:"error,omitempty"`
}

type FeedbackEntry struct {
	RuleID          string  `json:"rule_id"`
	FalsePositiveCount int  `json:"false_positive_count"`
	TotalCount      int     `json:"total_count"`
	Multiplier      float64 `json:"multiplier"`
}

func NewFinding(ruleID, name, severity, file string, line int, message, cwe, snippet, language string, confidence ConfidenceLevel, recommendation string, references []string) Finding {
	return Finding{
		RuleID:         ruleID,
		Name:           name,
		Severity:       severity,
		File:           file,
		Line:           line,
		Message:        message,
		CWE:            cwe,
		Snippet:        snippet,
		Language:       language,
		Confidence:     confidence,
		Recommendation: recommendation,
		References:     references,
	}
}
