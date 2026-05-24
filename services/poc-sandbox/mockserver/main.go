package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

type RequestRecord struct {
	Method   string              `json:"method"`
	Path     string              `json:"path"`
	Query    map[string][]string `json:"query"`
	Body     string              `json:"body"`
	Headers  http.Header         `json:"headers"`
	Remote   string              `json:"remote_addr"`
	Received string              `json:"received_at"`
}

type MockResponse struct {
	StatusCode int               `yaml:"status_code" json:"status_code"`
	Headers    map[string]string `yaml:"headers" json:"headers"`
	Body       string            `yaml:"body" json:"body"`
	DelayMs    int               `yaml:"delay_ms" json:"delay_ms"`
}

type MockRule struct {
	ID          string       `json:"id"`
	PathPattern string       `json:"path_pattern"`
	Method      string       `json:"method"`
	Response    MockResponse `json:"response"`
	HitCount    int          `json:"hit_count"`
	Enabled     bool         `json:"enabled"`
}

type SQLMockEntry struct {
	ID       string          `json:"id"`
	Database string          `json:"database"` 
	Query    string          `json:"query"`
	Columns  []string        `json:"columns"`
	Rows     [][]interface{} `json:"rows"`
	DelayMs  int             `json:"delay_ms"`
	HitCount int             `json:"hit_count"`
}

var (
	records   []RequestRecord
	recordsMu sync.Mutex

	mockRules   []*MockRule
	mockRulesMu sync.RWMutex

	sqlMocks   []*SQLMockEntry
	sqlMocksMu sync.RWMutex

	interceptTarget string
	interceptRules  []*MockRule
	interceptMu     sync.RWMutex

	rateLimitEnabled bool
	rateLimitPerSec  int
	rateLimitBurst   int
)

func main() {
	port := flag.Int("port", 9999, "Port to listen on")
	adminPort := flag.Int("admin-port", 9998, "Admin API port")
	dataDir := flag.String("data", "", "Path to load mock definitions from")
	flag.Parse()

	mux := http.NewServeMux()

	mux.HandleFunc("/", handleRequest)

	mux.HandleFunc("/ssrf-listener", handleRequest)
	mux.HandleFunc("/requests", handleGetRequests)
	mux.HandleFunc("/reset", handleReset)

	mux.HandleFunc("/status/200", handleSynthetic200)
	mux.HandleFunc("/status/500", handleSynthetic500)
	mux.HandleFunc("/status/403", handleSynthetic403)
	mux.HandleFunc("/status/302", handleSynthetic302)
	mux.HandleFunc("/echo", handleEcho)
	mux.HandleFunc("/delay", handleDelay)

	mux.HandleFunc("/sql/query", handleSQLQuery)
	mux.HandleFunc("/api/users", handleAPIUsers)
	mux.HandleFunc("/api/data", handleAPIData)
	mux.HandleFunc("/auth/token", handleAuthToken)
	mux.HandleFunc("/health", handleHealth)

	adminMux := http.NewServeMux()
	adminMux.HandleFunc("/admin/rules", handleAdminRules)
	adminMux.HandleFunc("/admin/rules/", handleAdminRuleByID)
	adminMux.HandleFunc("/admin/sql", handleAdminSQL)
	adminMux.HandleFunc("/admin/sql/", handleAdminSQLByID)
	adminMux.HandleFunc("/admin/intercept", handleAdminIntercept)
	adminMux.HandleFunc("/admin/clear", handleAdminClear)
	adminMux.HandleFunc("/admin/stats", handleAdminStats)
	adminMux.HandleFunc("/admin/rate-limit", handleAdminRateLimit)
	adminMux.HandleFunc("/admin/export", handleAdminExport)
	adminMux.HandleFunc("/admin/import", handleAdminImport)

	if *dataDir != "" {
		loadMockDefinitions(*dataDir)
	}

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", *port),
		Handler: withLogging(mux),
	}

	adminServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", *adminPort),
		Handler: withLogging(adminMux),
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		fmt.Printf("Mock server listening on :%d\n", *port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("main server: %v", err)
		}
	}()

	go func() {
		fmt.Printf("Admin API listening on :%d\n", *adminPort)
		if err := adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("admin server: %v", err)
		}
	}()

	<-quit
	fmt.Println("Shutting down...")
	server.Close()
	adminServer.Close()
}

func withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: 200}
		next.ServeHTTP(lrw, r)
		duration := time.Since(start)
		log.Printf("[%s] %s %s -> %d (%s)",
			r.Method, r.URL.Path, r.RemoteAddr, lrw.statusCode, duration)
	})
}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func recordRequest(r *http.Request, body string) {
	recordsMu.Lock()
	defer recordsMu.Unlock()
	records = append(records, RequestRecord{
		Method:   r.Method,
		Path:     r.URL.Path,
		Query:    r.URL.Query(),
		Body:     body,
		Headers:  r.Header.Clone(),
		Remote:   r.RemoteAddr,
		Received: time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func findMatchingRule(path string, method string) *MockResponse {
	mockRulesMu.RLock()
	defer mockRulesMu.RUnlock()

	for _, rule := range mockRules {
		if !rule.Enabled {
			continue
		}
		if rule.Method != "" && !strings.EqualFold(rule.Method, method) {
			continue
		}
		matched, err := regexp.MatchString(rule.PathPattern, path)
		if err == nil && matched {
			rule.HitCount++
			resp := rule.Response
			return &resp
		}
	}
	return nil
}

func handleRequest(w http.ResponseWriter, r *http.Request) {

	body, _ := io.ReadAll(r.Body)

	recordRequest(r, string(body))

	if mock := findMatchingRule(r.URL.Path, r.Method); mock != nil {
		if mock.DelayMs > 0 {
			time.Sleep(time.Duration(mock.DelayMs) * time.Millisecond)
		}
		for k, v := range mock.Headers {
			w.Header().Set(k, v)
		}
		if mock.StatusCode > 0 {
			w.WriteHeader(mock.StatusCode)
		}
		if mock.Body != "" {
			fmt.Fprint(w, mock.Body)
		}
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"recorded","path":"%s"}`, r.URL.Path)
}

func handleSynthetic200(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	recordRequest(r, string(body))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"ok","message":"Synthetic 200 OK response"}`)
}

func handleSynthetic500(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	recordRequest(r, string(body))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprint(w, `{"error":"internal_server_error","message":"Synthetic 500 error"}`)
}

func handleSynthetic403(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	recordRequest(r, string(body))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprint(w, `{"error":"forbidden","message":"Synthetic 403 forbidden"}`)
}

func handleSynthetic302(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	recordRequest(r, string(body))
	redirectURL := r.URL.Query().Get("redirect")
	if redirectURL == "" {
		redirectURL = "http://evil.example.com"
	}
	w.Header().Set("Location", redirectURL)
	w.WriteHeader(http.StatusFound)
}

func handleEcho(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	recordRequest(r, string(body))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := map[string]interface{}{
		"method":  r.Method,
		"path":    r.URL.Path,
		"query":   r.URL.Query(),
		"body":    string(body),
		"headers": r.Header,
	}
	json.NewEncoder(w).Encode(response)
}

func handleDelay(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	recordRequest(r, string(body))

	delayStr := r.URL.Query().Get("ms")
	delayMs := 1000
	if delayStr != "" {
		if d, err := fmt.Sscanf(delayStr, "%d", &delayMs); err == nil && d == 1 {
		}
	}
	time.Sleep(time.Duration(delayMs) * time.Millisecond)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"delayed","delay_ms":%d}`, delayMs)
}

func handleSQLQuery(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	recordRequest(r, string(body))

	q := r.URL.Query().Get("q")
	if q == "" && len(body) > 0 {
		q = string(body)
	}

	db := r.URL.Query().Get("db")
	if db == "" {
		db = "generic"
	}

	var matched *SQLMockEntry
	sqlMocksMu.RLock()
	for _, entry := range sqlMocks {
		if entry.Database != "" && !strings.EqualFold(entry.Database, db) {
			continue
		}
		if entry.Query != "" && !strings.Contains(strings.ToLower(q), strings.ToLower(entry.Query)) {
			continue
		}
		matched = entry
		entry.HitCount++
		break
	}
	sqlMocksMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")

	if matched != nil {
		if matched.DelayMs > 0 {
			time.Sleep(time.Duration(matched.DelayMs) * time.Millisecond)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"columns":       matched.Columns,
			"rows":          matched.Rows,
			"affected_rows": len(matched.Rows),
		})
		return
	}

	response := map[string]interface{}{
		"columns": []string{"id", "name", "email", "created_at"},
		"rows": [][]interface{}{
			{1, "admin", "admin@example.com", "2024-01-01T00:00:00Z"},
			{2, "user", "user@example.com", "2024-01-02T00:00:00Z"},
		},
		"affected_rows": 2,
	}
	json.NewEncoder(w).Encode(response)
}

func handleAPIUsers(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	recordRequest(r, string(body))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := map[string]interface{}{
		"users": []map[string]interface{}{
			{
				"id":         1,
				"username":   "admin",
				"email":      "admin@example.com",
				"role":       "administrator",
				"created_at": "2024-01-01T00:00:00Z",
			},
			{
				"id":         2,
				"username":   "john_doe",
				"email":      "john@example.com",
				"role":       "user",
				"created_at": "2024-01-15T00:00:00Z",
			},
		},
		"total": 2,
		"page":  1,
	}
	json.NewEncoder(w).Encode(response)
}

func handleAPIData(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	recordRequest(r, string(body))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := map[string]interface{}{
		"data": []map[string]interface{}{
			{"key": "config", "value": "sensitive_data"},
			{"key": "flag", "value": "OVERWATCH{PoC_VERIFICATION_SUCCESSFUL}"},
			{"key": "api_key", "value": "sk-mock-test-key-12345"},
		},
	}
	json.NewEncoder(w).Encode(response)
}

func handleAuthToken(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	recordRequest(r, string(body))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := map[string]interface{}{
		"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.mock_token_for_testing",
		"token_type":   "Bearer",
		"expires_in":   3600,
	}
	json.NewEncoder(w).Encode(response)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	recordRequest(r, string(body))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

func handleGetRequests(w http.ResponseWriter, r *http.Request) {
	recordsMu.Lock()
	defer recordsMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(records)
}

func handleReset(w http.ResponseWriter, r *http.Request) {
	recordsMu.Lock()
	records = nil
	recordsMu.Unlock()

	mockRulesMu.Lock()
	mockRules = nil
	mockRulesMu.Unlock()

	sqlMocksMu.Lock()
	sqlMocks = nil
	sqlMocksMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "reset"})
}

func handleAdminRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		mockRulesMu.RLock()
		defer mockRulesMu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockRules)

	case http.MethodPost:
		var rule MockRule
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &rule); err != nil {
			http.Error(w, fmt.Sprintf("invalid rule: %v", err), http.StatusBadRequest)
			return
		}
		rule.Enabled = true
		mockRulesMu.Lock()
		mockRules = append(mockRules, &rule)
		mockRulesMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(rule)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleAdminRuleByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/admin/rules/")
	mockRulesMu.Lock()
	defer mockRulesMu.Unlock()

	switch r.Method {
	case http.MethodGet:
		for _, rule := range mockRules {
			if rule.ID == id {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(rule)
				return
			}
		}
		http.Error(w, "rule not found", http.StatusNotFound)

	case http.MethodPut:
		var updated MockRule
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &updated); err != nil {
			http.Error(w, fmt.Sprintf("invalid rule: %v", err), http.StatusBadRequest)
			return
		}
		for _, rule := range mockRules {
			if rule.ID == id {
				rule.PathPattern = updated.PathPattern
				rule.Method = updated.Method
				rule.Response = updated.Response
				rule.Enabled = updated.Enabled
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(rule)
				return
			}
		}
		http.Error(w, "rule not found", http.StatusNotFound)

	case http.MethodDelete:
		for i, rule := range mockRules {
			if rule.ID == id {
				mockRules = append(mockRules[:i], mockRules[i+1:]...)
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		http.Error(w, "rule not found", http.StatusNotFound)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleAdminSQL(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		sqlMocksMu.RLock()
		defer sqlMocksMu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sqlMocks)

	case http.MethodPost:
		var entry SQLMockEntry
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &entry); err != nil {
			http.Error(w, fmt.Sprintf("invalid SQL mock: %v", err), http.StatusBadRequest)
			return
		}
		sqlMocksMu.Lock()
		sqlMocks = append(sqlMocks, &entry)
		sqlMocksMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(entry)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleAdminSQLByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/admin/sql/")
	sqlMocksMu.Lock()
	defer sqlMocksMu.Unlock()

	if r.Method == http.MethodDelete {
		for i, entry := range sqlMocks {
			if entry.ID == id {
				sqlMocks = append(sqlMocks[:i], sqlMocks[i+1:]...)
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		http.Error(w, "SQL mock not found", http.StatusNotFound)
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func handleAdminIntercept(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		interceptMu.RLock()
		defer interceptMu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"target": interceptTarget,
			"rules":  interceptRules,
		})

	case http.MethodPost:
		var config struct {
			Target string     `json:"target"`
			Rules  []MockRule `json:"rules"`
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &config); err != nil {
			http.Error(w, fmt.Sprintf("invalid config: %v", err), http.StatusBadRequest)
			return
		}
		interceptMu.Lock()
		interceptTarget = config.Target
		interceptRules = nil
		for _, rule := range config.Rules {
			r := rule
			r.Enabled = true
			interceptRules = append(interceptRules, &r)
		}
		interceptMu.Unlock()
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "intercept configured"})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleAdminClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	recordsMu.Lock()
	records = nil
	recordsMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "cleared"})
}

func handleAdminStats(w http.ResponseWriter, r *http.Request) {
	recordsMu.Lock()
	totalRequests := len(records)
	recordsMu.Unlock()

	mockRulesMu.RLock()
	totalHits := 0
	for _, rule := range mockRules {
		totalHits += rule.HitCount
	}
	mockRuleCount := len(mockRules)
	mockRulesMu.RUnlock()

	sqlMocksMu.RLock()
	sqlMockCount := len(sqlMocks)
	sqlMocksMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total_requests": totalRequests,
		"mock_rules":     mockRuleCount,
		"mock_rule_hits": totalHits,
		"sql_mocks":      sqlMockCount,
		"uptime_seconds": int(time.Since(processStartTime).Seconds()),
	})
}

var processStartTime = time.Now()

func handleAdminRateLimit(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled":      rateLimitEnabled,
			"rate_per_sec": rateLimitPerSec,
			"burst":        rateLimitBurst,
		})

	case http.MethodPost:
		var config struct {
			Enabled bool `json:"enabled"`
			Rate    int  `json:"rate_per_sec"`
			Burst   int  `json:"burst"`
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &config); err != nil {
			http.Error(w, fmt.Sprintf("invalid config: %v", err), http.StatusBadRequest)
			return
		}
		rateLimitEnabled = config.Enabled
		rateLimitPerSec = config.Rate
		rateLimitBurst = config.Burst
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "rate limit updated"})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleAdminExport(w http.ResponseWriter, r *http.Request) {
	recordsMu.Lock()
	exportedRecords := records
	recordsMu.Unlock()

	mockRulesMu.RLock()
	exportedRules := make([]*MockRule, len(mockRules))
	copy(exportedRules, mockRules)
	mockRulesMu.RUnlock()

	sqlMocksMu.RLock()
	exportedSQL := make([]*SQLMockEntry, len(sqlMocks))
	copy(exportedSQL, sqlMocks)
	sqlMocksMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"records":    exportedRecords,
		"mock_rules": exportedRules,
		"sql_mocks":  exportedSQL,
	})
}

func handleAdminImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var data struct {
		Records   []RequestRecord `json:"records"`
		MockRules []MockRule      `json:"mock_rules"`
		SQLMocks  []SQLMockEntry  `json:"sql_mocks"`
	}
	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &data); err != nil {
		http.Error(w, fmt.Sprintf("invalid import: %v", err), http.StatusBadRequest)
		return
	}

	recordsMu.Lock()
	records = append(records, data.Records...)
	recordsMu.Unlock()

	mockRulesMu.Lock()
	for _, rule := range data.MockRules {
		r := rule
		mockRules = append(mockRules, &r)
	}
	mockRulesMu.Unlock()

	sqlMocksMu.Lock()
	for _, entry := range data.SQLMocks {
		e := entry
		sqlMocks = append(sqlMocks, &e)
	}
	sqlMocksMu.Unlock()

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "imported",
		"records":    len(data.Records),
		"mock_rules": len(data.MockRules),
		"sql_mocks":  len(data.SQLMocks),
	})
}

func startTCPProxy(listenAddr string, targetAddr string) error {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("proxy listen: %w", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("proxy accept error: %v", err)
				return
			}
			go handleProxyConnection(conn, targetAddr)
		}
	}()

	return nil
}

func handleProxyConnection(client net.Conn, targetAddr string) {
	defer client.Close()

	target, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		log.Printf("proxy dial %s: %v", targetAddr, err)
		return
	}
	defer target.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(target, client)
		target.Close()
	}()

	go func() {
		defer wg.Done()
		io.Copy(client, target)
		client.Close()
	}()

	wg.Wait()
}

func loadMockDefinitions(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Printf("Warning: could not read mock definitions dir %s: %v", dir, err)
		return
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		path := fmt.Sprintf("%s/%s", dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("Warning: could not read %s: %v", path, err)
			continue
		}

		var rules []MockRule
		if err := json.Unmarshal(data, &rules); err != nil {
			log.Printf("Warning: could not parse %s: %v", path, err)
			continue
		}

		mockRulesMu.Lock()
		for _, rule := range rules {
			r := rule
			r.Enabled = true
			mockRules = append(mockRules, &r)
		}
		mockRulesMu.Unlock()

		log.Printf("Loaded %d mock rules from %s", len(rules), path)
	}
}
