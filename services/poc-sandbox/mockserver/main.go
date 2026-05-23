package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
)

type RequestRecord struct {
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Query   map[string][]string `json:"query"`
	Body    string              `json:"body"`
	Headers http.Header         `json:"headers"`
}

var (
	records []RequestRecord
	mu      sync.Mutex
)

func main() {
	port := flag.Int("port", 9999, "Port to listen on")
	flag.Parse()

	http.HandleFunc("/", handler)
	http.HandleFunc("/requests", getRequests)
	http.HandleFunc("/ssrf-listener", handler)

	fmt.Printf("Mock server listening on :%d\n", *port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *port), nil))
}

func handler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/requests" {
		getRequests(w, r)
		return
	}

	mu.Lock()
	body, _ := io.ReadAll(r.Body)
	records = append(records, RequestRecord{
		Method:  r.Method,
		Path:    r.URL.Path,
		Query:   r.URL.Query(),
		Body:    string(body),
		Headers: r.Header,
	})
	mu.Unlock()

	