package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/overwatch/scanner-engine/internal/finding"
	_ "modernc.org/sqlite"
)

type SQLiteStore struct {
	db *sql.DB
}

func NewSQLiteStore(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS findings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			rule_id TEXT,
			name TEXT,
			severity TEXT,
			file TEXT,
			line INTEGER,
			message TEXT,
			cwe TEXT,
			snippet TEXT,
			language TEXT,
			confidence TEXT,
			recommendation TEXT,
			references_json TEXT,
			occurrence_count INTEGER
		)
	`)
	if err != nil {
		return nil, fmt.Errorf("create table: %w", err)
	}

	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) SaveFindings(ctx context.Context, findings []finding.Finding) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO findings (
			rule_id, name, severity, file, line, message, cwe, snippet, language, confidence, recommendation, references_json, occurrence_count
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, f := range findings {
		refJSON, _ := json.Marshal(f.References)
		_, err := stmt.ExecContext(ctx,
			f.RuleID, f.Name, f.Severity, f.File, f.Line, f.Message, f.CWE, f.Snippet, f.Language, f.Confidence, f.Recommendation, string(refJSON), f.OccurrenceCount,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *SQLiteStore) GetFindings(ctx context.Context, filter map[string]string) ([]finding.Finding, error) {
	
	rows, err := s.db.QueryContext(ctx, "SELECT rule_id, name, severity, file, line, message, cwe, snippet, language, confidence, recommendation, references_json, occurrence_count FROM findings")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []finding.Finding
	for rows.Next() {
		var f finding.Finding
		var refJSON string
		err := rows.Scan(
			&f.RuleID, &f.Name, &f.Severity, &f.File, &f.Line, &f.Message, &f.CWE, &f.Snippet, &f.Language, &f.Confidence, &f.Recommendation, &refJSON, &f.OccurrenceCount,
		)
		if err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(refJSON), &f.References)
		findings = append(findings, f)
	}
	return findings, nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}
