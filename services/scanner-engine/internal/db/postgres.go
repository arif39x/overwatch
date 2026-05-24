package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	_ "github.com/lib/pq"
	"github.com/overwatch/scanner-engine/internal/finding"
)

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(connStr string) (*PostgresStore, error) {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}

	
	return &PostgresStore{db: db}, nil
}

func (s *PostgresStore) SaveFindings(ctx context.Context, findings []finding.Finding) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO findings (
			rule_id, name, severity, file, line, message, cwe, snippet, language, confidence, recommendation, references_json, occurrence_count
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
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

func (s *PostgresStore) GetFindings(ctx context.Context, filter map[string]string) ([]finding.Finding, error) {
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

func (s *PostgresStore) Close() error {
	return s.db.Close()
}
