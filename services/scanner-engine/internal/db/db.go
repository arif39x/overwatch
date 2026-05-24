package db

import (
	"context"
	"github.com/overwatch/scanner-engine/internal/finding"
)


type Store interface {
	SaveFindings(ctx context.Context, findings []finding.Finding) error
	GetFindings(ctx context.Context, filter map[string]string) ([]finding.Finding, error)
	Close() error
}
