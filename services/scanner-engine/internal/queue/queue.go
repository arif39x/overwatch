package queue

import (
	"context"
)


type Task struct {
	Type    string `json:"type"`
	Payload []byte `json:"payload"`
}


type Queue interface {
	Push(ctx context.Context, task *Task) error
	Pop(ctx context.Context) (*Task, error)
	Close() error
}
