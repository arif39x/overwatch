package queue

import (
	"context"
	"errors"
	"sync"
)

type MemoryQueue struct {
	tasks chan *Task
	mu    sync.Mutex
	closed bool
}

func NewMemoryQueue(size int) *MemoryQueue {
	return &MemoryQueue{
		tasks: make(chan *Task, size),
	}
}

func (q *MemoryQueue) Push(ctx context.Context, task *Task) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return errors.New("queue closed")
	}
	select {
	case q.tasks <- task:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		return errors.New("queue full")
	}
}

func (q *MemoryQueue) Pop(ctx context.Context) (*Task, error) {
	select {
	case task, ok := <-q.tasks:
		if !ok {
			return nil, errors.New("queue closed")
		}
		return task, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (q *MemoryQueue) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.closed {
		close(q.tasks)
		q.closed = true
	}
	return nil
}
