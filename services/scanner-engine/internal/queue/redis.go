package queue

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/redis/go-redis/v9"
)

type RedisQueue struct {
	client *redis.Client
	key    string
}

func NewRedisQueue(addr string, password string, db int, key string) *RedisQueue {
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})
	return &RedisQueue{
		client: rdb,
		key:    key,
	}
}

func (q *RedisQueue) Push(ctx context.Context, task *Task) error {
	data, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("marshal task: %w", err)
	}
	return q.client.LPush(ctx, q.key, data).Err()
}

func (q *RedisQueue) Pop(ctx context.Context) (*Task, error) {
	result, err := q.client.BRPop(ctx, 0, q.key).Result()
	if err != nil {
		return nil, fmt.Errorf("brpop: %w", err)
	}
	if len(result) < 2 {
		return nil, fmt.Errorf("unexpected brpop result length")
	}

	var task Task
	if err := json.Unmarshal([]byte(result[1]), &task); err != nil {
		return nil, fmt.Errorf("unmarshal task: %w", err)
	}
	return &task, nil
}

func (q *RedisQueue) Close() error {
	return q.client.Close()
}
