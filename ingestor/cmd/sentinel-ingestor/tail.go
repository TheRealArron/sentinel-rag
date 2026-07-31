package main

import (
	"context"

	"github.com/TheRealArron/sentinel-rag/ingestor/internal/tail"
)

// follower is the subset of tail.Follower main needs, kept as an interface so
// the CLI can be tested against an in-memory stand-in.
type follower interface {
	Read(p []byte) (int, error)
	Close() error
}

func tailFollow(ctx context.Context, path string, fromStart bool) (follower, error) {
	return tail.Follow(ctx, path, fromStart, 0)
}
