package store

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func TestUpdateCounterAndWindowRollover(t *testing.T) {
	mini := miniredis.RunT(t)
	s := New(mini.Addr(), "", 0, "test")
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	key := s.CounterKey("web.example.com", "example", "192.0.2.1")
	start := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	first, err := s.UpdateCounter(ctx, key, start, 2*time.Minute, true, false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.UpdateCounter(ctx, key, start.Add(time.Minute), 2*time.Minute, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if first.Count != 1 || second.Count != 2 || second.Errors != 1 || second.Successes != 1 || !second.Suspicious {
		t.Fatalf("unexpected counters: first=%#v second=%#v", first, second)
	}
	rolled, err := s.UpdateCounter(ctx, key, start.Add(2*time.Minute), 2*time.Minute, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if rolled.Count != 1 || rolled.Errors != 0 || rolled.Suspicious {
		t.Fatalf("rollover=%#v", rolled)
	}
}
