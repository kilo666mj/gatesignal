package publisher

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/kilo666mj/gatesignal/internal/metrics"
	"github.com/kilo666mj/gatesignal/internal/store"
)

func TestLeaseAllowsOneOwnerAndTransfersAfterExpiry(t *testing.T) {
	mini := miniredis.RunT(t)
	state := store.New(mini.Addr(), "", 0, "test")
	t.Cleanup(func() { _ = state.Close() })
	first, err := NewLease(state, metrics.New(), time.Second, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewLease(state, metrics.New(), time.Second, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); first.update(ctx) }()
	go func() { defer wg.Done(); second.update(ctx) }()
	wg.Wait()
	if first.Owns() == second.Owns() {
		t.Fatalf("owners after simultaneous acquisition: first=%t second=%t", first.Owns(), second.Owns())
	}
	owner, standby := first, second
	if second.Owns() {
		owner, standby = second, first
	}
	mini.FastForward(time.Second + time.Millisecond)
	owner.ownedUntil.Store(time.Now().Add(-time.Millisecond).UnixNano())
	standby.update(ctx)
	if !standby.Owns() {
		t.Fatal("standby did not acquire expired lease")
	}
	owner.update(ctx)
	if owner.Owns() {
		t.Fatal("former owner renewed a lease now owned by its peer")
	}
}

func TestLeaseReleaseAllowsRestartRecovery(t *testing.T) {
	mini := miniredis.RunT(t)
	state := store.New(mini.Addr(), "", 0, "test")
	t.Cleanup(func() { _ = state.Close() })
	first, err := NewLease(state, metrics.New(), time.Second, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	first.update(context.Background())
	if !first.Owns() {
		t.Fatal("first process did not acquire lease")
	}
	first.release()
	restarted, err := NewLease(state, metrics.New(), time.Second, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	restarted.update(context.Background())
	if !restarted.Owns() {
		t.Fatal("restarted process did not recover released lease")
	}
}
