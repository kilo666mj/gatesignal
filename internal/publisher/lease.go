// Package publisher coordinates exclusive external publication across GateSignal instances.
package publisher

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"github.com/kilo666mj/gatesignal/internal/metrics"
	"github.com/kilo666mj/gatesignal/internal/store"
)

type Ownership interface {
	Owns() bool
}

type Lease struct {
	store      *store.Store
	metrics    *metrics.Metrics
	key        string
	token      string
	ttl        time.Duration
	renewEvery time.Duration
	ownedUntil atomic.Int64
	done       chan struct{}
}

func NewLease(state *store.Store, telemetry *metrics.Metrics, ttl, renewEvery time.Duration) (*Lease, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return nil, fmt.Errorf("publisher lease token: %w", err)
	}
	return &Lease{store: state, metrics: telemetry, key: state.Key("publisher", "lease"), token: hex.EncodeToString(random), ttl: ttl, renewEvery: renewEvery, done: make(chan struct{})}, nil
}

func (l *Lease) Owns() bool {
	return time.Now().UnixNano() < l.ownedUntil.Load()
}

func (l *Lease) Start(ctx context.Context) {
	l.update(ctx)
	go func() {
		defer close(l.done)
		ticker := time.NewTicker(l.renewEvery)
		defer ticker.Stop()
		defer l.release()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				l.update(ctx)
			}
		}
	}()
}

func (l *Lease) Wait() { <-l.done }

func (l *Lease) update(ctx context.Context) {
	wasOwner := l.Owns()
	var (
		owner bool
		err   error
	)
	if wasOwner {
		owner, err = l.store.RenewLease(ctx, l.key, l.token, l.ttl)
	} else {
		owner, err = l.store.AcquireLease(ctx, l.key, l.token, l.ttl)
	}
	if err != nil {
		l.metrics.PublisherLeaseFailures.Add(1)
		log.Printf("publisher lease: %v", err)
		owner = false
	}
	if owner {
		l.ownedUntil.Store(time.Now().Add(l.ttl).UnixNano())
	} else {
		l.ownedUntil.Store(0)
	}
	l.metrics.PublisherOwner.Store(owner)
	if owner != wasOwner {
		l.metrics.PublisherTransitions.Add(1)
		log.Printf("publisher ownership changed owner=%t", owner)
	}
}

func (l *Lease) release() {
	wasOwner := l.Owns()
	l.ownedUntil.Store(0)
	l.metrics.PublisherOwner.Store(false)
	if !wasOwner {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := l.store.ReleaseLease(ctx, l.key, l.token); err != nil {
		l.metrics.PublisherLeaseFailures.Add(1)
		log.Printf("publisher lease release: %v", err)
	}
}
