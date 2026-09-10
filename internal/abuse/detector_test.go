package abuse

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/kilo666mj/gatesignal/internal/accesslog"
	"github.com/kilo666mj/gatesignal/internal/config"
	"github.com/kilo666mj/gatesignal/internal/metrics"
	"github.com/kilo666mj/gatesignal/internal/store"
)

type testOwnership struct{ owner atomic.Bool }

func (o *testOwnership) Owns() bool { return o.owner.Load() }

func TestSignalOmitsRequestDetails(t *testing.T) {
	event := accesslog.Event{ObservedAt: time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC), Host: "web.example.com", Site: "example", IP: "192.0.2.1", Target: "/private?token=secret"}
	counter := store.Counter{FirstSeen: event.ObservedAt, LastSeen: event.ObservedAt, Count: 10, Errors: 10}
	signal := newSignal(event, counter, "error_rate")
	if signal.EventID == "" || signal.Trigger != "error_rate" {
		t.Fatalf("signal=%#v", signal)
	}
}

func TestOnlyLeaseOwnerPublishesSharedOutbox(t *testing.T) {
	mini := miniredis.RunT(t)
	state := store.New(mini.Addr(), "", 0, "test")
	t.Cleanup(func() { _ = state.Close() })
	requests := atomic.Int64{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	owner := &testOwnership{}
	cfg := config.Signals{Mode: "publish", GatehubURL: server.URL, InstanceID: "gatesignal", Token: "test", OutboxMaxItems: 100}
	detector, err := New(cfg, state, metrics.New(), owner)
	if err != nil {
		t.Fatal(err)
	}
	signal := Signal{EventID: "stable-event", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := state.EnqueueJSON(context.Background(), detector.outboxKey, signal, 100); err != nil {
		t.Fatal(err)
	}
	detector.publish(context.Background())
	if requests.Load() != 0 {
		t.Fatal("non-owner made an external request")
	}
	if depth, err := state.QueueLength(context.Background(), detector.outboxKey); err != nil || depth != 1 {
		t.Fatalf("non-owner changed durable queue: depth=%d err=%v", depth, err)
	}
	owner.owner.Store(true)
	detector.publish(context.Background())
	if requests.Load() != 1 {
		t.Fatalf("owner requests=%d, want 1", requests.Load())
	}
	if depth, err := state.QueueLength(context.Background(), detector.outboxKey); err != nil || depth != 0 {
		t.Fatalf("owner did not acknowledge durable queue: depth=%d err=%v", depth, err)
	}
}
