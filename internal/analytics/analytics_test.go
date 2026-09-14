package analytics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/kilo666mj/gatesignal/internal/accesslog"
	"github.com/kilo666mj/gatesignal/internal/config"
	"github.com/kilo666mj/gatesignal/internal/metrics"
	"github.com/kilo666mj/gatesignal/internal/store"
)

type testOwnership bool

func (o testOwnership) Owns() bool { return bool(o) }

func TestPrivacyLimitedAggregation(t *testing.T) {
	mini := miniredis.RunT(t)
	state := store.New(mini.Addr(), "", 0, "test")
	t.Cleanup(func() { _ = state.Close() })
	cfg := config.Analytics{Mode: "shadow", Sites: map[string]string{"example": "web.example.com"}, Secret: "visitor-secret", RetentionDays: 8, QueueSize: 10, TopLimit: 20, OutboxMaxItems: 100}
	a, err := New(cfg, state, metrics.New(), "test-pipeline", nil)
	if err != nil {
		t.Fatal(err)
	}
	event := accesslog.Event{ObservedAt: time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC), Site: "example", IP: "192.0.2.10", Method: "GET", Target: "/private?token=secret", Status: 200, Bytes: 123, Referrer: "https://search.example.org/?q=secret", Agent: "browser"}
	if err := a.aggregate(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	for _, key := range mini.Keys() {
		if strings.Contains(key, "token=secret") || strings.Contains(key, "192.0.2.10") || strings.Contains(key, "browser") {
			t.Fatalf("sensitive value in key %q", key)
		}
	}
	if _, err := mini.ZScore("test:analytics:web.example.com:20260909T10:paths", "/private"); err != nil {
		t.Fatal(err)
	}
	bucket, err := a.snapshot(context.Background(), "test:analytics:web.example.com:20260909T10:totals")
	if err != nil {
		t.Fatal(err)
	}
	if bucket.CollectorHost != "test-pipeline" {
		t.Fatalf("collector_host=%q, want stable pipeline identity", bucket.CollectorHost)
	}
	if err := a.queueExport(context.Background(), bucket); err != nil {
		t.Fatal(err)
	}
	bucket.Requests++
	if err := a.queueExport(context.Background(), bucket); err != nil {
		t.Fatal(err)
	}
	count, err := state.Client().ZCard(context.Background(), "test:analytics:outbox:index").Result()
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("stable pipeline identity created %d outbox entries, want 1", count)
	}
}

func TestFlushUpdatesOutboxDepthAfterSuccessfulExport(t *testing.T) {
	mini := miniredis.RunT(t)
	state := store.New(mini.Addr(), "", 0, "test")
	t.Cleanup(func() { _ = state.Close() })
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(receiver.Close)
	telemetry := metrics.New()
	cfg := config.Analytics{
		Mode: "publish", Sites: map[string]string{"example": "web.example.com"},
		Secret: "visitor-secret", URL: receiver.URL, RequestTimeoutSeconds: 5,
		RetentionDays: 8, QueueSize: 10, TopLimit: 20, OutboxMaxItems: 100,
	}
	a, err := New(cfg, state, telemetry, "test-pipeline", testOwnership(true))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.queueExport(context.Background(), Bucket{
		CollectorHost: "test-pipeline", Site: "web.example.com",
		BucketStart: time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := telemetry.AnalyticsOutboxDepth.Load(); got != 0 {
		t.Fatalf("analytics outbox depth=%d, want 0 after successful flush", got)
	}
	if got := telemetry.AnalyticsExported.Load(); got != 1 {
		t.Fatalf("analytics exports=%d, want 1", got)
	}
}
