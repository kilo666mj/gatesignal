// Package metrics exposes GateSignal health and Prometheus metrics.
package metrics

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

type Metrics struct {
	startedAt               time.Time
	Ready                   atomic.Bool
	ShuttingDown            atomic.Bool
	LinesRead               atomic.Uint64
	LinesParsed             atomic.Uint64
	LinesUnmatched          atomic.Uint64
	TailRestarts            atomic.Uint64
	RedisFailures           atomic.Uint64
	PublisherOwner          atomic.Bool
	PublisherLeaseFailures  atomic.Uint64
	PublisherTransitions    atomic.Uint64
	SignalsDetected         atomic.Uint64
	SignalsQueued           atomic.Uint64
	SignalsPublished        atomic.Uint64
	SignalPublishFailures   atomic.Uint64
	SignalOutboxDepth       atomic.Int64
	AnalyticsObserved       atomic.Uint64
	AnalyticsDropped        atomic.Uint64
	AnalyticsExported       atomic.Uint64
	AnalyticsExportFailures atomic.Uint64
	AnalyticsOutboxDepth    atomic.Int64
	LastObservationUnix     atomic.Int64
}

func New() *Metrics { return &Metrics{startedAt: time.Now()} }

func (m *Metrics) Health(w http.ResponseWriter, _ *http.Request) {
	ready := m.Ready.Load() && !m.ShuttingDown.Load()
	code, status := http.StatusOK, "ok"
	if !ready {
		code, status = http.StatusServiceUnavailable, "unavailable"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": status, "ready": ready, "uptime_seconds": int64(time.Since(m.startedAt).Seconds())})
}

func (m *Metrics) Prometheus(w http.ResponseWriter, _ *http.Request) {
	ready := 0
	if m.Ready.Load() && !m.ShuttingDown.Load() {
		ready = 1
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = fmt.Fprintf(w, `# TYPE gatesignal_ready gauge
gatesignal_ready %d
# TYPE gatesignal_uptime_seconds gauge
gatesignal_uptime_seconds %.0f
# TYPE gatesignal_lines_read_total counter
gatesignal_lines_read_total %d
# TYPE gatesignal_lines_parsed_total counter
gatesignal_lines_parsed_total %d
# TYPE gatesignal_lines_unmatched_total counter
gatesignal_lines_unmatched_total %d
# TYPE gatesignal_tail_restarts_total counter
gatesignal_tail_restarts_total %d
# TYPE gatesignal_redis_failures_total counter
gatesignal_redis_failures_total %d
# TYPE gatesignal_publisher_owner gauge
gatesignal_publisher_owner %d
# TYPE gatesignal_publisher_lease_failures_total counter
gatesignal_publisher_lease_failures_total %d
# TYPE gatesignal_publisher_transitions_total counter
gatesignal_publisher_transitions_total %d
# TYPE gatesignal_signals_detected_total counter
gatesignal_signals_detected_total %d
# TYPE gatesignal_signals_queued_total counter
gatesignal_signals_queued_total %d
# TYPE gatesignal_signals_published_total counter
gatesignal_signals_published_total %d
# TYPE gatesignal_signal_publish_failures_total counter
gatesignal_signal_publish_failures_total %d
# TYPE gatesignal_signal_outbox_depth gauge
gatesignal_signal_outbox_depth %d
# TYPE gatesignal_analytics_observations_total counter
gatesignal_analytics_observations_total %d
# TYPE gatesignal_analytics_dropped_total counter
gatesignal_analytics_dropped_total %d
# TYPE gatesignal_analytics_exports_total counter
gatesignal_analytics_exports_total %d
# TYPE gatesignal_analytics_export_failures_total counter
gatesignal_analytics_export_failures_total %d
# TYPE gatesignal_analytics_outbox_depth gauge
gatesignal_analytics_outbox_depth %d
# TYPE gatesignal_last_observation_timestamp_seconds gauge
gatesignal_last_observation_timestamp_seconds %d
`, ready, time.Since(m.startedAt).Seconds(), m.LinesRead.Load(), m.LinesParsed.Load(),
		m.LinesUnmatched.Load(), m.TailRestarts.Load(), m.RedisFailures.Load(), boolNumber(m.PublisherOwner.Load()),
		m.PublisherLeaseFailures.Load(), m.PublisherTransitions.Load(), m.SignalsDetected.Load(),
		m.SignalsQueued.Load(), m.SignalsPublished.Load(), m.SignalPublishFailures.Load(), m.SignalOutboxDepth.Load(),
		m.AnalyticsObserved.Load(), m.AnalyticsDropped.Load(), m.AnalyticsExported.Load(), m.AnalyticsExportFailures.Load(),
		m.AnalyticsOutboxDepth.Load(), m.LastObservationUnix.Load())
}

func boolNumber(value bool) int {
	if value {
		return 1
	}
	return 0
}
