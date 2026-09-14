// Package abuse detects web abuse and publishes privacy-limited signals.
package abuse

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kilo666mj/gatesignal/internal/accesslog"
	"github.com/kilo666mj/gatesignal/internal/config"
	"github.com/kilo666mj/gatesignal/internal/metrics"
	"github.com/kilo666mj/gatesignal/internal/publisher"
	"github.com/kilo666mj/gatesignal/internal/store"
)

const batchSize = 100

type Signal struct {
	EventID       string `json:"event_id"`
	ObservedAt    string `json:"observed_at"`
	Host          string `json:"host"`
	Site          string `json:"site"`
	IP            string `json:"ip"`
	Trigger       string `json:"trigger"`
	Connections   int    `json:"connections"`
	Errors        int    `json:"errors"`
	Successes     int    `json:"successes"`
	WindowSeconds int    `json:"window_seconds"`
}

type batch struct {
	InstanceID string   `json:"instance_id"`
	Signals    []Signal `json:"signals"`
}

type Detector struct {
	cfg        config.Signals
	store      *store.Store
	metrics    *metrics.Metrics
	suspicious []*regexp.Regexp
	client     *http.Client
	outboxKey  string
	owner      publisher.Ownership
}

func New(cfg config.Signals, state *store.Store, telemetry *metrics.Metrics, owner publisher.Ownership) (*Detector, error) {
	d := &Detector{cfg: cfg, store: state, metrics: telemetry, client: &http.Client{Timeout: 10 * time.Second}, outboxKey: state.Key("signals", "outbox"), owner: owner}
	for _, pattern := range cfg.SuspiciousURIs {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("suspicious URI %q: %w", pattern, err)
		}
		d.suspicious = append(d.suspicious, compiled)
	}
	return d, nil
}

func (d *Detector) Start(ctx context.Context) {
	if d.cfg.Mode != "publish" {
		return
	}
	interval := time.Duration(d.cfg.PublishIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	go func() {
		d.publish(ctx)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				d.publish(ctx)
			}
		}
	}()
}

func (d *Detector) Process(ctx context.Context, event accesslog.Event) {
	if d.cfg.Mode == "disabled" {
		return
	}
	suspicious := false
	for _, pattern := range d.suspicious {
		if pattern.MatchString(event.Target) {
			suspicious = true
			break
		}
	}
	key := d.store.CounterKey(event.Host, event.Site, event.IP)
	counter, err := d.store.UpdateCounter(ctx, key, event.ObservedAt, time.Duration(d.cfg.WindowMinutes)*time.Minute, event.Status >= 400, suspicious)
	if err != nil {
		d.metrics.RedisFailures.Add(1)
		log.Printf("signal counter update: %v", err)
		return
	}
	if counter.Count < d.cfg.AlertConnections {
		return
	}
	errorPercent := float64(counter.Errors) / float64(counter.Count) * 100
	if !counter.Suspicious && errorPercent < d.cfg.ErrorPercent {
		return
	}
	trigger := "error_rate"
	if counter.Suspicious {
		trigger = "suspicious_uri"
	}
	signal := newSignal(event, counter, trigger)
	d.metrics.SignalsDetected.Add(1)
	if d.cfg.Mode == "publish" {
		if err := d.store.EnqueueJSON(ctx, d.outboxKey, signal, d.cfg.OutboxMaxItems); err != nil {
			d.metrics.RedisFailures.Add(1)
			log.Printf("signal enqueue: %v", err)
			return
		}
		d.metrics.SignalsQueued.Add(1)
	}
	if err := d.store.ResetCounter(ctx, key, counter.Count); err != nil {
		d.metrics.RedisFailures.Add(1)
		log.Printf("signal counter reset: %v", err)
	}
}

func newSignal(event accesslog.Event, counter store.Counter, trigger string) Signal {
	windowSeconds := int(counter.LastSeen.Sub(counter.FirstSeen).Seconds())
	if windowSeconds < 1 {
		windowSeconds = 1
	}
	identity := strings.Join([]string{event.Host, event.Site, event.IP, trigger, counter.FirstSeen.Format(time.RFC3339Nano), strconv.Itoa(counter.Count)}, "\x00")
	digest := sha256.Sum256([]byte(identity))
	return Signal{
		EventID: hex.EncodeToString(digest[:16]), ObservedAt: event.ObservedAt.Format(time.RFC3339Nano),
		Host: event.Host, Site: event.Site, IP: event.IP, Trigger: trigger,
		Connections: counter.Count, Errors: counter.Errors, Successes: counter.Successes, WindowSeconds: windowSeconds,
	}
}

func (d *Detector) publish(ctx context.Context) {
	if d.owner == nil || !d.owner.Owns() {
		return
	}
	raw, err := d.store.PeekQueue(ctx, d.outboxKey, batchSize)
	if err != nil {
		d.metrics.RedisFailures.Add(1)
		log.Printf("signal outbox read: %v", err)
		return
	}
	d.metrics.SignalOutboxDepth.Store(int64(len(raw)))
	if len(raw) == 0 {
		return
	}
	payload := batch{InstanceID: d.cfg.InstanceID}
	for _, item := range raw {
		var signal Signal
		if err := json.Unmarshal([]byte(item), &signal); err != nil {
			log.Printf("dropping invalid signal outbox item: %v", err)
			if len(payload.Signals) == 0 {
				_ = d.store.DropQueue(ctx, d.outboxKey, 1)
				return
			}
			break
		}
		payload.Signals = append(payload.Signals, signal)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	endpoint, err := url.Parse(d.cfg.GatehubURL)
	if err != nil {
		return
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/v1/signals/batch"
	query := endpoint.Query()
	query.Set("instance_id", d.cfg.InstanceID)
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+d.cfg.Token)
	if !d.owner.Owns() {
		return
	}
	response, err := d.client.Do(request)
	if err != nil {
		d.metrics.SignalPublishFailures.Add(1)
		log.Printf("signal publish: %v", err)
		return
	}
	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil {
			log.Printf("close signal response: %v", closeErr)
		}
	}()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		d.metrics.SignalPublishFailures.Add(1)
		log.Printf("signal publish returned %s", response.Status)
		return
	}
	if err := d.store.DropQueue(ctx, d.outboxKey, int64(len(payload.Signals))); err != nil {
		d.metrics.RedisFailures.Add(1)
		log.Printf("signal outbox acknowledge: %v", err)
		return
	}
	d.metrics.SignalsPublished.Add(uint64(len(payload.Signals)))
}
