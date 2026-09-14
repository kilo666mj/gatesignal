// Package analytics creates privacy-limited web traffic aggregates.
package analytics

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/redis/go-redis/v9"

	"github.com/kilo666mj/gatesignal/internal/accesslog"
	"github.com/kilo666mj/gatesignal/internal/config"
	"github.com/kilo666mj/gatesignal/internal/metrics"
	"github.com/kilo666mj/gatesignal/internal/publisher"
	"github.com/kilo666mj/gatesignal/internal/store"
)

type Analytics struct {
	cfg              config.Analytics
	store            *store.Store
	metrics          *metrics.Metrics
	collectorHost    string
	secret           []byte
	excludedNets     []*net.IPNet
	excludedURIs     []*regexp.Regexp
	monitoringAgents []*regexp.Regexp
	botAgents        []*regexp.Regexp
	staticExtensions map[string]struct{}
	internalDomains  map[string]struct{}
	queue            chan accesslog.Event
	client           *http.Client
	endpoint         string
	prefix           string
	owner            publisher.Ownership
}

type Item struct {
	Path     string `json:"path,omitempty"`
	Referrer string `json:"referrer,omitempty"`
	Views    int64  `json:"views"`
}

type Bucket struct {
	Source             string    `json:"source"`
	CollectorHost      string    `json:"collector_host"`
	Site               string    `json:"site"`
	BucketStart        time.Time `json:"bucket_start"`
	BucketSeconds      int       `json:"bucket_seconds"`
	Requests           int64     `json:"requests"`
	PageViews          int64     `json:"page_views"`
	UniqueVisitors     int64     `json:"unique_visitors"`
	ResponseBytes      int64     `json:"response_bytes"`
	Status2xx          int64     `json:"status_2xx"`
	Status3xx          int64     `json:"status_3xx"`
	Status4xx          int64     `json:"status_4xx"`
	Status5xx          int64     `json:"status_5xx"`
	HumanRequests      int64     `json:"human_requests"`
	BotRequests        int64     `json:"bot_requests"`
	MonitoringRequests int64     `json:"monitoring_requests"`
	TopPaths           []Item    `json:"top_paths"`
	TopReferrers       []Item    `json:"top_referrers"`
	ObservedAt         time.Time `json:"observed_at"`
}

func New(cfg config.Analytics, state *store.Store, telemetry *metrics.Metrics, pipelineID string, owner publisher.Ownership) (*Analytics, error) {
	a := &Analytics{cfg: cfg, store: state, metrics: telemetry, secret: []byte(cfg.Secret), prefix: state.Key("analytics") + ":", collectorHost: pipelineID, owner: owner}
	if cfg.Mode == "disabled" {
		return a, nil
	}
	var err error
	if a.excludedNets, err = parseNets(cfg.ExcludedNets); err != nil {
		return nil, err
	}
	if a.excludedURIs, err = compilePatterns("excluded URI", cfg.ExcludedURIs); err != nil {
		return nil, err
	}
	if a.monitoringAgents, err = compilePatterns("monitoring user-agent", cfg.MonitoringAgents); err != nil {
		return nil, err
	}
	if a.botAgents, err = compilePatterns("bot user-agent", cfg.BotAgents); err != nil {
		return nil, err
	}
	a.staticExtensions = make(map[string]struct{}, len(cfg.StaticExtensions))
	for _, extension := range cfg.StaticExtensions {
		extension = strings.ToLower(strings.TrimSpace(extension))
		if extension != "" && !strings.HasPrefix(extension, ".") {
			extension = "." + extension
		}
		if extension != "" {
			a.staticExtensions[extension] = struct{}{}
		}
	}
	a.internalDomains = make(map[string]struct{}, len(cfg.InternalReferrers))
	for _, domain := range cfg.InternalReferrers {
		if domain = strings.ToLower(strings.TrimSpace(domain)); domain != "" {
			a.internalDomains[domain] = struct{}{}
		}
	}
	a.queue = make(chan accesslog.Event, cfg.QueueSize)
	a.client = &http.Client{Timeout: time.Duration(cfg.RequestTimeoutSeconds) * time.Second}
	a.endpoint = strings.TrimRight(cfg.URL, "/") + "/api/ingest/web-traffic"
	return a, nil
}

func (a *Analytics) Start(ctx context.Context) {
	if a.cfg.Mode == "disabled" {
		return
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case event := <-a.queue:
				if err := a.aggregate(ctx, event); err != nil {
					a.metrics.RedisFailures.Add(1)
					log.Printf("analytics aggregation: %v", err)
				}
			}
		}
	}()
	if a.cfg.Mode != "publish" {
		return
	}
	go func() {
		a.export(ctx)
		interval := time.Duration(a.cfg.ExportIntervalSeconds) * time.Second
		if interval <= 0 {
			interval = 5 * time.Minute
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.export(ctx)
			}
		}
	}()
}

func (a *Analytics) Process(event accesslog.Event) {
	if a.cfg.Mode == "disabled" {
		return
	}
	if _, ok := a.cfg.Sites[event.Site]; !ok {
		return
	}
	select {
	case a.queue <- event:
		a.metrics.AnalyticsObserved.Add(1)
	default:
		a.metrics.AnalyticsDropped.Add(1)
	}
}

func (a *Analytics) aggregate(ctx context.Context, event accesslog.Event) error {
	if a.excludedIP(event.IP) {
		return nil
	}
	site := a.cfg.Sites[event.Site]
	path := normalizePath(event.Target)
	monitoring := matchesAny(a.monitoringAgents, event.Agent)
	bot := !monitoring && matchesAny(a.botAgents, event.Agent)
	pageView := (event.Method == "GET" || event.Method == "HEAD") && event.Status < 500 &&
		!monitoring && !bot && !matchesAny(a.excludedURIs, path) && !a.isStatic(path)
	hour := event.ObservedAt.UTC().Truncate(time.Hour)
	day := event.ObservedAt.UTC().Format("2006-01-02")
	prefix := a.prefix + site + ":" + hour.Format("20060102T15")
	totalsKey := prefix + ":totals"
	ttl := time.Duration(a.cfg.RetentionDays) * 24 * time.Hour
	client := a.store.Client()
	pipe := client.Pipeline()
	pipe.HIncrBy(ctx, totalsKey, "requests", 1)
	pipe.HIncrBy(ctx, totalsKey, "response_bytes", event.Bytes)
	pipe.HSet(ctx, totalsKey, "observed_at", event.ObservedAt.Format(time.RFC3339))
	pipe.HIncrBy(ctx, totalsKey, fmt.Sprintf("status_%dxx", event.Status/100), 1)
	switch {
	case monitoring:
		pipe.HIncrBy(ctx, totalsKey, "monitoring_requests", 1)
	case bot:
		pipe.HIncrBy(ctx, totalsKey, "bot_requests", 1)
	default:
		pipe.HIncrBy(ctx, totalsKey, "human_requests", 1)
	}
	if pageView {
		pipe.HIncrBy(ctx, totalsKey, "page_views", 1)
		pipe.ZIncrBy(ctx, prefix+":paths", 1, path)
		if referrer := a.externalReferrer(event.Referrer); referrer != "" {
			pipe.ZIncrBy(ctx, prefix+":referrers", 1, referrer)
		}
		pipe.PFAdd(ctx, a.prefix+site+":"+day+":visitors", a.visitorDigest(site, day, event.IP, event.Agent))
	}
	for _, key := range []string{totalsKey, prefix + ":paths", prefix + ":referrers", a.prefix + site + ":" + day + ":visitors"} {
		pipe.Expire(ctx, key, ttl)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return err
	}
	for _, key := range []string{prefix + ":paths", prefix + ":referrers"} {
		count, err := client.ZCard(ctx, key).Result()
		if err != nil {
			return err
		}
		limit := int64(a.cfg.TopLimit * 5)
		if count > limit {
			if err := client.ZRemRangeByRank(ctx, key, 0, count-limit-1).Err(); err != nil {
				return err
			}
		}
	}
	return nil
}

func normalizePath(target string) string {
	if !utf8.ValidString(target) || strings.ContainsAny(target, "\x00\r\n") {
		return ""
	}
	parts := strings.Fields(target)
	if len(parts) == 0 {
		return ""
	}
	value := parts[0]
	if query := strings.IndexByte(value, '?'); query >= 0 {
		value = value[:query]
	}
	if len(value) > 512 {
		value = value[:512]
	}
	return value
}

func (a *Analytics) excludedIP(value string) bool {
	ip := net.ParseIP(value)
	for _, network := range a.excludedNets {
		if ip != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func matchesAny(patterns []*regexp.Regexp, value string) bool {
	for _, pattern := range patterns {
		if pattern.MatchString(value) {
			return true
		}
	}
	return false
}

func (a *Analytics) isStatic(path string) bool {
	_, ok := a.staticExtensions[strings.ToLower(filepath.Ext(path))]
	return ok
}

func (a *Analytics) externalReferrer(value string) string {
	if value == "" || value == "-" {
		return ""
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return ""
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" || len(host) > 253 {
		return ""
	}
	if _, internal := a.internalDomains[host]; internal {
		return ""
	}
	return host
}

func (a *Analytics) visitorDigest(site, day, ip, agent string) string {
	dailySecret := sha256.Sum256(append(append([]byte{}, a.secret...), []byte(day)...))
	if parsed := net.ParseIP(ip); parsed != nil {
		ip = parsed.String()
	}
	digest := sha256.Sum256([]byte(hex.EncodeToString(dailySecret[:]) + "\x00" + site + "\x00" + ip + "\x00" + strings.TrimSpace(agent)))
	return hex.EncodeToString(digest[:])
}

func (a *Analytics) export(ctx context.Context) {
	if a.owner == nil || !a.owner.Owns() {
		return
	}
	buckets, err := a.snapshots(ctx)
	if err != nil {
		a.fail("snapshot", err)
		return
	}
	for _, bucket := range buckets {
		if err := a.queueExport(ctx, bucket); err != nil {
			a.fail("queue", err)
			return
		}
	}
	if err := a.flush(ctx); err != nil {
		a.fail("publish", err)
	}
}

func (a *Analytics) fail(operation string, err error) {
	a.metrics.AnalyticsExportFailures.Add(1)
	log.Printf("analytics %s: %v", operation, err)
}

func (a *Analytics) snapshots(ctx context.Context) ([]Bucket, error) {
	var cursor uint64
	var buckets []Bucket
	for {
		keys, next, err := a.store.Client().Scan(ctx, cursor, a.prefix+"*:*:totals", 100).Result()
		if err != nil {
			return nil, err
		}
		for _, key := range keys {
			bucket, err := a.snapshot(ctx, key)
			if err != nil {
				return nil, err
			}
			buckets = append(buckets, bucket)
		}
		cursor = next
		if cursor == 0 {
			return buckets, nil
		}
	}
}

func (a *Analytics) snapshot(ctx context.Context, totalsKey string) (Bucket, error) {
	trimmed := strings.TrimSuffix(strings.TrimPrefix(totalsKey, a.prefix), ":totals")
	separator := strings.LastIndexByte(trimmed, ':')
	if separator < 1 {
		return Bucket{}, fmt.Errorf("invalid analytics key %q", totalsKey)
	}
	site, hourText := trimmed[:separator], trimmed[separator+1:]
	hour, err := time.Parse("20060102T15", hourText)
	if err != nil {
		return Bucket{}, fmt.Errorf("invalid analytics hour: %w", err)
	}
	client := a.store.Client()
	values, err := client.HGetAll(ctx, totalsKey).Result()
	if err != nil {
		return Bucket{}, err
	}
	prefix := strings.TrimSuffix(totalsKey, ":totals")
	paths, err := a.topItems(ctx, prefix+":paths", true)
	if err != nil {
		return Bucket{}, err
	}
	referrers, err := a.topItems(ctx, prefix+":referrers", false)
	if err != nil {
		return Bucket{}, err
	}
	visitors, err := client.PFCount(ctx, a.prefix+site+":"+hour.Format("2006-01-02")+":visitors").Result()
	if err != nil {
		return Bucket{}, err
	}
	observedAt, _ := time.Parse(time.RFC3339, values["observed_at"])
	return Bucket{Source: "gatesignal", CollectorHost: a.collectorHost, Site: site, BucketStart: hour.UTC(), BucketSeconds: 3600,
		Requests: number(values["requests"]), PageViews: number(values["page_views"]), UniqueVisitors: visitors, ResponseBytes: number(values["response_bytes"]),
		Status2xx: number(values["status_2xx"]), Status3xx: number(values["status_3xx"]), Status4xx: number(values["status_4xx"]), Status5xx: number(values["status_5xx"]),
		HumanRequests: number(values["human_requests"]), BotRequests: number(values["bot_requests"]), MonitoringRequests: number(values["monitoring_requests"]),
		TopPaths: paths, TopReferrers: referrers, ObservedAt: observedAt}, nil
}

func (a *Analytics) topItems(ctx context.Context, key string, paths bool) ([]Item, error) {
	items, err := a.store.Client().ZRevRangeWithScores(ctx, key, 0, int64(a.cfg.TopLimit-1)).Result()
	if err != nil {
		return nil, err
	}
	out := make([]Item, 0, len(items))
	for _, item := range items {
		value, ok := item.Member.(string)
		if !ok {
			continue
		}
		entry := Item{Views: int64(item.Score)}
		if paths {
			entry.Path = value
		} else {
			entry.Referrer = value
		}
		out = append(out, entry)
	}
	return out, nil
}

func number(value string) int64 { result, _ := strconv.ParseInt(value, 10, 64); return result }

func (a *Analytics) queueExport(ctx context.Context, bucket Bucket) error {
	payload, err := json.Marshal(bucket)
	if err != nil {
		return err
	}
	identity := fmt.Sprintf("%s\x00%s\x00%d", bucket.CollectorHost, bucket.Site, bucket.BucketStart.Unix())
	digest := sha256.Sum256([]byte(identity))
	id := hex.EncodeToString(digest[:])
	key := a.prefix + "outbox:" + id
	index := a.prefix + "outbox:index"
	now := time.Now().UTC()
	client := a.store.Client()
	exists, err := client.Exists(ctx, key).Result()
	if err != nil {
		return err
	}
	pipe := client.TxPipeline()
	if exists == 0 {
		pipe.HSet(ctx, key, "payload", payload, "attempts", 0, "next_attempt", now.Unix())
	} else {
		pipe.HSet(ctx, key, "payload", payload)
	}
	pipe.Expire(ctx, key, time.Duration(a.cfg.RetentionDays)*24*time.Hour)
	pipe.ZAdd(ctx, index, redis.Z{Score: float64(now.Unix()), Member: id})
	if _, err := pipe.Exec(ctx); err != nil {
		return err
	}
	count, err := client.ZCard(ctx, index).Result()
	if err != nil || count <= a.cfg.OutboxMaxItems {
		return err
	}
	oldest, err := client.ZPopMin(ctx, index, count-a.cfg.OutboxMaxItems).Result()
	if err != nil {
		return err
	}
	for _, item := range oldest {
		if oldID, ok := item.Member.(string); ok {
			if err := client.Del(ctx, a.prefix+"outbox:"+oldID).Err(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *Analytics) flush(ctx context.Context) error {
	client := a.store.Client()
	index := a.prefix + "outbox:index"
	ids, err := client.ZRange(ctx, index, 0, -1).Result()
	if err != nil {
		return err
	}
	a.metrics.AnalyticsOutboxDepth.Store(int64(len(ids)))
	now := time.Now().UTC()
	for _, id := range ids {
		key := a.prefix + "outbox:" + id
		values, err := client.HGetAll(ctx, key).Result()
		if err != nil {
			return err
		}
		if len(values) == 0 {
			if err := client.ZRem(ctx, index, id).Err(); err != nil {
				return err
			}
			continue
		}
		nextAttempt, _ := strconv.ParseInt(values["next_attempt"], 10, 64)
		if nextAttempt > now.Unix() {
			continue
		}
		if err := a.send(ctx, []byte(values["payload"])); err != nil {
			attempts, _ := strconv.Atoi(values["attempts"])
			attempts++
			shift := attempts
			if shift > 10 {
				shift = 10
			}
			if updateErr := client.HSet(ctx, key, "attempts", attempts, "next_attempt", now.Add(time.Second<<shift).Unix()).Err(); updateErr != nil {
				return fmt.Errorf("publish failed (%v), backoff update failed: %w", err, updateErr)
			}
			return err
		}
		pipe := client.TxPipeline()
		pipe.Del(ctx, key)
		pipe.ZRem(ctx, index, id)
		if _, err := pipe.Exec(ctx); err != nil {
			return err
		}
		a.metrics.AnalyticsExported.Add(1)
	}
	return nil
}

func (a *Analytics) send(ctx context.Context, payload []byte) error {
	if a.owner == nil || !a.owner.Owns() {
		return fmt.Errorf("publisher lease not held")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	if a.cfg.Token != "" {
		request.Header.Set("Authorization", "Bearer "+a.cfg.Token)
	}
	if a.cfg.AccessClientID != "" {
		request.Header.Set("CF-Access-Client-Id", a.cfg.AccessClientID)
	}
	if a.cfg.AccessClientSecret != "" {
		request.Header.Set("CF-Access-Client-Secret", a.cfg.AccessClientSecret)
	}
	response, err := a.client.Do(request)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil {
			log.Printf("close analytics response: %v", closeErr)
		}
	}()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("analytics endpoint returned HTTP %d", response.StatusCode)
	}
	return nil
}

func parseNets(entries []string) ([]*net.IPNet, error) {
	result := make([]*net.IPNet, 0, len(entries))
	for _, entry := range entries {
		if strings.TrimSpace(entry) == "" {
			continue
		}
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			ip := net.ParseIP(entry)
			if ip == nil {
				return nil, fmt.Errorf("invalid excluded network %q", entry)
			}
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			network = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		}
		result = append(result, network)
	}
	return result, nil
}

func compilePatterns(kind string, patterns []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid %s expression %q: %w", kind, pattern, err)
		}
		out = append(out, compiled)
	}
	return out, nil
}
