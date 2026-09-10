// Package config loads and validates GateSignal configuration.
package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
)

type Config struct {
	Inputs    []Input   `json:"inputs"`
	Redis     Redis     `json:"redis"`
	HTTP      HTTP      `json:"http"`
	Publisher Publisher `json:"publisher"`
	Signals   Signals   `json:"signals"`
	Analytics Analytics `json:"analytics"`
}

type Publisher struct {
	PipelineID           string `json:"pipeline_id"`
	LeaseTTLSeconds      int    `json:"lease_ttl_seconds"`
	RenewIntervalSeconds int    `json:"renew_interval_seconds"`
}

type Input struct {
	Path          string `json:"path"`
	StartPosition string `json:"start_position"`
}

type Redis struct {
	Address   string `json:"address"`
	Password  string `json:"password,omitempty"`
	DB        int    `json:"db"`
	Namespace string `json:"namespace"`
}

type HTTP struct {
	Listen string `json:"listen"`
}

type Signals struct {
	Mode                   string   `json:"mode"`
	GatehubURL             string   `json:"gatehub_url"`
	InstanceID             string   `json:"instance_id"`
	Token                  string   `json:"token,omitempty"`
	AlertConnections       int      `json:"alert_connections"`
	WindowMinutes          int      `json:"window_minutes"`
	ErrorPercent           float64  `json:"error_percent"`
	SuspiciousURIs         []string `json:"suspicious_uris"`
	PublishIntervalSeconds int      `json:"publish_interval_seconds"`
	OutboxMaxItems         int64    `json:"outbox_max_items"`
}

type Analytics struct {
	Mode                  string            `json:"mode"`
	Sites                 map[string]string `json:"sites"`
	URL                   string            `json:"url"`
	Secret                string            `json:"secret,omitempty"`
	Token                 string            `json:"token,omitempty"`
	AccessClientID        string            `json:"access_client_id,omitempty"`
	AccessClientSecret    string            `json:"access_client_secret,omitempty"`
	ExportIntervalSeconds int               `json:"export_interval_seconds"`
	RequestTimeoutSeconds int               `json:"request_timeout_seconds"`
	RetentionDays         int               `json:"retention_days"`
	ExcludedNets          []string          `json:"excluded_nets"`
	ExcludedURIs          []string          `json:"excluded_uris"`
	StaticExtensions      []string          `json:"static_extensions"`
	MonitoringAgents      []string          `json:"monitoring_user_agents"`
	BotAgents             []string          `json:"bot_user_agents"`
	InternalReferrers     []string          `json:"internal_referrer_domains"`
	QueueSize             int               `json:"queue_size"`
	TopLimit              int               `json:"top_limit"`
	OutboxMaxItems        int64             `json:"outbox_max_items"`
}

func defaults() Config {
	return Config{
		Redis:     Redis{Address: "127.0.0.1:6379", Namespace: "gatesignal"},
		HTTP:      HTTP{Listen: "127.0.0.1:9194"},
		Publisher: Publisher{LeaseTTLSeconds: 30, RenewIntervalSeconds: 10},
		Signals: Signals{Mode: "disabled", AlertConnections: 10, WindowMinutes: 2,
			ErrorPercent: 80, PublishIntervalSeconds: 5, OutboxMaxItems: 10000},
		Analytics: Analytics{Mode: "disabled", ExportIntervalSeconds: 300,
			RequestTimeoutSeconds: 5, RetentionDays: 8, QueueSize: 1024,
			TopLimit: 20, OutboxMaxItems: 1000,
			StaticExtensions: []string{".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot", ".pdf"}},
	}
}

func Load(path string) (Config, error) {
	cfg := defaults()
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := applySecrets(&cfg); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func applySecrets(cfg *Config) error {
	files := []struct {
		env    string
		target *string
	}{
		{"GATESIGNAL_REDIS_PASSWORD_FILE", &cfg.Redis.Password},
		{"GATESIGNAL_GATEHUB_TOKEN_FILE", &cfg.Signals.Token},
		{"GATESIGNAL_ANALYTICS_SECRET_FILE", &cfg.Analytics.Secret},
		{"GATESIGNAL_ANALYTICS_TOKEN_FILE", &cfg.Analytics.Token},
		{"GATESIGNAL_ANALYTICS_ACCESS_CLIENT_ID_FILE", &cfg.Analytics.AccessClientID},
		{"GATESIGNAL_ANALYTICS_ACCESS_CLIENT_SECRET_FILE", &cfg.Analytics.AccessClientSecret},
	}
	for _, item := range files {
		path := strings.TrimSpace(os.Getenv(item.env))
		if path == "" {
			continue
		}
		value, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", item.env, err)
		}
		*item.target = strings.TrimSpace(string(value))
	}
	return nil
}

func (cfg Config) Validate() error {
	if len(cfg.Inputs) == 0 {
		return fmt.Errorf("at least one input is required")
	}
	for i, input := range cfg.Inputs {
		if strings.TrimSpace(input.Path) == "" {
			return fmt.Errorf("inputs[%d].path is required", i)
		}
		if input.StartPosition != "" && input.StartPosition != "end" && input.StartPosition != "beginning" {
			return fmt.Errorf("inputs[%d].start_position must be end or beginning", i)
		}
	}
	if cfg.Redis.Address == "" || cfg.Redis.Namespace == "" {
		return fmt.Errorf("redis address and namespace are required")
	}
	if cfg.HTTP.Listen == "" {
		return fmt.Errorf("http.listen is required")
	}
	publishing := cfg.Signals.Mode == "publish" || cfg.Analytics.Mode == "publish"
	if publishing && strings.TrimSpace(cfg.Publisher.PipelineID) == "" {
		return fmt.Errorf("publisher.pipeline_id is required when an output publishes")
	}
	if strings.TrimSpace(cfg.Publisher.PipelineID) != "" {
		if cfg.Publisher.LeaseTTLSeconds <= 0 || cfg.Publisher.RenewIntervalSeconds <= 0 || cfg.Publisher.RenewIntervalSeconds*2 >= cfg.Publisher.LeaseTTLSeconds {
			return fmt.Errorf("publisher lease TTL must be positive and more than twice the renew interval")
		}
	}
	if err := validateMode("signals", cfg.Signals.Mode); err != nil {
		return err
	}
	if cfg.Signals.Mode != "disabled" {
		if cfg.Signals.AlertConnections <= 0 || cfg.Signals.WindowMinutes <= 0 || cfg.Signals.ErrorPercent < 0 || cfg.Signals.ErrorPercent > 100 {
			return fmt.Errorf("signal thresholds are invalid")
		}
		if cfg.Signals.Mode == "publish" {
			if cfg.Signals.InstanceID == "" || cfg.Signals.Token == "" {
				return fmt.Errorf("signals instance_id and token are required in publish mode")
			}
			if err := validateHTTPSOrigin(cfg.Signals.GatehubURL); err != nil {
				return fmt.Errorf("signals.gatehub_url: %w", err)
			}
		}
	}
	if err := validateMode("analytics", cfg.Analytics.Mode); err != nil {
		return err
	}
	if cfg.Analytics.Mode != "disabled" {
		if len(cfg.Analytics.Sites) == 0 || cfg.Analytics.Secret == "" || cfg.Analytics.RetentionDays <= 0 || cfg.Analytics.QueueSize <= 0 || cfg.Analytics.TopLimit <= 0 {
			return fmt.Errorf("analytics sites, secret, retention, queue_size, and top_limit are required")
		}
		if cfg.Analytics.Mode == "publish" {
			if err := validateHTTPSOrigin(cfg.Analytics.URL); err != nil {
				return fmt.Errorf("analytics.url: %w", err)
			}
		}
	}
	return nil
}

func validateMode(name, mode string) error {
	switch mode {
	case "disabled", "shadow", "publish":
		return nil
	default:
		return fmt.Errorf("%s.mode must be disabled, shadow, or publish", name)
	}
}

func validateHTTPSOrigin(value string) error {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("must be an HTTPS origin URL")
	}
	return nil
}
