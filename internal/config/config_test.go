package config

import "testing"

func TestDefaultsValidateShadow(t *testing.T) {
	cfg := defaults()
	cfg.Inputs = []Input{{Path: "/var/log/gatesignal/access.log", StartPosition: "end"}}
	cfg.Signals.Mode = "shadow"
	cfg.Analytics.Mode = "disabled"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestPublishRequiresHTTPS(t *testing.T) {
	cfg := defaults()
	cfg.Inputs = []Input{{Path: "/tmp/access.log"}}
	cfg.Signals.Mode = "publish"
	cfg.Signals.InstanceID = "central-logs"
	cfg.Signals.Token = "test-token"
	cfg.Signals.GatehubURL = "http://gatehub.example.com"
	if err := cfg.Validate(); err == nil {
		t.Fatal("accepted non-HTTPS Gatehub URL")
	}
}

func TestPublishRequiresStablePipelineAndValidLease(t *testing.T) {
	cfg := defaults()
	cfg.Inputs = []Input{{Path: "/tmp/access.log"}}
	cfg.Analytics.Mode = "publish"
	cfg.Analytics.Sites = map[string]string{"example": "www.example.com"}
	cfg.Analytics.Secret = "test-secret"
	cfg.Analytics.URL = "https://analytics.example.com"
	if err := cfg.Validate(); err == nil {
		t.Fatal("accepted publish mode without publisher.pipeline_id")
	}
	cfg.Publisher.PipelineID = "central-web"
	cfg.Publisher.RenewIntervalSeconds = 15
	if err := cfg.Validate(); err == nil {
		t.Fatal("accepted lease TTL that is not more than twice the renew interval")
	}
	cfg.Publisher.RenewIntervalSeconds = 10
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}
