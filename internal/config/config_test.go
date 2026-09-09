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
