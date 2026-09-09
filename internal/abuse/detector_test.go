package abuse

import (
	"testing"
	"time"

	"github.com/kilo666mj/gatesignal/internal/accesslog"
	"github.com/kilo666mj/gatesignal/internal/store"
)

func TestSignalOmitsRequestDetails(t *testing.T) {
	event := accesslog.Event{ObservedAt: time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC), Host: "web.example.com", Site: "example", IP: "192.0.2.1", Target: "/private?token=secret"}
	counter := store.Counter{FirstSeen: event.ObservedAt, LastSeen: event.ObservedAt, Count: 10, Errors: 10}
	signal := newSignal(event, counter, "error_rate")
	if signal.EventID == "" || signal.Trigger != "error_rate" {
		t.Fatalf("signal=%#v", signal)
	}
}
