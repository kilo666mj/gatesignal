// Package accesslog parses web access records delivered through syslog.
package accesslog

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Event contains the request fields needed by GateSignal. Raw events are
// processed in memory and are never sent to Gatehub or the analytics endpoint.
type Event struct {
	ObservedAt time.Time
	Host       string
	Site       string
	IP         string
	Method     string
	Target     string
	Status     int
	Bytes      int64
	Referrer   string
	Agent      string
}

var formats = []*regexp.Regexp{
	// RFC3339 host nginx_site client - identity [nginx time] "request" status bytes "referrer" "agent"
	regexp.MustCompile(`^(\S+) (\S+) (nginx_[A-Za-z0-9_.-]+) (\S+) - \S+ \[[^]]+\] "([^"]*)" (\d{3}) (\S+) "([^"]*)" "([^"]*)"`),
	// RFC3339 host nginx_site timing-marker client - identity "request" status bytes "referrer" "agent"
	regexp.MustCompile(`^(\S+) (\S+) (nginx_[A-Za-z0-9_.-]+) \S+ (\S+) - \S+ "([^"]*)" (\d{3}) (\S+) "([^"]*)" "([^"]*)"`),
}

// Parse parses a supported nginx syslog access record.
func Parse(line string) (Event, bool) {
	var fields []string
	for _, format := range formats {
		if fields = format.FindStringSubmatch(line); fields != nil {
			break
		}
	}
	if fields == nil {
		return Event{}, false
	}
	observedAt, err := time.Parse(time.RFC3339, fields[1])
	if err != nil {
		return Event{}, false
	}
	if _, err := netip.ParseAddr(fields[4]); err != nil {
		return Event{}, false
	}
	request := strings.Fields(fields[5])
	if len(request) < 2 {
		return Event{}, false
	}
	status, err := strconv.Atoi(fields[6])
	if err != nil {
		return Event{}, false
	}
	responseBytes, _ := strconv.ParseInt(fields[7], 10, 64)
	return Event{
		ObservedAt: observedAt.UTC(),
		Host:       fields[2],
		Site:       strings.TrimPrefix(fields[3], "nginx_"),
		IP:         fields[4],
		Method:     request[0],
		Target:     request[1],
		Status:     status,
		Bytes:      responseBytes,
		Referrer:   fields[8],
		Agent:      fields[9],
	}, true
}
