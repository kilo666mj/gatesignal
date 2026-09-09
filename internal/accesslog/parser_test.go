package accesslog

import "testing"

func TestParseFormats(t *testing.T) {
	tests := []string{
		`2026-09-09T11:24:02+02:00 web.example.com nginx_example 192.0.2.10 - - [09/Sep/2026:11:24:02 +0200] "GET /hello?secret=value HTTP/2.0" 200 13 "https://search.example/search?q=x" "browser" "-" "-"`,
		`2026-08-24T15:24:16+02:00 web.example.com nginx_example [000] 2001:db8::10 - - "GET /.git/HEAD HTTP/2.0" 404 30 "-" "scanner" "-" "-"`,
		`2026-08-21T17:54:49+02:00 web.example.com nginx_example 17:54:49 192.0.2.10 - - "HEAD / HTTP/1.1" 200 0 "-" "monitor" "-" "-"`,
	}
	for _, line := range tests {
		event, ok := Parse(line)
		if !ok {
			t.Fatalf("failed to parse %q", line)
		}
		if event.Host != "web.example.com" || event.Site != "example" {
			t.Fatalf("unexpected event: %#v", event)
		}
	}
}

func TestRejectsNonAccessRecords(t *testing.T) {
	line := `2026-09-09T11:24:02+02:00 web.example.com nginx_example 2026/09/09 11:24:02 [error] upstream failed`
	if _, ok := Parse(line); ok {
		t.Fatal("parsed nginx error record as access traffic")
	}
}
