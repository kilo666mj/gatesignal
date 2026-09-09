# GateSignal

GateSignal turns HTTP access logs into privacy-limited operational signals. It
detects scanner-like traffic for [Gatehub](https://github.com/kilo666mj/gatehub)
and can export aggregated web analytics without exporting raw request targets,
query strings, referrer URLs, user agents, or visitor addresses.

```text
HTTP access logs -> GateSignal -> Gatehub -> enforcement gates
                              \-> aggregate analytics
```

GateSignal is intentionally responsible for the complete HTTP access-log
pipeline: ingestion, parsing, windowed detection, aggregation, durable delivery,
health, and metrics. General system and application alerting belongs in a
separate log monitor.

## Status

GateSignal is ready for shadow-mode evaluation. The wire format is compatible
with Gatehub's existing aggregate web-signal endpoint. Do not enable `publish`
mode until the Gatehub node is registered and the former publisher is disabled.

## Features

- Follows one or more files written by rsyslog or another log router.
- Parses nginx access records with RFC 3339 envelope timestamps.
- Uses atomic Redis-compatible counters for HA-safe detection windows.
- Detects configurable error-rate and suspicious-URI thresholds.
- Keeps a bounded, durable Gatehub outbox with deterministic event IDs.
- Produces hourly analytics with normalized paths, referrer hostnames, and
  daily one-way visitor identifiers.
- Provides `disabled`, `shadow`, and `publish` modes independently for signals
  and analytics.
- Exposes `/healthz`, `/readyz`, and Prometheus metrics.

## Build and test

GateSignal requires Go 1.26 or newer.

```sh
go build ./cmd/gatesignal
go test -race ./...
go vet ./...
```

## Configuration

Copy `config.example.json` to `/etc/gatesignal/config.json`. Start with both
outputs in `shadow` mode and a dedicated Redis namespace such as
`gatesignal-shadow`.

Credentials should be stored in root-owned files and referenced through:

- `GATESIGNAL_REDIS_PASSWORD_FILE`
- `GATESIGNAL_GATEHUB_TOKEN_FILE`
- `GATESIGNAL_ANALYTICS_SECRET_FILE`
- `GATESIGNAL_ANALYTICS_TOKEN_FILE`
- `GATESIGNAL_ANALYTICS_ACCESS_CLIENT_ID_FILE`
- `GATESIGNAL_ANALYTICS_ACCESS_CLIENT_SECRET_FILE`

Inline credential fields exist for development, but should not be used in a
tracked production configuration.

### Output modes

- `disabled`: does no processing for that output.
- `shadow`: performs parsing, detection, or aggregation but makes no external
  requests and does not build a publish backlog.
- `publish`: enables the durable external publisher.

Use a new Redis namespace when changing a shadow deployment to production.
This prevents retained shadow aggregates from being exported after cutover.

## Log routing

GateSignal and a general log monitor can run on the same collector. They should
not compete for a listening socket. Route HTTP access records into GateSignal's
own file or socket and keep application, system, and web-server error records on
the general log path. `contrib/rsyslog/30-gatesignal.conf` shows a non-destructive
shadow-mode copy.

See [docs/migration.md](docs/migration.md) for the cutover sequence and
`contrib/systemd/gatesignal.service` for a hardened service example.

## Privacy model

Gatehub signals contain the source address, affected host/site, trigger,
connection counts, and observation window. They never include the request
target or HTTP headers.

Analytics remove query strings, reduce external referrers to hostnames, and use
a daily secret-derived digest for visitor cardinality. Raw visitor addresses and
user agents remain transient input fields and are not stored in analytics keys
or payloads.

## License

[MIT](LICENSE)
