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

## Security boundary

GateSignal is an observer and publisher, not an inline firewall. It reads
untrusted access-log text and emits aggregate evidence; Gatehub owns policy,
and the enforcement gates keep their own explicit rollout controls. A forged or
malformed log line must never be treated as authentication or as proof of a
person's identity.

Raw request targets, query strings, headers, referrer URLs, user agents, and
visitor addresses are processed in memory. Gatehub signals include a source
address and aggregate counts because correlation requires them; analytics use
a daily secret-derived visitor identifier instead. Protect access-log files,
Redis state, output credentials, and the loopback-only health/metrics listener.

## Status

GateSignal supports staged shadow and publish operation. Start in shadow mode,
verify parsing, thresholds, privacy, and HA lease transfer, then enable one
publisher at a time. Do not enable `publish` mode until the Gatehub node is
registered and the former publisher is disabled.

## Features

- Follows one or more files written by rsyslog or another log router.
- Parses nginx access records with RFC 3339 envelope timestamps.
- Uses atomic Redis-compatible counters for HA-safe detection windows.
- Detects configurable error-rate and suspicious-URI thresholds.
- Keeps a bounded, durable Gatehub outbox with deterministic event IDs.
- Elects one external publisher with a renewable Redis lease for HA deployments.
- Produces hourly analytics with normalized paths, referrer hostnames, and
  daily one-way visitor identifiers.
- Provides `disabled`, `shadow`, and `publish` modes independently for signals
  and analytics.
- Exposes `/healthz`, `/readyz`, and Prometheus metrics.

## Safe quick start

GateSignal requires Go 1.27.1 or newer and a Redis-compatible server. With a
development Redis listening on `127.0.0.1:6379`:

```sh
go build -o gatesignal ./cmd/gatesignal
go test -race ./...
go vet ./...
touch access.log
./gatesignal -config examples/config.shadow.json
```

The example enables only shadow signal detection. It makes no external
requests, writes state below the `gatesignal-quickstart` Redis namespace, and
serves health and metrics on loopback. In another terminal, append a synthetic
nginx syslog record and inspect the counters:

```sh
printf '%s\n' '2026-09-17T10:00:00Z web.example.com nginx_example 192.0.2.10 - - [17/Sep/2026:10:00:00 +0000] "GET /.git/HEAD HTTP/2.0" 404 30 "-" "example-scanner" "-" "-"' >> access.log
curl --fail http://127.0.0.1:9194/readyz
curl --fail http://127.0.0.1:9194/metrics
```

Stop the process and remove the example namespace before reusing the same Redis
database for another evaluation.

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

All instances in an HA pipeline must use the same `publisher.pipeline_id` and
Redis namespace. The pipeline ID replaces the collector hostname in analytics
bucket identity, so failover retries update the same site/hour bucket instead
of creating a duplicate. Only the renewable lease holder sends external
requests; non-owners continue aggregation and durable queueing.
The lease is active in shadow mode when a pipeline ID is configured, allowing
ownership and failover to be verified before either output is enabled.

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

## Documentation

- [Deployment and configuration](docs/deployment.md)
- [Operations, recovery, and troubleshooting](docs/operations.md)
- [Migration from an existing web-log processor](docs/migration.md)
- [How the five Gate projects fit together](https://github.com/kilo666mj/michaelspost-docs/blob/main/docs/guides/gate-stack.md)

## License

[MIT](LICENSE)
