# Operations and recovery

Health checks, metrics, Redis durability, upgrades, rollback, and common
failure modes.

## Health and readiness

`GET /healthz` and `GET /readyz` return the same readiness state. They become
successful after Redis connects and every configured input starts. `GET
/metrics` always exposes the current counters on the same listener.

```sh
curl --fail http://127.0.0.1:9194/healthz
curl --fail http://127.0.0.1:9194/readyz
curl --fail http://127.0.0.1:9194/metrics
journalctl -u gatesignal --since today
```

Monitor at least:

- `gatesignal_ready` and `gatesignal_last_observation_timestamp_seconds`;
- parsed, unmatched, and tail-restart counters;
- Redis and publisher-lease failures;
- signal and analytics publish failures; and
- signal and analytics outbox depth.

For an HA pipeline, exactly one healthy instance should report
`gatesignal_publisher_owner 1`. Non-owners still parse and aggregate against the
shared Redis namespace.

## Durable state and recovery

Redis holds detection windows, publisher leases, hourly analytics, and bounded
delivery queues. Configure Redis persistence and backups to match the allowed
loss window. Access logs remain the raw source; their rotation and retention
are owned by the log router.

Back up the Redis dataset using the server's supported snapshot or append-only
file procedure. Test restores into an isolated Redis instance and namespace.
Never attach a restored shadow namespace to a publisher: use a new production
namespace at cutover so stale evaluation data cannot be sent.

If Redis is lost, GateSignal can resume from new access-log lines after the
server returns, but in-progress windows and queued deliveries are lost. Whether
older raw lines can be replayed depends on log retention and the configured
input start position. Replaying a large historical file can create misleading
current alerts; restore a tested Redis backup or replay only a bounded,
understood interval.

## Upgrades and rollback

Before replacing the binary:

1. Record the source revision and current configuration.
2. Back up Redis and preserve the previous binary.
3. Run tests and configuration validation from the replacement revision.
4. Upgrade one non-owner HA instance first, or stop the single instance.
5. Start it and verify readiness, parsing, lease state, and queue depth.
6. Upgrade the remaining instance and exercise an intentional lease transfer.

Rollback restores the previous binary and configuration. Keep the same Redis
namespace when the schema remains compatible; otherwise restore the matching
pre-upgrade Redis snapshot into an isolated namespace before re-enabling
publication. Never run old and new publishers concurrently unless the release
notes explicitly describe that mixed-version state.

## Troubleshooting

- **Startup reports a configuration error:** JSON fields are strict. Check
  spelling, output modes, required analytics values, HTTPS origins, and lease
  timing.
- **Startup cannot read a secret:** a configured `*_FILE` environment variable
  names a missing or unreadable file. Remove unused variables or correct its
  ownership and mode.
- **Startup cannot connect to Redis:** verify address, database, password, TLS
  boundary provided by the deployment, and firewall reachability.
- **Readiness remains unavailable:** inspect the journal for an input that does
  not exist or cannot be followed and confirm Redis is reachable.
- **Lines are read but unmatched:** compare the rsyslog output with the formats
  covered by `internal/accesslog`. Error logs and access logs must have distinct
  tags.
- **No external events in shadow mode:** this is expected. Shadow mode neither
  sends requests nor builds a publish backlog.
- **Queue depth grows:** check endpoint reachability, credentials, ownership,
  response status, and publish-failure counters. Do not discard the namespace
  before deciding how to handle queued evidence.
- **Multiple HA publishers claim ownership:** confirm every instance uses the
  same Redis server, database, namespace, and `publisher.pipeline_id`; then
  verify system clocks and lease settings.
- **Duplicate events after cutover:** stop the legacy publisher and confirm log
  routing is exclusive. GateSignal event IDs are deterministic, but a different
  producer may not share that idempotency key.
- **Unexpected analytics identity changes:** keep the analytics secret and
  pipeline ID stable within the intended privacy period. Rotating the secret
  deliberately breaks visitor continuity.

## Disable and remove

Set each output to `disabled` or stop the service before changing log routing.
Confirm queues are empty or deliberately archived, remove the rsyslog copy,
then disable GateSignal. Revoke its Gatehub and analytics credentials and
delete its Redis namespace only after the rollback window expires.
