# Migration from an existing web-log processor

The migration is designed to prevent both lost observations and duplicate
external events.

## 1. Prepare a separate input

Configure the central log router to copy HTTP access records to
`/var/log/gatesignal/access.log`. Keep the existing route active. Ensure the
GateSignal service account can read the new file and its rotated successors.

Access and error logs should have distinct tags or facilities before the final
route is made exclusive. Web-server error logs normally remain with the general
log monitor.

## 2. Run GateSignal in shadow mode

Set both outputs to `shadow` and use a dedicated namespace:

```json
{
  "redis": { "namespace": "gatesignal-shadow" },
  "publisher": { "pipeline_id": "central-web" },
  "signals": { "mode": "shadow" },
  "analytics": { "mode": "shadow" }
}
```

Shadow mode detects and aggregates, but neither sends external requests nor
queues data for later publication. Compare these Prometheus counters with the
existing processor:

- `gatesignal_lines_parsed_total`
- `gatesignal_signals_detected_total`
- `gatesignal_analytics_observations_total`
- `gatesignal_redis_failures_total`
- `gatesignal_analytics_dropped_total`

## 3. Prepare consumers

Register a dedicated Gatehub node for GateSignal and configure its token file.
Confirm that the analytics receiver accepts `source: gatesignal`. Keep the
GateSignal outputs in shadow mode during this preparation.

Before publication, run every HA instance with the same production Redis
namespace and `publisher.pipeline_id`. Verify that exactly one instance reports
`gatesignal_publisher_owner 1`, then exercise lease transfer by stopping that
instance. The peer must become owner after the lease TTL without duplicating
the deterministic signal or analytics identity.

## 4. Cut over one output at a time

For each output:

1. Disable that output in the existing processor.
2. Change GateSignal to a fresh production Redis namespace.
3. Enable GateSignal `publish` mode.
4. Send a documentation-address canary and verify exactly one resulting event.
5. Check the outbox depth and failure metrics.

Never leave both publishers enabled with the same input stream.

## 5. Make log routing exclusive

After both outputs are stable, stop routing HTTP access records to the old
processor. Keep web-server error records on the general log path. Remove the
old web-processing code only after a normal observation period and a verified
rollback package are available.
