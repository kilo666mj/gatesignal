# Deployment and configuration

Production prerequisites, configuration ownership, service installation, log
routing, and staged publication.

## Prerequisites

GateSignal needs:

- a Linux host with access to dedicated nginx access-log files;
- a Redis-compatible server with persistence appropriate for the desired
  recovery point;
- Gatehub node credentials when signals publish;
- analytics credentials and a stable secret when analytics publish; and
- Go 1.27.1 or newer to build from source.

Run GateSignal on the log collector or another host that receives the same
timestamped records. Keep the health and Prometheus listener on loopback or a
protected monitoring network.

## Build and install

Build a static binary from a reviewed revision, then install the provided
service example and a deployment-specific configuration:

```sh
go test -race ./...
go vet ./...
CGO_ENABLED=0 go build -trimpath -o gatesignal ./cmd/gatesignal
sudo install -m 0755 gatesignal /usr/local/bin/gatesignal
sudo install -d -o root -g gatesignal -m 0750 /etc/gatesignal
sudo install -m 0644 contrib/systemd/gatesignal.service /etc/systemd/system/gatesignal.service
sudo install -o root -g gatesignal -m 0640 config.example.json /etc/gatesignal/config.json
```

Create the `gatesignal` system user and group before the directory commands.
Give that group read access to GateSignal's dedicated log files, but not to
unrelated system logs.

The service example names each supported secret-file environment variable. A
referenced file must exist even when that output is in shadow mode. Remove
unused environment lines from the local unit override, or create the required
root-owned files with mode `0640` and group `gatesignal`.

After configuring the service:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now gatesignal
sudo systemctl status gatesignal
curl --fail http://127.0.0.1:9194/readyz
```

## Configuration

`-config` selects the JSON file and defaults to
`/etc/gatesignal/config.json`. Unknown JSON fields are rejected.

| Section | Purpose | Important constraints |
| --- | --- | --- |
| `inputs` | Files to follow | At least one path; `start_position` is `beginning` or `end` |
| `redis` | Counters, queues, analytics, and lease state | Address and namespace are required; use a dedicated namespace per environment |
| `http` | Health, readiness, and metrics listener | Required; bind to loopback unless a firewall protects it |
| `publisher` | Stable HA pipeline identity and renewable lease | Required for publish mode; renew interval must be less than half the TTL |
| `signals` | Detection thresholds and Gatehub delivery | Gatehub origin must be HTTPS in publish mode; instance ID and token are required |
| `analytics` | Site mapping, privacy filters, and analytics delivery | Sites, secret, retention, and queue bounds are required when enabled |

Credentials can be supplied inline for development. In production, put them in
root-owned files and set the matching environment variables documented in the
[README](../README.md#configuration).

Use RFC-reserved domains and addresses in shared examples. Keep production
site names, collector identities, endpoints, and credentials in private
configuration management.

## Log routing

Give HTTP access and error streams distinct syslog program names or facilities.
Copy only access records to GateSignal's dedicated file while shadowing:

```sh
sudo install -m 0644 contrib/rsyslog/30-gatesignal.conf /etc/rsyslog.d/30-gatesignal.conf
sudo rsyslogd -N1
sudo systemctl restart rsyslog
```

The committed rsyslog example deliberately leaves the existing route active.
After cutover, keep web-server error logs and general system/application alerts
on the general monitoring path.

## Staged rollout

1. Start both outputs in `shadow` with a new Redis namespace.
2. Verify parsed/unmatched counts, thresholds, privacy, and retention.
3. If more than one collector participates, configure the same
   `publisher.pipeline_id` and namespace on every instance and test lease
   transfer while still shadowing.
4. Register one dedicated `gatesignal` node in Gatehub.
5. Disable the previous publisher, change to a fresh production namespace, and
   enable only the signal output.
6. Verify one reserved-address canary, queue drainage, and Gatehub receipt.
7. Repeat separately for analytics, then make log routing exclusive.

The full cutover and rollback sequence is in [migration.md](migration.md).
