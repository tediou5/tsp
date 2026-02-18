TSP Network Traffic Benchmark
=============================

For local `seal` and `open` benchmark, see [Benchmark](./benchmark.md).
Use `tsp bench` for sustained transport traffic tests.

## Quick start

Server:

```sh
tsp --wallet bob bench server
```

Client:

```sh
tsp --wallet alice bench client \
  --profile local-tcp \
  --payload-size 1KiB \
  --duration 30s
```

## Built-in profiles

- `local-tcp` default:
  - server uses `--vid bob`
  - client uses `--sender alice --receiver bob`
- `hosted-http`:
  - server uses `--vid b`
  - client uses `--sender a --receiver b`
- If `--transport` is omitted, endpoint is derived from receiver VID.
- Explicit `--vid` `--sender` `--receiver` `--transport` override profile defaults.

Hosted HTTP baseline:

```sh
tsp --wallet bench-http-b bench server --profile hosted-http
```

```sh
tsp --wallet bench-http-a bench client \
  --profile hosted-http \
  --payload-size 1KiB \
  --duration 30s
```

## Output and metrics

Throughput output:

```text
Session 1 started (TCP)
[ ID]     Interval  Proto     Transfer  Messages      Msg/s        Bandwidth  Seal_us(p50)  Open_us(p50)
[  0]      1.0 sec    TCP      1.2 MiB       120     120.00    10.20 Mbits/s         650.3         710.1
...
Session 1 summary:
[SUM]  30.0 sec    TCP      36.1 MiB      3600     120.00    10.08 Mbits/s         642.0         705.8
```

Latency mode:

```sh
tsp --wallet alice bench client \
  --payload-size 1KiB \
  --duration 30s \
  --mode latency
```

Latency mode reports RTT and jitter with p50, p95, p99, and stddev.

If `--transport` is set, it must match the receiver VID endpoint.
This check fails fast when transport routing does not match VID routing.

Server throughput output is session-based. If traffic is idle for `>= 2 * interval`,
next traffic starts a new session and prints a new `SUM` line.

## Measurement scope

- For custom identities, sender and receiver should already be verified and related.
- Built-in profiles auto-bootstrap local keys, verification, and relationship.
- Relationship setup and first-time VID verification are outside the measured window.

## JSON output

Server and client support `--json` for machine-readable summary output.

Example:

```sh
tsp --wallet alice bench client ... --json
```

## Compare with `iperf3`

1. Run `iperf3` with the same host, port, payload, and duration.
2. Run `tsp bench` with the same settings.
3. Compare bandwidth and latency distribution.

For baseline tests, prefer HTTP(S) first because reqwest reuses pooled connections.

- base transport bandwidth: `X Mbits/s`
- TSP bandwidth: `Y Mbits/s`
- overhead ratio: `1 - (Y / X)`

## Current limits

- Supported transports: TCP, TLS, QUIC, HTTP, HTTPS.
- Single stream.
- Payload size must be set.
- Built-in profiles: `local-tcp` and `hosted-http`.
- TCP TLS QUIC paths currently use one connection per message.
