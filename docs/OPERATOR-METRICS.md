# Enabling KMS metrics (permissionlessweb/kms, branch `metrics-merge`)

Metrics come from danbryan/kms `metrics` branch (commit 3b7ff47, "Add optional Prometheus
metrics endpoint"), merged onto permissionlessweb/kms `main` (e85f792). Target: CometBFT
**v0.40.0** (same as cosmos/kms main and our terp-core v6.4.0 dev nodes). It is not v0.37.

> Status: these metrics exist only on the local `metrics-merge` branch. Neither the dev KMS
> nor the mainnet KMS binary that is running now serves metrics. The cosmos/kms (Go) signer
> on the main validator does not serve them either.

## 1. Enable

Add to the kms YAML config (the same file passed via `--home`). The block is opt-in:
if you leave it out, nothing listens. Collection inside the process is always on.

```yaml
metrics:
  listen: <bind-addr>:<port>   # upstream example uses port 8545; serves GET /metrics
```

- Path: `/metrics`. This is the only route, with standard Prometheus text exposition.
- There are no CLI flags or env vars. Config is the only way to turn it on.
- If you add `metrics:` without `listen`, startup fails with `config: metrics block requires listen`.
- On startup the log shows `serving metrics listen=... path=/metrics`.
- **No authentication and no TLS.** Bind to loopback or a private interface, and firewall it.
  The response includes the public consensus address (`kms_key_info`) and the validator dial address.
  Pick a port that does not collide with anything else on the host. For example, 8545 is the
  common EVM JSON-RPC port.
- Check it with: `curl -s http://<kms-host>:<port>/metrics | grep ^kms_`

## 2. Prometheus scrape config

```yaml
scrape_configs:
  - job_name: kms
    scrape_interval: 15s
    static_configs:
      - targets: ['<kms-host>:<port>']
        labels:
          role: signer
```

## 3. Metric reference (all implemented in `internal/metrics/metrics.go`)

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `kms_build_info` | gauge (=1) | version, go_version | Running build |
| `kms_key_info` | gauge (=1) | chain_id, backend, algorithm, address | Configured key per chain. `address` is the public consensus address |
| `kms_validator_connected` | gauge | chain_id, addr | 1 while the dial-out privval connection is up, 0 otherwise |
| `kms_validator_connected_since_timestamp_seconds` | gauge | chain_id, addr | Unix time the current connection was established |
| `kms_validator_dials_total` | counter | chain_id, addr, result=ok\|error | Dial attempts. A burst of `ok` means the node keeps restarting or dropping the connection |
| `kms_requests_total` | counter | chain_id, type=proposal\|prevote\|precommit\|pubkey\|ping, result=ok\|refused\|error | Every privval request. `refused` = double-sign guard (CometBFT FilePV "height/round/step regression" or "conflicting data") |
| `kms_sign_duration_seconds` | histogram | chain_id, type | Whole-request latency (checks + backend sign + state persist). Buckets run from 0.5 ms to 2.5 s |
| `kms_last_signed_height` | gauge | chain_id, type | Height of the last successful signature of that type |
| `kms_last_signed_round` | gauge | chain_id, type | Round of the same |
| `kms_last_signed_timestamp_seconds` | gauge | chain_id, type | Unix time of the same |
| `kms_sign_state_height` / `_round` / `_step` | gauge | chain_id | Double-sign high-water mark (step 1 = proposal, 2 = prevote, 3 = precommit). Note: this is updated from successful signs in this process, not read from the state file at startup |
| `kms_backend_sign_duration_seconds` | histogram | backend, algorithm | Raw key-backend `Sign` latency (file, pkcs11, awskms, bluetooth, ...) |
| `kms_backend_errors_total` | counter | backend, algorithm | Errors returned by the backend's `Sign` |
| `go_*`, `process_*` | various | - | Standard Go runtime and process collectors |

Fork-specific note: when a connection uses the request's chain id (the temporary takeoff node),
`chain_id` on request metrics is the id from the request. That can add short-lived series.

## 4. Suggested alerts

```yaml
groups:
- name: kms
  rules:
  - alert: KMSDown                      # process dead or unreachable
    expr: up{job="kms"} == 0
    for: 1m
  - alert: SignerDisconnected
    expr: kms_validator_connected == 0
    for: 1m
  - alert: SignerFlapping
    expr: increase(kms_validator_dials_total{result="ok"}[10m]) > 3
  - alert: SignerNotSigning             # signing gap / missed heights
    expr: time() - max by (chain_id) (kms_last_signed_timestamp_seconds{type="precommit"}) > 60
    for: 2m
  - alert: SignedHeightStalled
    expr: changes(kms_last_signed_height{type="precommit"}[5m]) == 0
    for: 5m
  - alert: DoubleSignGuardTriggered
    expr: increase(kms_requests_total{result="refused"}[5m]) > 0
    labels: {severity: critical}
  - alert: SignRequestErrors
    expr: increase(kms_requests_total{result="error"}[5m]) > 0
  - alert: BackendErrors
    expr: increase(kms_backend_errors_total[5m]) > 0
  - alert: SignLatencyHigh
    expr: histogram_quantile(0.99, sum by (le, chain_id) (rate(kms_sign_duration_seconds_bucket[5m]))) > 0.1
    for: 15m
  - alert: UnexpectedKey
    expr: absent(kms_key_info{address="<EXPECTED_CONSENSUS_ADDRESS>"})
```

The KMS cannot see missed blocks on-chain. For actual missed-block counts, pair these alerts with
CometBFT node metrics (`cometbft_consensus_validator_missed_blocks`, `cometbft_consensus_height`)
or a chain-side exporter.

## 5. Grafana

Import `docs/grafana-dashboard.json` (shipped by the merge). It asks for a Prometheus datasource
when you import it, and its thresholds match the alerts above. Useful panels: connected state per
chain/addr, last signed height against node height, requests by result (stacked), p50/p99
`kms_sign_duration_seconds`, and backend latency/errors.

## 6. OpenTelemetry

**Not implemented.** There is no OTLP exporter, no tracing, and no otel dependency in the code.
To get the data into an OTel pipeline today, scrape `/metrics` with the OpenTelemetry Collector
`prometheus` receiver:

```yaml
receivers:
  prometheus:
    config:
      scrape_configs:
        - job_name: kms
          static_configs: [{targets: ['<kms-host>:<port>']}]
```

*Planned / not implemented:* native OTLP push, tracing spans per sign request, and
authentication or TLS on the metrics listener.
