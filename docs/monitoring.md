# Monitoring reference

Every admin endpoint, every Prometheus metric, and the structured admission-decision log line —
what each returns, exactly, with a realistic example. For what the underlying config that drives
these values means, see [`configuration.md`](configuration.md).

## Admin API

Both modules register a `caddy.AdminRouter` module (`admin.api.fairness` /
`admin.api.adaptive_admission`) exposing one read-only status endpoint each on Caddy's admin API
(default `localhost:2019`, unauthenticated on the local admin socket like any other Caddy admin
route). Both return `404` with `{"error": "<module> is not configured"}` if that module isn't
loaded in the running config at all, and `405` if called with anything but `GET`.

### `GET /fairness/status`

Per-backend resolved scoring configuration, per-dimension tracked-entity counts, and shared
resource (GeoIP DB / JWKS) health.

```sh
curl -s http://localhost:2019/fairness/status | jq .
```

```json
{
  "backends": [
    {
      "backend": "default",
      "base_scores": {
        "anonymous": 60,
        "internal": 100,
        "researcher": 100,
        "service_account": 100,
        "unknown": 60
      },
      "min_score": 0,
      "max_score": 100,
      "dimensions": {
        "asn": { "Alpha": 0.2, "SoftThreshold": 500, "SoftPenalty": 10, "HardThreshold": 2000, "HardPenalty": 40 },
        "country": { "Alpha": 0.2, "SoftThreshold": 2000, "SoftPenalty": 10, "HardThreshold": 10000, "HardPenalty": 40 },
        "ip": { "Alpha": 0.2, "SoftThreshold": 20, "SoftPenalty": 10, "HardThreshold": 100, "HardPenalty": 40 },
        "net24": { "Alpha": 0.2, "SoftThreshold": 100, "SoftPenalty": 10, "HardThreshold": 500, "HardPenalty": 40 },
        "net6": { "Alpha": 0.2, "SoftThreshold": 100, "SoftPenalty": 10, "HardThreshold": 500, "HardPenalty": 40 },
        "user": { "Alpha": 0.2, "SoftThreshold": 20, "SoftPenalty": 10, "HardThreshold": 100, "HardPenalty": 40 }
      },
      "dimension_entry_counts": {
        "asn": 143,
        "country": 37,
        "ip": 8912,
        "net24": 2201,
        "net6": 55,
        "user": 12
      }
    }
  ],
  "shared": {
    "geoip": [
      { "key": "/etc/caddy/GeoLite2-City.mmdb", "healthy": true, "references": 1 },
      { "key": "/etc/caddy/GeoLite2-ASN.mmdb", "healthy": true, "references": 1 }
    ],
    "jwks": [
      { "key": "https://idp.example.com/.well-known/jwks.json", "healthy": true, "references": 1 }
    ]
  }
}
```

**Field notes:**

- `backends[]` is sorted by `backend` label. One entry per distinct `fairness` handler block in
  the running config (i.e. one per `backend <label>` value actually in use).
- `base_scores` keys are the 5 `UserClass` string values; `dimensions` keys are the 6 dimension
  names (`ip`, `net24`, `net6`, `asn`, `country`, `user`).
- **`dimensions.*` fields serialize using their capitalized Go struct field names** (`Alpha`,
  `SoftThreshold`, `SoftPenalty`, `HardThreshold`, `HardPenalty`), not snake_case — `PenaltyConfig`
  has no `json` struct tags. Everything else in this response is snake_case. This is a genuine
  inconsistency in the current response shape, not a documentation error — plan your JSON parsing
  accordingly.
- `dimension_entry_counts` is the number of distinct tracked entities per dimension (e.g. distinct
  source IPs seen recently for `ip`), not an EWMA value — this is the discoverability signal used
  in [`scenarios.md`](scenarios.md)'s crawler example (an ASN with a disproportionately large `ip`
  count relative to its own `asn` entry is a sign of a distributed low-and-slow source).
- `shared.geoip` / `shared.jwks` are deduplicated by resource key (a DB path or JWKS URL) across
  *all* backends, since GeoIP readers and JWKS verifiers are pooled app-wide rather than
  per-backend — `references` counts how many backend configs currently point at that same
  resource.

### `GET /adaptive_admission/status`

Per-backend controller kind, concurrency limit, current in-flight count, mean observed backend
latency, and current queue depth.

```sh
curl -s http://localhost:2019/adaptive_admission/status | jq .
```

```json
{
  "backends": [
    {
      "backend": "default",
      "controller_kind": "adaptive",
      "limit": 87,
      "in_flight": 42,
      "mean_latency_ms": 118.4,
      "queue_size": 3
    }
  ]
}
```

**Field notes:**

- `backends[]` is sorted by `backend` label, same as `fairness/status`.
- `controller_kind` is `"fixed"` or `"adaptive"`.
- `in_flight` can read up to 1 higher than the number of requests genuinely executing against the
  backend at that instant, even while otherwise idle — the dispatch loop reserves a capacity slot
  (incrementing this counter) before it pops the next queued ticket, as a deliberate lookahead so a
  slot is never released and immediately lost to a race; this is documented behavior, not a bug.
- There is no `upstreams`/load-balancer field here on purpose — `reverse_proxy`'s own health-check
  and upstream state is already exposed by Caddy's own `admin.api.reverse_proxy` module at
  `GET /reverse_proxy/upstreams`; this endpoint only reports what `adaptive_admission` itself owns
  (capacity control + queueing), not the proxy layer behind it.

## Prometheus metrics

Registered on Caddy's own metrics registry — exposed via Caddy's built-in `metrics` directive (no
separate `/metrics` server to run). **12 series total: 1 from `fairness`, 11 from
`adaptive_admission`** (this corrects an earlier "14" figure that appeared in this project's own
README before this documentation pass).

```sh
curl -s http://localhost:2019/metrics | grep -E '^(fairness|adaptive_admission)_'
```

### `fairness` (1 metric)

| Metric | Type | Labels | Help |
|---|---|---|---|
| `fairness_score_distribution` | Histogram | `backend`, `user_class` | Distribution of computed fairness scores. Linear buckets, width 10, from 0 to 100 (11 buckets: `0,10,20,...,100`, plus `+Inf`). |

Example scrape output:

```
fairness_score_distribution_bucket{backend="default",user_class="anonymous",le="0"} 0
fairness_score_distribution_bucket{backend="default",user_class="anonymous",le="10"} 0
fairness_score_distribution_bucket{backend="default",user_class="anonymous",le="60"} 812
fairness_score_distribution_bucket{backend="default",user_class="anonymous",le="+Inf"} 15234
fairness_score_distribution_sum{backend="default",user_class="anonymous"} 891234.5
fairness_score_distribution_count{backend="default",user_class="anonymous"} 15234
```

### `adaptive_admission` (11 metrics)

| Metric | Type | Labels | Help |
|---|---|---|---|
| `adaptive_admission_requests_in_flight` | Gauge | `backend` | Requests currently admitted and in flight. |
| `adaptive_admission_concurrency_limit` | Gauge | `backend` | Current controller concurrency limit. |
| `adaptive_admission_queue_size` | Gauge | `backend` | Current number of queued (not yet admitted) requests. |
| `adaptive_admission_requests_total` | Counter | `backend` | Total requests seen. |
| `adaptive_admission_requests_admitted_total` | Counter | `backend` | Total requests admitted (dispatched to next handler). |
| `adaptive_admission_requests_rejected_total` | Counter | `backend`, `reason` | Total requests rejected, by reason (`queue_full` or `queue_wait_exceeded`). |
| `adaptive_admission_backend_errors_total` | Counter | `backend` | Total dispatched requests whose outcome was a 5xx/error. |
| `adaptive_admission_backend_timeouts_total` | Counter | `backend` | Total dispatched requests whose outcome was a timeout. |
| `adaptive_admission_adaptive_limit_changes_total` | Counter | `backend`, `direction` | Total adaptive-controller limit changes, by direction (`grow` or `shrink`). |
| `adaptive_admission_backend_request_duration_seconds` | Histogram | `backend` | Dispatched request duration. Prometheus default buckets. |
| `adaptive_admission_queue_wait_duration_seconds` | Histogram | `backend` | Time an admitted request spent queued before admission. Prometheus default buckets. |

Example scrape output:

```
adaptive_admission_requests_in_flight{backend="default"} 42
adaptive_admission_concurrency_limit{backend="default"} 87
adaptive_admission_queue_size{backend="default"} 3
adaptive_admission_requests_total{backend="default"} 918273
adaptive_admission_requests_admitted_total{backend="default"} 915102
adaptive_admission_requests_rejected_total{backend="default",reason="queue_full"} 41
adaptive_admission_requests_rejected_total{backend="default",reason="queue_wait_exceeded"} 3130
adaptive_admission_backend_errors_total{backend="default"} 218
adaptive_admission_backend_timeouts_total{backend="default"} 12
adaptive_admission_adaptive_limit_changes_total{backend="default",direction="grow"} 1204
adaptive_admission_adaptive_limit_changes_total{backend="default",direction="shrink"} 87
adaptive_admission_backend_request_duration_seconds_bucket{backend="default",le="0.5"} 912004
adaptive_admission_backend_request_duration_seconds_sum{backend="default"} 108234.9
adaptive_admission_backend_request_duration_seconds_count{backend="default"} 915102
adaptive_admission_queue_wait_duration_seconds_bucket{backend="default",le="0.1"} 909811
adaptive_admission_queue_wait_duration_seconds_sum{backend="default"} 42039.2
adaptive_admission_queue_wait_duration_seconds_count{backend="default"} 915102
```

## Structured admission-decision log line

`adaptive_admission` emits exactly one `zap` structured log line per request, at `info` level,
with message `admission_decision`. `fairness` never logs a decision on its own — its
classification/score output is folded into this same line via the `fairness_log_fields` hand-off
(§8 of [`configuration.md`](configuration.md)), so there is exactly one log line per request across
both modules combined, not one each.

Fields present on **every** line: `backend` (string), `admitted` (bool).

Fields present **only when `admitted: true`**: `queue_wait_ms` (int64), `backend_latency_ms`
(int64), `status_code` (int).

Fields present **only when `admitted: false`**: `reject_reason` (string, `queue_full` or
`queue_wait_exceeded`) — mutually exclusive with the three admitted-only fields above.

Fields folded in from `fairness` **when a `fairness` handler ran earlier in the chain** (absent
entirely if `fairness` wasn't configured for this route): `ip` (string), `asn` (uint64, the numeric
AS number, only present when GeoIP ASN lookup resolved), `country` (string, ISO alpha-2, only
present when GeoIP city lookup resolved), `user_class` (string), `exempt` (bool, whether `country`
was on the `exempt_country` list for this request), `score_breakdown` (object — always has `base`
and `final`; always has `total_penalty` after fairness has computed a score, present as `0` if no
dimension contributed a penalty; and one `penalty_<dimension>` key per dimension that actually
contributed a non-zero penalty this request, e.g. `penalty_asn` — dimensions contributing `0` are
omitted entirely rather than listed with a `0` value).

**Example — admitted request:**

```json
{
  "level": "info",
  "msg": "admission_decision",
  "backend": "default",
  "admitted": true,
  "queue_wait_ms": 4,
  "backend_latency_ms": 87,
  "status_code": 200,
  "ip": "203.0.113.42",
  "asn": 64500,
  "country": "PT",
  "user_class": "anonymous",
  "exempt": false,
  "score_breakdown": { "base": 60, "total_penalty": 0, "final": 60 }
}
```

**Example — rejected request** (the low-and-slow crawler ASN from
[`scenarios.md`](scenarios.md), after a tuned `penalty asn` override pushed it into the queue's
lowest-priority tier and it lost the race against a full queue):

```json
{
  "level": "info",
  "msg": "admission_decision",
  "backend": "default",
  "admitted": false,
  "reject_reason": "queue_full",
  "ip": "198.51.100.17",
  "asn": 64501,
  "country": "SG",
  "user_class": "anonymous",
  "exempt": false,
  "score_breakdown": { "base": 60, "penalty_asn": 10, "total_penalty": 10, "final": 50 }
}
```
