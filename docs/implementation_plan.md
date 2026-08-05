# caddy-adaptive-admission-controller — Implementation Plan

## Context

`REQUIREMENTS.md` is fully decided (all §7 open questions resolved). This plan turns that
requirements doc into an ordered build sequence for a production port
(`caddy-adaptive-admission-controller`, two Caddy modules — `fairness` and `adaptive_admission` —
composed in one repo but independently importable per §3.4).

**Workflow:** implement one phase at a time, in the order below. At the end of each phase — once
its own verification step passes — commit with a Conventional Commit message before starting the
next phase. Phases are not batched into one commit.

## Package layout (repo root, module path `github.com/arquivo/caddy-adaptive-admission-controller`)

```
/fairness/                  http.handlers.fairness + its caddy.App (namespace "fairness")
    module.go               module registration, ServeHTTP, RegisterOrder position
    app.go                  App: GeoIP DB / JWKS UsagePool-based resource dedup (keyed by identity)
    classify.go              per-request classification (ip/subnet/asn/country/user class)
    geoip.go                 MaxMind mmdb readers, fail-open
    auth.go                  JWT/JWKS verification, background refresh, fail-open
    scoring.go               per-backend EWMA state (ClientStats maps) + penalty computation
    config.go                Caddyfile + JSON config structs, override-merge (deep-copy safe)
    caddyfile.go             UnmarshalCaddyfile
    admin.go                 caddy.AdminRouter: GET /fairness/status (phase 10)
    metrics.go               score-distribution histogram registration (phase 9)
    *_test.go                table-driven tests colocated per file above

/adaptiveadmission/         http.handlers.adaptive_admission + its caddy.App (namespace "adaptive_admission")
    module.go                module registration, ServeHTTP, RegisterOrder position
    app.go                    App: per-backend capacity/LB/queue state
    capacity.go               fixed + adaptive controllers, bounded-wake acquire/release
    capacity_test.go          multiplier/cooldown/threshold table-driven tests
    queue.go                  bounded priority queue/scheduler, rejection reasons
    queue_test.go             ordering + queue_full/queue_wait_exceeded tests
    dispatch.go               reverse_proxy composition, sticky/backup verification
    config.go / caddyfile.go
    admin.go                  caddy.AdminRouter: GET /adaptive_admission/status (phase 10)
    metrics.go / logging.go   phase 9

/cmd/loadtest/               port of scripts/load_test.py — concurrency ramp/sweep tool (phase 11)

/examples/                   runnable example Caddyfiles (single-backend, multi-backend w/ import)

implementation_plan.md       this plan
```

Package boundary rule: `fairness` and `adaptiveadmission` never import each other's internals — the
only coupling point is the `caddyhttp.SetVar`/`GetVar` score hand-off (already a documented Caddy
mechanism, not a Go dependency).

## Phases

### Phase 1 — Documentation review & implementation plan

Re-read `REQUIREMENTS.md` and `README.md` end-to-end for internal consistency; write this phase
breakdown into `implementation_plan.md` at repo root. No code. **Done when:**
`implementation_plan.md` exists and matches this plan; committed.

### Phase 2 — Project scaffolding

`go.mod` (module path above), directory layout above with empty/no-op `fairness` and
`adaptiveadmission` packages: each registers its `http.handlers.*` directive and `caddy.App` with
Caddy's plugin registry, unmarshals a minimal Caddyfile stanza, and passes the request straight to
`next.ServeHTTP()` with no logic yet. A local `xcaddy build --with
github.com/arquivo/caddy-adaptive-admission-controller=.` must succeed and produce a runnable
binary. **Done when:** `go build ./...` and a local `xcaddy build` both succeed; a trivial Caddyfile
loading both no-op directives runs and proxies a request end-to-end.

### Phase 3 — GitHub CI

Add `.github/workflows/build.yml`: on push/PR to `main`, run `go vet ./...`, `go test ./...`, and an
`xcaddy build --with github.com/arquivo/caddy-adaptive-admission-controller=.` step to catch
plugin-registration breakage that plain `go build` wouldn't (mirrors how this project will actually
be consumed, per §3.4). Keep the existing `commitlint.yml` untouched. **Done when:** the workflow
runs green on the scaffolding from Phase 2, in CI (not just locally).

### Phase 4 — `fairness`: ingress consumption + classification

Consume `{client_ip}` (§4.1 — no custom trusted-proxy logic). Implement classification (§4.2): IP,
`/24`/`/48`/`/56` subnet bucketing, ASN + country via MaxMind `.mmdb` (fail-open independently per
DB), user class + user ID via optional JWT/JWKS (fail-open, background refresh). GeoIP reader /
JWKS refresh loop live on the `fairness` App module, deduped via `caddy.UsagePool` keyed by file
path / issuer URL (§3.1). Full Caddyfile + JSON unmarshaling for this config surface. **Done when:**
table-driven tests cover subnet bucketing edge cases (IPv4/IPv6, prefix boundaries) and fail-open
paths (missing/corrupt mmdb, unreachable JWKS); a config with two blocks pointing at the same GeoIP
path opens the DB once (assert via a counting fake or reference count).

### Phase 5 — `fairness`: EWMA scoring

Implement `ClientStats`/EWMA maps **per handler instance** (§3.2/§7 Q6 — isolated per backend, not
on the App module), the fixed-tick EWMA update, per-dimension soft/hard threshold → penalty
evaluation, backend-override deep-merge over global defaults (with explicit deep-copy of shared
default maps/slices before mutation), exempt-country handling (counted, not penalized), and the
idle-entry GC ticker. Writes final score via `caddyhttp.SetVar`. **Done when:** table-driven tests
assert exact EWMA math against hand-computed sequences, exact penalty amounts at/around soft/hard
thresholds, override-merge correctness (backend override changes only its own dimension, doesn't
mutate the shared default read by another backend), and GC reclaiming idle entries after TTL.

### Phase 6 — `adaptiveadmission`: capacity controller (isolated package first)

Build `capacity.go` standalone, before wiring into the request path: fixed controller (static
limit) and adaptive controller (min/initial/max concurrency, the exact multiplier/cooldown table
from §4.4 — timeout-rate ×0.60/60s, error-rate ×0.75/30s, p95>2×target ×0.70/30s, p95>target ×0.85,
grow at p95<0.5×target ×1.05/no cooldown). `acquire(cost)`/`release(...)` using `sync.Cond.Signal()`
in a bounded loop (never `Broadcast()`), waking exactly enough waiters for freed capacity, and
waking immediately on a limit increase. **Done when:** unit tests assert each multiplier/cooldown
branch in isolation (fake clock, synthetic latency/error/timeout-rate inputs), and a concurrency
stress test (many goroutines calling `acquire`/`release`) asserts no over-admission beyond the
current limit and no deadlock/lost wakeups — this is the subtlest primitive in the system and gets
tested before anything depends on it.

### Phase 7 — `adaptiveadmission`: priority queue / scheduler

Bounded priority queue ordered by score then arrival FIFO; rejects `queue_full` vs
`queue_wait_exceeded` (Little's-law projected wait) as distinct reasons; worker acquires capacity
before popping the head (comment the uniform-cost-1 assumption this depends on, per §4.5). **Done
when:** tests assert priority ordering (higher score served first, FIFO within same score),
rejection-reason correctness at each boundary, and that this composes correctly with the Phase 6
capacity controller (acquire-before-pop under concurrent load).

### Phase 8 — Wire the request path end-to-end

Register `httpcaddyfile.RegisterOrder` for both directives (`fairness` immediately before
`adaptive_admission`, §7 Q7). `adaptive_admission` reads the score via `caddyhttp.GetVar` with a
neutral-score fail-open default. Compose dispatch with `reverse_proxy` (`lb_policy least_conn`,
active+passive health checks, `cookie`/`client_ip_hash` stickiness, primary/backup upstream tiers)
per §4.6/§4.7 — verify Caddy's actual behavior with multiple upstreams matches the "fail open to
full instance set" requirement rather than assuming it. **Done when:** an example Caddyfile
(`/examples`) with `fairness` + `adaptive_admission` + `reverse_proxy` chained (both the bare
top-level form relying on `RegisterOrder`, and the explicit `route { }` form) proxies real requests
end-to-end against two dummy upstreams, correctly prioritizing higher-score requests under
saturation and correctly failing over on an unhealthy upstream.

### Phase 9 — Metrics + structured logging

Register the 14-metric surface (§4.8) against Caddy's existing Prometheus registry (no second
`/metrics` server); `adaptive_admission` emits the single structured JSON log line per admission
decision (§4.9), folding in `fairness`'s classification/score fields via `GetVar` — `fairness` never
logs per-request itself. **Done when:** `/metrics` exposes all 14 series with correct labels after a
handful of test requests; log output is exactly one structured line per request, containing every
field the spec lists.

### Phase 10 — Admin / introspection API

Both App modules implement `caddy.AdminRouter` (§4.10): `GET /adaptive_admission/status`
(per-backend controller/limit/latency/queue/upstream snapshot) and `GET /fairness/status`
(per-backend resolved scoring config + EWMA counters, plus a shared GeoIP/JWKS health section).
**Done when:** hitting both endpoints on `localhost:2019` against a running instance returns the
documented per-backend shape, matching live state after synthetic traffic.

### Phase 11 — Load testing

Port `scripts/load_test.py`'s concurrency ramp/sweep into `/cmd/loadtest` (ramp-up, hold-open,
multi-endpoint, measuring p50/p95/p99 and throughput vs. offered concurrency, per §8). Run it against
the full chain built in Phase 8 with realistic dummy upstream latency. If throughput inverts at any
concurrency level, profile with `pprof` before hypothesizing a fix (§8's explicit lesson from the
Python investigation). **Done when:** a load-test run report is captured showing throughput does not
invert the way the Python system's did across the same concurrency range (50→250), or, if it does,
the `pprof` profile identifying the actual cause is captured and a targeted fix is applied and
re-verified — not a speculative fix.

### Phase 12 — Release polish

`xcaddy build` release workflow producing a downloadable binary artifact (and container image if
useful), README updated with build/usage instructions, example Caddyfiles finalized. **Done when:** a
tagged release (or dry-run of the release workflow) produces a working binary artifact via CI.

## Verification summary

- Every phase from 4 onward ships with table-driven Go tests colocated with the code (`go test
  ./...` must stay green across phases — CI from Phase 3 onward enforces this automatically).
- Phase 2/3 verify buildability (`go build`, `xcaddy build`) before any business logic exists.
- Phase 8 is the first true end-to-end verification (real HTTP requests through the full chain).
- Phase 11 is the only phase whose verification is a runtime performance measurement rather than a
  test suite — deliberately sequenced after the full request path exists (§8 requires load-testing
  the actual system, not a partial one).
