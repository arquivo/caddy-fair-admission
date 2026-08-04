# caddy-adaptive-admission-controller

A native [Caddy](https://caddyserver.com/) module implementing adaptive, p95-latency-driven
admission control (concurrency limiting, EWMA-based scoring/penalties, priority queueing, and
least-in-flight load balancing) in front of arquivo.pt's backends.

This is a from-scratch Go port of an existing Python system
(`adaptive-admission-controller`, FastAPI/Starlette), designed to run as goroutines inside the
same `caddy` process that fronts arquivo.pt — replacing a standalone uvicorn process — once the
Apache→Caddy web-server migration lands.

## Status

Implemented and load-tested. Two independently importable Caddy modules:

- `fairness` — request classification (IP/subnet/ASN/country/user class) and EWMA-based fairness
  scoring/penalties (`http.handlers.fairness`, `fairness` app namespace).
- `adaptive_admission` — capacity control (fixed or adaptive, p95-latency-driven) and priority
  queueing ahead of `reverse_proxy` (`http.handlers.adaptive_admission`, `adaptive_admission` app
  namespace).

See [REQUIREMENTS.md](REQUIREMENTS.md) for the full functional spec and
[implementation_plan.md](implementation_plan.md) for the phase-by-phase build log.

## Building

Build a `caddy` binary with both modules via [xcaddy](https://github.com/caddyserver/xcaddy):

```sh
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
xcaddy build --with github.com/arquivo/caddy-adaptive-admission-controller=.
```

CI (`.github/workflows/build.yml`) runs `go vet`, `go test ./...`, and this same `xcaddy build` on
every push/PR to `main`. Tagged releases (`.github/workflows/release.yml`) build and publish binary
artifacts.

## Usage

See [`examples/`](examples/) for runnable Caddyfiles:

- `fairness-adaptive-admission.Caddyfile` — the full chain (`fairness` → `adaptive_admission` →
  `reverse_proxy`) against real backends, with active/passive health checks and load-balancer
  stickiness, shown both as bare top-level directives and inside an explicit `route {}` block.
- `scaffold.Caddyfile` — a minimal sanity-check config with no backend.

Minimal example:

```caddyfile
:8080 {
	fairness {
		auth_jwks_url https://idp.example.com/.well-known/jwks.json
	}
	adaptive_admission {
		controller adaptive {
			min_concurrency  10
			max_concurrency  200
			target_p95       800ms
		}
		queue_max_size 500
		queue_timeout  10s
	}
	reverse_proxy backend-1:8080 backend-2:8080
}
```

### Admin API

Both modules expose introspection endpoints on Caddy's admin API (default `localhost:2019`):

- `GET /adaptive_admission/status` — per-backend controller kind/limit/in-flight/queue depth.
- `GET /fairness/status` — per-backend resolved scoring config and EWMA entry counts, plus shared
  GeoIP/JWKS resource health.

### Metrics and logging

14 Prometheus metrics are registered on Caddy's own metrics registry (exposed via Caddy's
`metrics` directive, no separate `/metrics` server), and `adaptive_admission` emits one structured
JSON log line per admission decision, folding in `fairness`'s classification/score fields.

## Load testing

`/loadtest` is an importable concurrency ramp/sweep engine (ramp-up, hold-open, multi-endpoint),
measuring p50/p95/p99 latency and throughput vs. offered concurrency — see
[REQUIREMENTS.md §8](REQUIREMENTS.md) for the rationale (the original Python system's throughput
inverted between 50 and 250 concurrent requests; this exists to catch a regression of that shape in
the Go port). `/cmd/loadtest` is a CLI wrapper around it:

```sh
go run ./cmd/loadtest -url http://127.0.0.1:8080 -levels 50,100,150,200,250
```

[`LOAD_TEST_REPORT.md`](LOAD_TEST_REPORT.md) is a captured run against the full chain, showing
throughput scaling from ~2.9k to ~10.9k req/s across that same range with no inversion. Re-run it
against a live instance with:

```sh
RUN_LOADTEST_E2E=1 go test . -run TestLoadTest_FullChain_ConcurrencySweep -v
```

## Contributing

This repository enforces [Conventional Commits](https://www.conventionalcommits.org/) on every
pull request via commitlint (see `.github/workflows/commitlint.yml`). Format commit messages as:

```
<type>(<optional scope>): <description>
```

Common types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`.
