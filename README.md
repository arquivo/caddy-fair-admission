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

## Documentation

- [`docs/configuration.md`](docs/configuration.md) — the full Caddyfile reference for both
  modules: every directive, the `scoring { }` grammar, what EWMA/soft/hard penalties mean, user
  classes, exempt countries, the adaptive controller's multiplier/cooldown table, queue semantics,
  and the `fairness`→`adaptive_admission` score hand-off.
- [`docs/scenarios.md`](docs/scenarios.md) — two worked examples: a distributed low-and-slow
  crawler (spread across enough source IPs that per-IP rate limiting is blind to it) vs. a normal
  browsing session, walked through all 6 scoring dimensions.
- [`docs/monitoring.md`](docs/monitoring.md) — every admin API endpoint and every Prometheus
  metric, with example input/output, plus the structured admission-decision log line's fields.
- [`docs/REQUIREMENTS.md`](docs/REQUIREMENTS.md) — the full functional spec.
- [`docs/implementation_plan.md`](docs/implementation_plan.md) — the phase-by-phase build log.
- [`docs/LOAD_TEST_REPORT.md`](docs/LOAD_TEST_REPORT.md) — a captured concurrency-sweep run against
  the full chain (see [Load testing](#load-testing) below).

## Building

Build a `caddy` binary with both modules via [xcaddy](https://github.com/caddyserver/xcaddy):

```sh
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
xcaddy build --with github.com/arquivo/caddy-adaptive-admission-controller=.
```

Or build a container image with the [`Dockerfile`](Dockerfile), which does the same `xcaddy build`
inside Caddy's own official builder image and copies the result into Caddy's own runtime image:

```sh
docker build -t caddy-fair-admission .
docker run --rm -p 8080:8080 -p 2019:2019 \
  -v "$(pwd)/examples/fairness-adaptive-admission.Caddyfile:/etc/caddy/Caddyfile:ro" \
  caddy-fair-admission
```

Or pull the image already published to
[Docker Hub](https://hub.docker.com/r/arquivo/caddy-adaptive-admission-controller) instead of
building it yourself:

```sh
docker pull arquivo/caddy-adaptive-admission-controller:latest
docker run --rm -p 8080:8080 -p 2019:2019 \
  -v "$(pwd)/examples/fairness-adaptive-admission.Caddyfile:/etc/caddy/Caddyfile:ro" \
  arquivo/caddy-adaptive-admission-controller:latest
```

CI (`.github/workflows/build.yml`) runs `go vet`, `go test ./...`, and this same `xcaddy build` on
every push/PR to `main`. Releases are cut automatically, not by hand: once `Build` passes on
`main`, [semantic-release](https://github.com/semantic-release/semantic-release)
(`.github/workflows/semantic-release.yml`, using
[Arquivo's shared reusable workflow](https://github.com/arquivo/.github)) inspects the
[Conventional Commits](https://www.conventionalcommits.org/) merged since the last release —
enforced on PRs by `commitlint.yml` — and, if any warrant a release, bumps the version, updates
`CHANGELOG.md`, and publishes a GitHub Release with a `vX.Y.Z` tag. GitHub doesn't let a push
made with a workflow's own token trigger other workflows, so `semantic-release.yml` itself
detects whether a new tag actually appeared and, if so, calls `.github/workflows/release.yml`
(cross-compiles and attaches binary artifacts for linux/darwin/windows to the release) and
`.github/workflows/docker-publish.yml` (builds and pushes the Docker image, tagged with the
branch, semver version, and commit SHA as appropriate) directly, in the same run.

## Usage

See [`examples/`](examples/) for runnable Caddyfiles, from minimal to exhaustive:

- [`scaffold.Caddyfile`](examples/scaffold.Caddyfile) — a minimal sanity-check config with no real
  backend (`respond` instead of `reverse_proxy`); proves the two modules load and chain correctly.
- [`fairness-adaptive-admission.Caddyfile`](examples/fairness-adaptive-admission.Caddyfile) — the
  full chain (`fairness` → `adaptive_admission` → `reverse_proxy`) against real backends, with
  active/passive health checks and load-balancer stickiness, shown both as bare top-level
  directives and inside an explicit `route {}` block.
- [`fairness-full.Caddyfile`](examples/fairness-full.Caddyfile) — every `fairness` directive and
  every `scoring { }` sub-directive set explicitly, one per commented line.
- [`adaptive-admission-full.Caddyfile`](examples/adaptive-admission-full.Caddyfile) — both
  controller kinds (`fixed` and `adaptive`) with every sub-field set explicitly, one per commented
  line.

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

See [`docs/configuration.md`](docs/configuration.md) for what every field above means and its
default.

### Admin API and metrics

Both modules expose introspection endpoints on Caddy's admin API (`GET /fairness/status`,
`GET /adaptive_admission/status`) and register 12 Prometheus metrics total (1 `fairness` + 11
`adaptive_admission`) on Caddy's own metrics registry, exposed via Caddy's built-in `metrics`
directive. `adaptive_admission` also emits one structured JSON log line per admission decision,
folding in `fairness`'s classification/score fields.

Full endpoint shapes, metric names/types/labels, and example input/output for all of the above are
in [`docs/monitoring.md`](docs/monitoring.md).

## Developing this module

Prerequisites: the Go version pinned in [`go.mod`](go.mod).

```sh
go build ./...   # compile everything
go vet ./...     # static checks (also run in CI)
go test ./...    # unit + integration tests (also run in CI)
```

To exercise a real running instance rather than just the test suite, build with `xcaddy` (see
[Building](#building) above) and run it against one of the [`examples/`](examples/) Caddyfiles:

```sh
./caddy run --config examples/fairness-adaptive-admission.Caddyfile --adapter caddyfile
```

You can then hit the admin endpoints (`curl localhost:2019/fairness/status`) or scrape
`localhost:2019/metrics` against that live instance — see [`docs/monitoring.md`](docs/monitoring.md)
for what to expect back.

### Load testing

`/loadtest` is an importable concurrency ramp/sweep engine (ramp-up, hold-open, multi-endpoint),
measuring p50/p95/p99 latency and throughput vs. offered concurrency — see
[`docs/REQUIREMENTS.md` §8](docs/REQUIREMENTS.md) for the rationale (the original Python system's
throughput inverted between 50 and 250 concurrent requests; this exists to catch a regression of
that shape in the Go port). `/cmd/loadtest` is a CLI wrapper around it, for pointing at any already-
running instance:

```sh
go run ./cmd/loadtest -url http://127.0.0.1:8080 -levels 50,100,150,200,250
```

[`docs/LOAD_TEST_REPORT.md`](docs/LOAD_TEST_REPORT.md) is a captured run against the full chain
(an in-process instance, not `xcaddy`/`cmd/loadtest`), showing throughput scaling from ~2.9k to
~10.9k req/s across that same range with no inversion. Re-run it and regenerate that report with:

```sh
RUN_LOADTEST_E2E=1 go test . -run TestLoadTest_FullChain_ConcurrencySweep -v
```

This test is opt-in (skipped by default, and not run in CI) since it's a runtime performance
measurement — several concurrency levels, each held open for seconds — rather than a correctness
check.

## Contributing

This repository enforces [Conventional Commits](https://www.conventionalcommits.org/) on every
pull request via commitlint (see `.github/workflows/commitlint.yml`). Format commit messages as:

```
<type>(<optional scope>): <description>
```

Common types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`.
