# caddy-adaptive-admission-controller — Requirements

## 1. Purpose

Port the full capability set of the existing Python AAC (`adaptive-admission-controller`,
FastAPI/Starlette reverse-proxy admission control in front of arquivo.pt's backends) into a native
**Caddy module**, so it runs as goroutines inside the same `caddy` process that will front
arquivo.pt after the Apache→Caddy migration — instead of as a separate uvicorn process fronted by
Apache/Caddy over HTTP.

This is a **from-scratch reimplementation**, not a wrapper around the Python process. The project
name is **`caddy-adaptive-admission-controller`** — "adaptive" is load-bearing: p95-latency-driven,
self-tuning concurrency control (`AdaptiveController`) is the system's core differentiator over a
plain rate limiter, and the name must not lose that word.

## 2. Hard constraint: no bespoke config file

The Python system reads a standalone `config/backends.yaml` (loaded via `AAC_CONFIG_PATH`). **The
Caddy port must not do this.** All configuration — backend definitions, upstreams, concurrency
controllers, scoring rules, ingress trust settings, GeoIP paths, auth/JWKS settings — must be
expressible natively inside Caddy's own per-site/per-host configuration, via:

- a **Caddyfile directive** (e.g. `adaptive_admission { ... }`) usable inside a `site` block, and
- the equivalent **JSON config** node under `apps.http.servers.<name>.routes[].handle`.

No `AAC_*` environment variables, no separate YAML file, no side-channel config path. Anything the
Python system currently reads from `backends.yaml` or `AAC_`-prefixed env vars must become either
directive arguments/sub-blocks or, where genuinely global rather than per-site (see §7), Caddy
"app"-level JSON config surfaced through its own directive/global option.

## 3. Architecture shape

### 3.1 Two module roles

- **HTTP handler module** (`http.handlers.adaptive_admission`) — implements
  `caddyhttp.MiddlewareHandler.ServeHTTP(w, r, next)`. One instance is configured per Caddyfile
  `adaptive_admission` block / per JSON route `handle` entry, corresponding 1:1 to one of today's
  Python "backends" (a path-prefix-matched upstream group). Caddy's own `matcher` blocks
  (`path_prefix.py:_prefix_matches` port) replace the Python `match.path_prefix` field entirely —
  route matching is Caddy's job, not this module's.
- **App module** (`caddy.App`, namespace `adaptive_admission`) — holds state that must be shared
  *across* backend instances within the same Caddy process: the GeoIP DB readers (opened once, not
  once per backend), the JWKS verifier/refresh loop (one per configured issuer, not per backend),
  and — if scoring penalties must be shared across multiple `caddy` processes on the same host in
  future — a pluggable penalty-store backend. Referenced by handler instances via Caddy's
  `caddy.App`/module-loading mechanism (`ctx.App("adaptive_admission")`), not by a config file path.

### 3.2 In-process shared state replaces Redis (single-instance target)

The Python system's `RedisPenaltyStore` exists because `uvicorn --workers N` runs N *separate
processes* with no shared memory — this was the whole reason the Python multi-process scaling plan
was abandoned in favor of this rewrite. A single `caddy` process has no such barrier: all
goroutines share memory directly. For the primary target deployment (one Caddy process per host),
penalty counters, capacity-controller state (`_in_flight`, latency window), and load-balancer state
(sticky map, health map) should be plain in-process data structures guarded by `sync.Mutex` /
`sync.RWMutex`, matching `asyncio.Lock`/`asyncio.Condition` 1:1 with `sync.Mutex`/`sync.Cond`.

**Open question carried into design, not resolved by this doc:** if arquivo.pt ever runs multiple
Caddy instances behind a shared front (matching the Python system's existing "Multi-instance load
balancing scope limits" documented gap), the penalty store and sticky-session state would need an
external backend again (Redis or otherwise) via the same `PenaltyStore`-style interface abstraction
used today — but this is explicitly **out of scope for v1**, exactly as it was cut from the Python
system's scope for the same reason.

### 3.3 Config reload semantics to design around

Per Caddy's module lifecycle: on every config change (`caddy reload` / admin API `/load`), Caddy
provisions **new** module instances before tearing down the old ones — instances can briefly
overlap, and there is no guarantee of "hand off state from old to new instance" for free. Anything
this plugin holds in memory that must survive a reload (in particular: capacity-controller
in-flight counts and adaptive limits, load-balancer health/sticky state, GeoIP/JWKS caches) needs a
deliberate carry-over strategy — e.g. `caddy.UsagePool` keyed by backend name, so a reload reuses
the existing state object instead of resetting counters/limits to their configured defaults on
every `caddy reload`. This must be an explicit design decision, not an accidental side effect of
whatever `Provision()` happens to do — silently resetting adaptive concurrency limits to
`initial_concurrency` on every unrelated config reload elsewhere on the same Caddy instance would be
a regression.

## 4. Functional requirements ported from the Python system

Each item below names the Python source of truth and what it must become in Caddy-native terms.

### 4.1 Ingress / trusted proxy (`app/ingress.py`)

- Reject (403) any request whose peer is not in a configured trusted-proxy allowlist, **except**
  `/healthz`, `/readyz`, `/metrics`-equivalent paths.
- Resolve real client IP from `X-Forwarded-For` at a configurable number of hops from the right,
  falling back to the peer IP.
- In Caddy terms: this overlaps with Caddy's built-in `trusted_proxies` global option and
  `client_ip` placeholder machinery — **prefer reusing Caddy's own trusted-proxy resolution instead
  of reimplementing it**, and have this module consume `{http.request.remote.host}` /ish
  placeholders rather than parsing XFF itself, unless Caddy's built-in hop-counting semantics don't
  match FR-010a's "exactly N hops from the right" requirement precisely (needs verification during
  design, not assumed here).

### 4.2 Classification (`app/classifier.py`, `app/geoip.py`, `app/auth.py`)

- Per-request context: source IP, `/24` (IPv4) or configurable `/48`/`/56` (IPv6) subnet, ASN,
  country (via MaxMind `.mmdb` city+ASN DBs, each independently fail-open if unopenable), user
  class + user ID (via optional JWT bearer verification against a JWKS endpoint, RS256, with
  periodic background refresh that fails open — keeps stale/empty key set rather than erroring).
  User classes: `anonymous, researcher, service_account, internal, unknown` (identity-only —
  behavior-based signals live entirely in scoring, never folded into user class).
- GeoIP DB paths and JWKS issuer/audience/refresh-interval are per-deployment settings — expressed
  as Caddyfile sub-directives / JSON fields on the app module (shared across backends) rather than
  repeated per backend block, since one process opens the DB/JWKS config once.

### 4.3 Scoring / penalties (`app/scoring.py`, `app/config.py`'s `ScoringConfig`)

- A `final = clamp(base_score[user_class] - penalty, min_score, max_score)` per request, where
  `penalty` sums step-function penalties (soft/hard thresholds → soft/hard penalty amounts) over a
  rolling window, independently per dimension: `ip, net24, net6, asn, country, user`.
- Exempt countries: still track/increment counters (observability) but never contribute their
  penalty to the final score.
- Backend-level overrides that deep-merge onto global defaults per dimension (mirroring
  `resolve_scoring_config`'s override-merge, including its aliasing-safety concern — Go structs are
  value types by default so this class of bug is less likely, but any shared default maps/slices
  must still be deep-copied before per-backend mutation).
- Must fail open (fall back to unpenalized base score) if the counter backend is unavailable, never
  5xx the request.
- Config surface: exempt countries, IPv6 prefix length (48/56), base scores per user class, score
  clamp min/max, and default + per-backend-override penalty windows (window seconds, soft/hard
  threshold, soft/hard penalty) — all expressible as nested Caddyfile blocks/JSON per backend.

### 4.4 Capacity control (`app/capacity.py`)

- Two controller kinds, selected per backend:
  - **Fixed**: static concurrency limit.
  - **Adaptive**: `min/initial/max concurrency`, `target_p95_ms`, `timeout_rate_threshold`,
    `error_rate_threshold`; a periodic (default 30s) adjustment loop that shrinks the limit on
    elevated timeout rate (×0.60, 60s cooldown), elevated error rate (×0.75, 30s cooldown), p95 >
    2×target (×0.70, 30s cooldown), p95 > target (×0.85, no stated cooldown difference from the
    p95>2x branch — port exact thresholds/multipliers as-is), grows on p95 < 0.5×target (×1.05, no
    cooldown), and wakes blocked waiters immediately whenever the limit is raised.
- `acquire(cost)` blocks (never returns a false/reject signal) until capacity is available;
  `release(cost, latency_ms, status_code, timed_out)` records outcome and unblocks exactly enough
  waiters for the freed capacity (the already-fixed wake-storm bug in the Python system —
  `notify(cost)` not `notify_all()` — must be designed in correctly from the start in Go, i.e. use
  `sync.Cond.Signal()` in a loop bounded by freed cost, or an equivalent bounded-wake primitive, not
  `Broadcast()` on every release).
- `cost` is uniform (`1`) for v1, matching the Python system's decision log — do not build
  per-request variable cost unless explicitly requested later.

### 4.5 Scheduling / priority queue (`app/scheduler.py`, `app/errors.py`)

- Backend-scoped bounded priority queue, ordered by score (higher score served first) then arrival
  time (FIFO within same score).
- Reject with 429 if the queue is full (`queue_max_size`) or if Little's-law-style projected wait
  (`queue_depth * mean_latency_ms / concurrency_limit`) already exceeds `queue_timeout_seconds` —
  distinguish these two rejection reasons in logs/metrics exactly as the Python system does
  (`queue_full` vs `queue_wait_exceeded`).
- Worker acquires capacity **before** popping the queue head, so admission always reflects current
  priority order, not queue-time snapshot order (only correct because cost is uniformly 1 — call
  this out as a load-bearing assumption in code comments, same as the Python source does).

### 4.6 Load balancing (`app/load_balancer.py`)

- Per-backend least-in-flight instance selection across primary `upstreams`, falling back to
  `backup_upstreams` if all primaries are unhealthy, and failing open to the full instance set if
  everything is unhealthy (never hard-fail a request due to LB state).
- Optional sticky sessions keyed by client IP, TTL-expiring, with **fair-share eviction**: evict a
  sticky pin only when the pinned instance's load has reached `ceil(capacity_hint / candidate
  count)` *and* a strictly-less-loaded alternative exists.
- Background health checks: periodic raw TCP probe of down instances, mark recovered/still-down,
  with matching log events (`upstream_instance_marked_down` / `upstream_instance_recovered`).
- Known Python-side scope cut carried forward as an explicit non-goal for v1: `current_limit()` /
  capacity-controller decisions are backend-scoped, not instance-health-aware — an unhealthy
  instance being routed around doesn't shrink the backend's overall concurrency limit. Revisit only
  if explicitly requested.
- **Caddy overlap:** Caddy's built-in `reverse_proxy` already has upstream selection, health checks,
  and (via `lb_policy`) various balancing policies. Decide during design whether to (a) reuse
  `reverse_proxy`'s upstream pool/health-check machinery and only supply a custom `lb_policy` module
  plugging in least-in-flight + sticky-by-fair-share, or (b) keep this fully custom to preserve the
  Python system's exact sticky/fair-share semantics. Reusing Caddy's `reverse_proxy` upstream +
  health-check code is very likely less risky than reimplementing TCP health probing from scratch —
  flagged here as the default recommendation, not yet decided.

### 4.7 Dispatch / reverse proxy (`app/dispatcher.py`)

- Preserve original request path/query when proxying to the selected instance (`path_prefix` used
  only for backend *selection*, never rewritten into the upstream URL — "drop-in Apache ProxyPass
  replacement" behavior).
- Strip hop-by-hop headers; preserve repeated headers such as multiple `Set-Cookie` values.
- Distinguish connect failures (mark instance down, 502) from response timeouts (503,
  `reason=backend_timeout`) from generic HTTP errors (502) from successful-but-5xx upstream
  responses (still counted as "admitted", tracked separately via `backend_errors_total`-equivalent
  metric) — this exact taxonomy of outcomes must be preserved since it drives both metrics and the
  adaptive controller's error/timeout rate thresholds.
- **Caddy overlap:** this entire concern maps closely onto Caddy's own `reverse_proxy` transport/
  timeout/error-handling. Strongly prefer wrapping/composing with `reverse_proxy` rather than
  writing a parallel HTTP client stack — this is one of the biggest potential implementation-size
  reductions versus the Python system, which had to build its own httpx-based proxy layer from
  scratch. Needs design-phase verification that `reverse_proxy`'s hooks are sufficient to distinguish
  connect-vs-timeout-vs-5xx the way the adaptive controller requires.

### 4.8 Metrics (`app/metrics.py`)

- Same 14-metric surface (gauges: in-flight requests/tokens, concurrency limit, queue size,
  per-instance in-flight/healthy; counters: requests/admitted/rejected by reason, queue timeouts,
  backend errors/timeouts, adaptive limit changes, per-instance errors/connect-failures;
  histograms: backend request duration, queue wait duration, score distribution) — labeled by
  backend (and instance/class/reason where the Python version does). Caddy already ships Prometheus
  metrics support (`metrics` app/directive) — integrate as additional metrics registered against
  Caddy's existing Prometheus registry rather than standing up a second `/metrics` endpoint.

### 4.9 Structured logging (`app/observability.py`)

- One JSON log line per admission decision (`admitted`/`rejected`) carrying backend, user class,
  source IP, ASN, country, exemption flag, full score breakdown, cost, and (where applicable)
  rejection reason / queue wait ms / backend latency ms / status code. Caddy already emits
  structured (zap-based) JSON logs — emit these as structured log entries via the module's
  `ctx.Logger()` rather than a separate logging subsystem, so operators get one unified log stream
  instead of two.

### 4.10 Admin / introspection API (`app/admin.py`)

- Read-only (no hot-reload endpoints needed — Caddy's own admin API already does config reload):
  per-backend summary (controller type, current limit, mean latency, queue size, upstream/healthy
  counts), full resolved policy/scoring config, current limit, and upstream snapshot
  (url/healthy/in-flight/sticky-count/is-backup). Token-gated; fails closed (403) if no token is
  configured.
- **Caddy overlap:** Caddy already has an admin API on `localhost:2019`. Prefer exposing this
  introspection data either as a Caddy admin API route extension (if the module system allows
  registering admin endpoints) or as a small set of app-level JSON fields readable via
  `GET /config/...`, rather than standing up a second bearer-token-gated HTTP surface — needs
  design-phase verification of whether Caddy modules can register admin API routes.

## 5. Config schema sketch (Caddyfile + JSON)

Illustrative only — exact field names/nesting to be finalized at design time.

**Caddyfile**, inside a `site` block, one directive per backend:

```caddyfile
handle_path /textsearch* {
    adaptive_admission {
        controller adaptive {
            min_concurrency    10
            initial_concurrency 40
            max_concurrency    200
            target_p95_ms      800
            timeout_rate_threshold 0.05
            error_rate_threshold   0.05
        }

        upstream http://page-search-api-1:8080
        upstream http://page-search-api-2:8080
        backup_upstream http://page-search-api-standby:8080

        connect_timeout   5s
        backend_timeout   30s
        queue_max_size    500
        queue_timeout     10s
        sticky_sessions   on
        sticky_ttl        5m

        scoring {
            base_score researcher 100
            base_score anonymous  60
            penalty ip window=60s soft=20:-10 hard=100:-40
            # ... per-dimension overrides
        }
    }
    reverse_proxy ...  # or adaptive_admission composes with reverse_proxy directly
}
```

Global, process-wide settings (GeoIP DB paths, JWKS issuer/JWKS URL/audience, exempt countries,
default penalty windows, IPv6 prefix length) live once at the top of the Caddyfile via the app
module's global option block, e.g.:

```caddyfile
{
    adaptive_admission_global {
        geoip_city_db /etc/caddy/GeoLite2-City.mmdb
        geoip_asn_db  /etc/caddy/GeoLite2-ASN.mmdb
        auth_issuer   https://sso.arquivo.pt/realms/arquivo
        auth_jwks_url https://sso.arquivo.pt/realms/arquivo/protocol/openid-connect/certs
        exempt_country PT
        ipv6_prefix_length 56
    }
}
```

The equivalent JSON: the per-backend block becomes the handler's config object under
`apps.http.servers.<name>.routes[].handle[]` (`"handler": "adaptive_admission", ...fields}`); the
global block becomes `apps.adaptive_admission.{geoip, auth, scoring_defaults, ...}`, loaded as an
app module and referenced by the handler modules via `ctx.App("adaptive_admission")`.

## 6. Non-goals for v1 (carried forward from the Python system's documented scope cuts)

- No dry-run/observe-only mode (unless requested later).
- No per-request variable cost — cost is uniformly 1.
- No cross-instance shared state (Redis or otherwise) — single Caddy process per host is the target
  deployment; multi-instance clustering is out of scope, same as it was cut from the Python system.
- No coupling to the separate Apache→Caddy web-server migration project — this plugin is usable
  standalone in any Caddy config once built; sequencing of the two migrations is a deployment
  decision, not a design dependency.

## 7. Open questions to resolve during design (not decided by this document)

1. Does Caddy's built-in trusted-proxy/`client_ip` placeholder machinery satisfy FR-010a's
   exact-hop-count XFF resolution, or does this module need its own?
2. Reuse `reverse_proxy` (upstreams, health checks, `lb_policy`) vs. fully custom load
   balancer/dispatcher — recommended default is to reuse and extend, see §4.6/§4.7.
3. Can this module register its own admin API routes, or should introspection ride on
   `GET /config/...` against app-level state instead of a bespoke `/admin/*` surface?
4. Exact `caddy.UsagePool` (or equivalent) strategy for carrying capacity-controller/load-balancer
   state across a config reload without resetting it to configured defaults every time (§3.3).
5. Whether GeoIP/JWKS state belongs on the app module (shared) or could reasonably be per-handler —
   current recommendation is app-level (§3.1) to avoid redundant DB opens/JWKS fetches per backend.
