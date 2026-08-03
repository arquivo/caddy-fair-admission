# caddy-adaptive-admission-controller — Requirements

## 1. Purpose

Port the full capability set of the existing Python AAC (`adaptive-admission-controller`,
FastAPI/Starlette reverse-proxy admission control in front of arquivo.pt's backends) into native
**Caddy modules**, so it runs as goroutines inside the same `caddy` process that will front
arquivo.pt after the Apache→Caddy migration — instead of as a separate uvicorn process fronted by
Apache/Caddy over HTTP. This is split into two composable modules within one project — `fairness`
and `adaptive_admission` (§3.1) — chained together in a Caddy route, not one monolithic handler.

This is a **from-scratch reimplementation**, not a wrapper around the Python process. The project
name is **`caddy-adaptive-admission-controller`** — "adaptive" is load-bearing: p95-latency-driven,
self-tuning concurrency control (`AdaptiveController`) is the system's core differentiator over a
plain rate limiter, and the name must not lose that word.

## 2. Hard constraint: no bespoke config file

The Python system reads a standalone `config/backends.yaml` (loaded via `AAC_CONFIG_PATH`). **The
Caddy port must not do this.** All configuration — backend definitions, upstreams, concurrency
controllers, scoring rules, ingress trust settings, GeoIP paths, auth/JWKS settings — must be
expressible natively inside Caddy's own per-site/per-host configuration, via:

- **Caddyfile directives** (`fairness { ... }` and `adaptive_admission { ... }`, chained together
  in the same route — see §3.1/§5) usable inside a `site` block, and
- the equivalent **JSON config** nodes under `apps.http.servers.<name>.routes[].handle`.

No `AAC_*` environment variables, no separate YAML file, no side-channel config path. Anything the
Python system currently reads from `backends.yaml` or `AAC_`-prefixed env vars must become either
directive arguments/sub-blocks or, where genuinely global rather than per-site (see §7), Caddy
"app"-level JSON config surfaced through its own directive/global option.

## 3. Architecture shape

### 3.1 Module roles: `fairness` and `adaptive_admission`

The system is split into two independently-loadable Caddy modules rather than one monolithic
handler — Caddy's `ServeHTTP(w, r, next)` middleware-chain model is built for exactly this kind of
composition (the same way `basicauth`, `rate_limit`, and `reverse_proxy` compose):

- **`fairness`** — `http.handlers.fairness`, backed by its own app module (`caddy.App`, namespace
  `fairness`). Covers ingress/trusted-proxy consumption and classification (§4.1-4.2) and
  EWMA-based scoring/penalties (§4.3). Its app module holds the GeoIP DB readers (opened once, not
  once per backend), the JWKS verifier/refresh loop (one per configured issuer), and the
  per-dimension EWMA scoring maps (§3.2). On `ServeHTTP`, it computes the request's classification
  and score, writes them onto the request via `caddyhttp.SetVar` (Caddy's standard mechanism for one
  handler to pass data to later handlers in the same chain — this also exposes the score as a Caddy
  placeholder, e.g. `{vars.fairness_score}`, usable for free in logging/matchers elsewhere in the
  Caddyfile), then calls `next.ServeHTTP()`.
- **`adaptive_admission`** — `http.handlers.adaptive_admission`, backed by its own app module
  (`caddy.App`, namespace `adaptive_admission`). Covers capacity control (§4.4), the priority
  queue/scheduler (§4.5), load balancing (§4.6), and dispatch (§4.7). Its app module holds
  capacity-controller state (in-flight counts, latency window, adaptive limit) and load-balancer
  state (sticky map, health map) per backend. On `ServeHTTP`, it reads the score `fairness` set via
  `caddyhttp.GetVar` — defaulting to a neutral/unpenalized score and proceeding fail-open (§4.3) if
  `fairness` wasn't chained ahead of it at all, exactly as it already must if `fairness`'s own
  counters are merely down — enqueues by that score, waits for capacity, then dispatches.

Both are configured per Caddyfile block / per JSON route `handle` entry, corresponding 1:1 to one
of today's Python "backends" (a path-prefix-matched upstream group); Caddy's own `matcher` blocks
(`path_prefix.py:_prefix_matches` port) replace the Python `match.path_prefix` field entirely — route
matching is Caddy's job, not either module's.

**Ordering is load-bearing and not automatic.** `fairness` must run before `adaptive_admission` in
the chain so a score exists to prioritize by. Because these are two independently-registered
third-party directives, Caddy's built-in directive order has no opinion on their relative sequence
— this must be handled by either registering an explicit `httpcaddyfile.RegisterOrder` position for
both, or documenting that operators wrap them in an explicit `route { fairness; adaptive_admission;
reverse_proxy }` block (Caddy's own recommended pattern for third-party directive ordering); see the
open question in §7.

**There is no dedicated global-options directive for either module** (see §5) — each block declares
its own settings (GeoIP/JWKS on `fairness` blocks, capacity/LB tuning on `adaptive_admission`
blocks), typically shared across blocks via Caddy's native `import` snippet mechanism rather than a
bespoke global block, and each app module's `Provision()` dedupes its own expensive shared resources
by keying on their identity (a GeoIP DB reader keyed by file path, a JWKS verifier/refresh loop
keyed by issuer URL) rather than requiring the settings to be written down in only one place in the
Caddyfile.

### 3.2 In-process shared state (in-memory only, single-instance target)

The Python system's `RedisPenaltyStore` exists only because `uvicorn --workers N` runs N *separate
processes* with no shared memory — this was the whole reason the Python multi-process scaling plan
was abandoned in favor of this rewrite. A single `caddy` process has no such barrier: all goroutines
share memory directly, so this port **drops the external-store abstraction entirely** rather than
reimplementing a `PenaltyStore`-style interface "in case it's needed later." Penalty/EWMA counters
live in the `fairness` app module's state; capacity-controller state (`_in_flight`, latency window)
and load-balancer state (sticky map, health map) live in the `adaptive_admission` app module's state
(§3.1). All of it is plain in-process data structures guarded by `sync.Mutex`/`sync.RWMutex`,
matching `asyncio.Lock`/`asyncio.Condition` 1:1 with `sync.Mutex`/`sync.Cond`.

**Per-entity scoring state (held by the `fairness` app module) is aggregated statistics, not raw
request logs.** Storing individual request timestamps per IP would be memory-prohibitive at
arquivo.pt's scale. Each tracked entity (IP, `/24`/`/48`/`/56`, ASN) instead holds one small
fixed-size struct:

```go
type ClientStats struct {
    LastSeen time.Time
    EWMARPS  float64
    Inflight int
}
```

kept in one `map[string]*ClientStats` per dimension (IP, `/24`(or `/48`/`/56`), ASN), guarded by a
mutex — sharded mutexes or `sync.Map` only if contention profiling later shows plain locking is a
bottleneck. See §4.3 for how `EWMARPS` is computed and used for penalty thresholds. At arquivo.pt's
expected cardinality (order 10^5–10^6 distinct active entities), this is single-digit-to-low-hundreds
of MB — not a scale that justifies an external store.

**Garbage collection:** a background ticker (every ~1 minute, configurable) sweeps each map and
deletes entries where `now.Sub(LastSeen) > idle_ttl` (default e.g. 10 minutes), so memory is bounded
by *recently active* entities rather than all-time-seen ones.

**Multi-instance clustering is explicitly out of scope for v1** (unchanged from the Python system's
own documented "Multi-instance load balancing scope limits" gap, see also §6): if arquivo.pt ever
runs multiple Caddy instances behind a shared front, each instance would only see a fraction of the
traffic per entity, and scoring/sticky state would need to be reconciled across instances somehow —
solving that (via Redis or any other external store) is deliberately **not** designed in
speculatively here. Revisit only if multi-instance actually becomes a deployment requirement.

### 3.3 Config reload semantics to design around

Per Caddy's module lifecycle: on every config change (`caddy reload` / admin API `/load`), Caddy
provisions **new** module instances before tearing down the old ones — instances can briefly
overlap, and there is no guarantee of "hand off state from old to new instance" for free. Both app
modules hold state that must survive a reload — `adaptive_admission`'s capacity-controller in-flight
counts/adaptive limits and load-balancer health/sticky state, and `fairness`'s GeoIP/JWKS caches and
per-entity EWMA scoring maps (§3.2/§4.3) — and each needs its own deliberate carry-over strategy,
e.g. `caddy.UsagePool` keyed by backend name, so a reload reuses the existing state object instead
of resetting counters/limits to their configured defaults on every `caddy reload`. This must be an
explicit design decision in both app modules, not an accidental side effect of whatever
`Provision()` happens to do — silently resetting adaptive concurrency limits to `initial_concurrency`
on every unrelated config reload elsewhere on the same Caddy instance would be a regression.

### 3.4 Build & distribution

Caddy modules are compiled in, not dynamically loaded, so this project must own producing a
buildable/distributable `caddy` binary rather than assuming operators will figure that out
themselves — but it must not *only* be consumable as a private prebuilt binary either. Both of the
following are required:

- **This repo builds and publishes its own `caddy` binary.** CI uses
  [`xcaddy`](https://github.com/caddyserver/xcaddy) (`xcaddy build --with
  github.com/arquivo/caddy-adaptive-admission-controller=.`) to produce a ready-to-run binary (and,
  if useful for arquivo.pt's deployment, a container image wrapping it) as a release artifact —
  the primary way arquivo.pt itself deploys this is a binary this project ships, not a Caddyfile
  someone else has to `xcaddy build` by hand.
- **Both modules stay independently importable.** The Go packages implementing
  `http.handlers.fairness`/`fairness` app module and `http.handlers.adaptive_admission`/
  `adaptive_admission` app module live in one repo but must remain normal, standalone Go packages
  (correct `go.mod` path, no hard dependency on anything specific to this repo's own release
  pipeline) — importable either together or independently, since §3.1 already requires
  `adaptive_admission` to work without `fairness` chained ahead of it. Any third party can compose
  either or both into their *own* custom Caddy build the standard way: `xcaddy build --with
  github.com/arquivo/caddy-adaptive-admission-controller` alongside whatever other modules they
  need. Do not assume this project's own prebuilt binary is the only supported way to consume it.

## 4. Functional requirements ported from the Python system

Each item below names the Python source of truth and what it must become in Caddy-native terms.
§4.1-4.3 belong to the `fairness` module, §4.4-4.7 to `adaptive_admission` (§3.1); §4.8-4.10 span
both.

### 4.1 Ingress / trusted proxy (`app/ingress.py`) — `fairness`

- **No custom trusted-proxy/XFF logic in this module at all.** Caddy's own `trusted_proxies` +
  `trusted_proxies_strict` global options already resolve a real client IP from `X-Forwarded-For`
  behind a trusted boundary, and a plain `not remote_ip <ranges>` matcher already rejects untrusted
  peers (with `/healthz`/`/readyz`/`/metrics`-equivalent paths excluded via a path matcher) — both
  are standard Caddyfile config, not something `fairness` needs to implement or expose settings for.
- `fairness` simply consumes Caddy's already-resolved `{client_ip}` placeholder.

### 4.2 Classification (`app/classifier.py`, `app/geoip.py`, `app/auth.py`) — `fairness`

- Per-request context: source IP, `/24` (IPv4) or configurable `/48`/`/56` (IPv6) subnet, ASN,
  country (via MaxMind `.mmdb` city+ASN DBs, each independently fail-open if unopenable), user
  class + user ID (via optional JWT bearer verification against a JWKS endpoint, RS256, with
  periodic background refresh that fails open — keeps stale/empty key set rather than erroring).
  User classes: `anonymous, researcher, service_account, internal, unknown` (identity-only —
  behavior-based signals live entirely in scoring, never folded into user class).
- GeoIP DB paths and JWKS issuer/audience/refresh-interval are declared per `fairness` block
  (typically shared across blocks via Caddy's native `import`, §5) — the `fairness` app module
  dedupes the actual DB opens/JWKS refresh loops by resource identity (§3.1) rather than requiring
  one process-wide config location.

### 4.3 Scoring / penalties (`app/scoring.py`, `app/config.py`'s `ScoringConfig`) — EWMA-based, `fairness`

- A `final = clamp(base_score[user_class] - penalty, min_score, max_score)` per request, where
  `penalty` sums step-function penalties (soft/hard thresholds → soft/hard penalty amounts),
  independently per dimension: `ip, net24, net6, asn, country, user`.
- **Design refinement vs. the Python source:** the Python system's per-dimension counters are plain
  rolling-window request counts (`window_seconds`). This port instead drives thresholds off an
  **EWMA (exponentially weighted moving average) of requests/sec**, per dimension — a technique
  widely used in load balancers/proxies (Envoy, HAProxy, TCP congestion control) to avoid reacting
  to momentary spikes while still accumulating penalty against sustained load. A normal user's
  brief 20-request burst decays back out quickly; a crawler holding ~20 rps for minutes, or an ASN
  spiking to thousands of rps, progressively accumulates penalty. Updated on a fixed tick (default
  1s) per tracked entity:
  ```
  ewma(t) = alpha * requests_in_last_tick + (1 - alpha) * ewma(t-1)
  ```
  `alpha` (default e.g. `0.2`) is a per-dimension-configurable smoothing factor — lower alpha reacts
  more slowly/smoothly, higher alpha weights the most recent tick more heavily. This **replaces**
  the Python system's `window_seconds` rolling-window semantics for this port; window-based counting
  is not carried forward.
- Thresholds (`soft`/`hard` → penalty amounts) are evaluated against each dimension's current
  `EWMARPS` value (§3.2's `ClientStats.EWMARPS`) rather than a raw window count.
- Exempt countries: still track/increment EWMA counters (observability) but never contribute their
  penalty to the final score.
- Backend-level overrides deep-merge onto global defaults per dimension (mirroring
  `resolve_scoring_config`'s override-merge, including its aliasing-safety concern — Go structs are
  value types by default so this class of bug is less likely, but any shared default maps/slices
  must still be deep-copied before per-backend mutation).
- Must fail open (fall back to unpenalized base score) if the in-memory counter state is
  unavailable/uninitialized, never 5xx the request.
- Config surface: exempt countries, IPv6 prefix length (48/56), base scores per user class, score
  clamp min/max, EWMA tick interval (default, per `fairness` block, typically shared via `import`)
  and default + per-backend-override per-dimension
  `alpha`, soft/hard threshold, soft/hard penalty, and idle-entry TTL (§3.2 GC) — all expressible as
  nested Caddyfile blocks/JSON per backend.

### 4.4 Capacity control (`app/capacity.py`) — `adaptive_admission`

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

### 4.5 Scheduling / priority queue (`app/scheduler.py`, `app/errors.py`) — `adaptive_admission`

- Backend-scoped bounded priority queue, ordered by score (higher score served first) then arrival
  time (FIFO within same score).
- Reject with 429 if the queue is full (`queue_max_size`) or if Little's-law-style projected wait
  (`queue_depth * mean_latency_ms / concurrency_limit`) already exceeds `queue_timeout_seconds` —
  distinguish these two rejection reasons in logs/metrics exactly as the Python system does
  (`queue_full` vs `queue_wait_exceeded`).
- Worker acquires capacity **before** popping the queue head, so admission always reflects current
  priority order, not queue-time snapshot order (only correct because cost is uniformly 1 — call
  this out as a load-bearing assumption in code comments, same as the Python source does).

### 4.6 Load balancing (`app/load_balancer.py`) — `adaptive_admission`

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

### 4.7 Dispatch / reverse proxy (`app/dispatcher.py`) — `adaptive_admission`

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
  Caddy's existing Prometheus registry rather than standing up a second `/metrics` endpoint. Metrics
  originating in `fairness` (score distribution) and `adaptive_admission` (everything else) both
  register against that same shared registry — the module split changes which package emits a given
  metric, not the metric surface itself.

### 4.9 Structured logging (`app/observability.py`)

- One JSON log line per admission decision (`admitted`/`rejected`) carrying backend, user class,
  source IP, ASN, country, exemption flag, full score breakdown, cost, and (where applicable)
  rejection reason / queue wait ms / backend latency ms / status code. Caddy already emits
  structured (zap-based) JSON logs — emit these as structured log entries via the module's
  `ctx.Logger()` rather than a separate logging subsystem, so operators get one unified log stream
  instead of two. Since `adaptive_admission` is the one that knows the final admitted/rejected
  outcome, it owns emitting this single log line — it reads the classification/score `fairness` set
  via `caddyhttp.GetVar` (§3.1) and folds them in as fields, so `fairness` itself never logs
  separately per request (consistent with §8's "one structured log call per admission decision").

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
  design-phase verification of whether Caddy modules can register admin API routes. Since state is
  now split across two app modules (§3.1), introspection must cover both — `fairness`'s resolved
  scoring config and GeoIP/JWKS health, and `adaptive_admission`'s capacity/load-balancer snapshot —
  whether that ends up as one combined surface or two parallel ones is part of this open question.

## 5. Config schema sketch (Caddyfile + JSON)

Illustrative only — exact field names/nesting to be finalized at design time.

**Caddyfile**, inside a `site` block: one `fairness` block and one `adaptive_admission` block per
backend, chained via an explicit `route` block for ordering (§3.1). There is no separate
`adaptive_admission_global`/`fairness_global` directive or app-level global-options block — settings
that are conceptually shared across backends (GeoIP DB paths, JWKS issuer, exempt countries, EWMA
defaults, capacity-controller tuning, etc.) are just regular fields inside each block, reused across
blocks with Caddy's own native `import` directive and named snippets (`(snippet-name) { ... }` /
`import snippet-name`) rather than a bespoke global syntax. See §3.1 for how the underlying app
modules still avoid opening the same GeoIP DB / starting a duplicate JWKS refresh loop per block:

```caddyfile
(shared_fairness_defaults) {
    geoip_city_db /etc/caddy/GeoLite2-City.mmdb
    geoip_asn_db  /etc/caddy/GeoLite2-ASN.mmdb
    auth_issuer   https://sso.arquivo.pt/realms/arquivo
    auth_jwks_url https://sso.arquivo.pt/realms/arquivo/protocol/openid-connect/certs
    exempt_country PT
    ipv6_prefix_length 56
    ewma_tick_interval 1s
    idle_entry_ttl     10m
}

handle_path /textsearch* {
    route {
        fairness {
            import shared_fairness_defaults

            scoring {
                base_score researcher 100
                base_score anonymous  60
                penalty ip alpha=0.2 soft=20:-10 hard=100:-40
                # ... per-dimension overrides
            }
        }

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
        }

        reverse_proxy ...  # or adaptive_admission composes with reverse_proxy directly
    }
}

handle_path /imagesearch* {
    route {
        fairness {
            import shared_fairness_defaults
        }
        adaptive_admission {
            # ...this block's own controller/upstream config
        }
        reverse_proxy ...
    }
}
```

The explicit `route { ... }` wrapper is what guarantees `fairness` runs before
`adaptive_admission` in the Caddyfile (see the ordering discussion in §3.1) — whether this stays
a documented requirement or gets additionally enforced via `httpcaddyfile.RegisterOrder` (so a bare,
non-`route`-wrapped ordering also works) is an open question, §7.

The equivalent JSON: each block's fully-resolved config (including whatever it imported) becomes its
own handler config object under `apps.http.servers.<name>.routes[].handle[]`
(`"handler": "fairness", ...` then `"handler": "adaptive_admission", ...`, in that order in the
`handle` array — JSON's array order *is* the execution order, so there is no ordering ambiguity on
the JSON side the way there is in Caddyfile). JSON config has no equivalent of `import` (there's
nothing to textually expand), so each route's handler objects are simply fully self-contained/
repeated, and it's each app module's keyed resource dedup (§3.1), not the config shape, that prevents
redundant GeoIP/JWKS or capacity-controller-state work when multiple routes' resolved config happens
to match. Both app modules (`fairness`, `adaptive_admission`) are loaded and referenced by their
respective handler modules via `ctx.App(...)`, exactly as in §3.1 — neither has a corresponding
Caddyfile global-options block of its own.

## 6. Non-goals for v1 (carried forward from the Python system's documented scope cuts)

- No dry-run/observe-only mode (unless requested later).
- No per-request variable cost — cost is uniformly 1.
- No cross-instance shared state — single Caddy process per host is the target deployment;
  multi-instance clustering (and whatever external store it would require) is out of scope, same as
  it was cut from the Python system.
- No coupling to the separate Apache→Caddy web-server migration project — this plugin is usable
  standalone in any Caddy config once built; sequencing of the two migrations is a deployment
  decision, not a design dependency.

## 7. Open questions to resolve during design (not decided by this document)

1. ~~Does Caddy's built-in trusted-proxy/`client_ip` placeholder machinery satisfy FR-010a's
   exact-hop-count XFF resolution, or does this module need its own?~~ — **decided:** no custom
   logic needed; Caddy's `trusted_proxies`/`trusted_proxies_strict` + a `not remote_ip` matcher
   fully cover it (§4.1). Dropped the "exact hop count" requirement itself — it was a Python
   implementation detail, not something worth preserving for its own sake.
2. Reuse `reverse_proxy` (upstreams, health checks, `lb_policy`) vs. fully custom load
   balancer/dispatcher — recommended default is to reuse and extend, see §4.6/§4.7.
3. Can this module register its own admin API routes, or should introspection ride on
   `GET /config/...` against app-level state instead of a bespoke `/admin/*` surface?
4. Exact `caddy.UsagePool` (or equivalent) strategy for carrying capacity-controller/load-balancer/
   EWMA-scoring state across a config reload without resetting it to configured defaults every time
   (§3.3).
5. ~~Whether GeoIP/JWKS state belongs on the app module (shared) or could reasonably be
   per-handler~~ — **decided:** the `fairness` app module (§3.1), keyed by resource identity (DB
   path / issuer URL) rather than requiring a dedicated global-options directive, so blocks share
   the underlying resource whether or not they used `import` to declare identical settings (§5).
6. Whether per-dimension EWMA maps (§3.2/§4.3) belong on the `fairness` app module (shared across
   backends, one IP's traffic to backend A and backend B counted together) or per-handler (isolated
   per backend) — current recommendation is app-level, since penalizing an abusive IP should apply
   system-wide, not reset per backend it happens to hit.
7. Whether directive ordering between `fairness` and `adaptive_admission` should be enforced via
   `httpcaddyfile.RegisterOrder` (so a bare, non-`route`-wrapped Caddyfile still orders correctly)
   or left as a documented requirement to wrap both in an explicit `route { ... }` block (§3.1/§5)
   — recommended default is to attempt `RegisterOrder` and treat the explicit `route` block as a
   fallback/escape hatch, not decided here.

## 8. Performance requirements and lessons from the Python implementation

A dated (2026-08-03) production/load-test investigation against the Python system
(`docs/scaling_remediation_plan.md`, `docs/deployment.md`, `docs/known_limitations.md` in
`adaptive-admission-controller`) found that its throughput **peaked around 50-100 concurrent
requests (~327 req/s) and then dropped** as offered concurrency rose to 250 (down to ~80 req/s,
p99 > 4.5s), with 0% rejections and no FD/queue exhaustion — i.e. the process was CPU-bound, not
resource-starved. A "wake-storm" hypothesis (`asyncio.Condition.notify_all()` waking every queued
waiter) was fixed and A/B tested but produced **no measurable improvement**, because the
architecture only ever has one waiter per backend condition — the fix was correct but not the
cause. Real profiling (`py-spy`, since `cProfile` misattributes async I/O time) showed CPU time
diffused across dozens of call sites (event-loop bookkeeping, HTTP client internals, JSON logging,
middleware chain), none individually above ~2% of samples: **cumulative per-request overhead
across the whole single-threaded async stack**, not one fixable hot function. The documented
conclusion was that this requires multi-process scale-out to fix in Python.

**This class of failure is largely eliminated by construction in Go** — goroutines run on real OS
threads across cores, so there is no single-threaded ceiling to saturate the way `uvicorn`'s one
event loop did. That is a reason to expect a materially higher ceiling, **not** a license to skip
verifying it, and not a reason to reintroduce the same shape of problem (many cheap-looking
per-request costs compounding into one bottleneck) inside a single hot path. Concretely, carried
forward as requirements for this port:

- **Load test the actual concurrency ramp, don't assume Go's parallelism alone fixes it.** Port an
  equivalent of `scripts/load_test.py` (ramp-up/hold-open/multi-endpoint concurrency sweep,
  measuring p50/p95/p99 and throughput vs. offered concurrency) early enough to run it against the
  Go module before considering this port's performance validated. If throughput still inverts at
  some concurrency level, profile with `pprof` before hypothesizing a fix — the Python
  investigation's lesson is that plausible-sounding contention theories (wake-storm) can be wrong
  even when the underlying fix is harmless to make.
- **No single global lock serializing all per-request scoring/state updates.** The Python system's
  per-request scoring did six *sequential* Redis round-trips (not concurrent), serialized on the
  admission-decision critical path. The in-memory EWMA maps (§3.2/§4.3) must not recreate an
  equivalent serialization point: prefer per-dimension sharded mutexes or `sync.Map` over one
  mutex guarding all six dimensions' maps, and update independent dimensions concurrently
  (goroutines/`errgroup`) rather than sequentially, if profiling later shows this matters — do not
  add this complexity speculatively before measuring, but do not reach for "one big mutex" as the
  default either, given it was directly implicated as a design smell (even though not the root
  cause) in the source system.
- **Percentile tracking must not re-sort the full sample window on every controller tick.** The
  Python `LatencyWindow.p95()` re-sorts a 100-sample deque (`O(n log n)`) on every `adjust_loop()`
  tick (§4.4). Even though the tick is infrequent (default 30s), implement this with an
  incrementally-maintained structure (e.g. a fixed-size histogram/bucket structure, a running
  t-digest, or an insertion-sorted structure updated per-sample) so p95 computation is `O(log n)`
  or better — do it correctly the first time rather than porting the sort-per-tick approach as-is.
- **Any bounded cache added to this port must use true O(1) eviction**, not a linear scan. The
  Python `GeoIPLookup` cache evicts via `min(cache, key=...)` — an O(n) scan over up to 10k entries
  on every eviction. If this port adds an in-memory cache anywhere (e.g. GeoIP lookup results,
  JWKS key lookups), use a real LRU (ring buffer + map, or an existing Go LRU package), never a
  scan-to-find-minimum.
- **Load-balancer instance selection must not rebuild candidate sets from scratch per request.**
  The Python `LeastLoadedLoadBalancer._active_pool()` rebuilds two filtered dicts from all upstream
  URLs on every single `select()` call, serialized under one shared lock (§4.6). This port's
  least-in-flight selection should maintain an incrementally-updated candidate structure (updated
  on health-check transitions and in-flight count changes) rather than recomputing a full
  active/healthy partition on every dispatched request.
- **One structured log call per admission decision, not several.** The Python system does at least
  two separate JSON-serialization passes per request (the admission event and a separate
  score-breakdown log, §4.9). This port's structured logging requirement (§4.9) already specifies
  "one JSON log line per admission decision" — implement that literally as a single `ctx.Logger()`
  call carrying all fields (including the score breakdown) as structured zap fields, not as a
  separately-serialized nested blob or a second log call.
- **Keep the always-executed request/response hot path allocation-light.** Header filtering
  (hop-by-hop stripping), queue-entry construction, and per-request IP parsing are individually
  cheap in the Python source but run unconditionally on every request and were named among the
  diffuse profiling hot spots. Where Go idioms make it easy (e.g. reusing buffers via `sync.Pool`
  for queue entries, avoiding unnecessary `net.IP`/string conversions when Caddy's own
  placeholders already provide a parsed value), prefer the lower-allocation form — but do not
  micro-optimize this speculatively at the expense of clarity; profile first, per the load-testing
  requirement above.
- **Upstream connection pooling must be explicitly sized, not left at a library default.** The
  Python system's shared Redis connection pool (default size 100) was identified as "the tightest
  shared ceiling in the system," initially configured only implicitly. Since this port drops Redis
  entirely (§3.2), the equivalent concern is upstream HTTP connection pooling via `reverse_proxy` —
  its transport's max-idle-connections/max-connections-per-host settings should be explicit,
  documented config surface (§4.7), not left to Go's `http.Transport` defaults.
