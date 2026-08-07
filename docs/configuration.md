# Configuration reference

This is the authoritative reference for every Caddyfile directive both modules accept, and for the
scoring/admission mechanics behind them. For narrative walkthroughs of how this behaves against
real traffic patterns, see [`scenarios.md`](scenarios.md). For the admin API and metrics this
config surface feeds, see [`monitoring.md`](monitoring.md).

Both modules are configured with a Caddyfile block per backend/route (`fairness { ... }` and
`adaptive_admission { ... }`), or the equivalent JSON under
`apps.http.servers.<name>.routes[].handle`. There is no separate global-options directive or
bespoke config file for either module — settings that are conceptually shared across backends
(GeoIP paths, JWKS issuer, scoring defaults, ...) are just regular fields inside each block, reused
across blocks with Caddy's native `import`/named-snippet mechanism. See
[`examples/`](../examples/) for runnable files exercising every directive below.

## 1. `fairness` block

| Directive | Args | Default | Notes |
|---|---|---|---|
| `backend <string>` | 1 | `"default"` | A label only — used in metrics/logs/admin output, never affects routing. |
| `geoip_city_db <path>` | 1 | unset (no country/ASN lookups) | Path to a MaxMind city `.mmdb`. Fails open independently of `geoip_asn_db` if unopenable. |
| `geoip_asn_db <path>` | 1 | unset | Path to a MaxMind ASN `.mmdb`. Fails open independently of `geoip_city_db`. |
| `auth_issuer <string>` | 1 | `""` | Expected JWT `iss` claim; not itself validated at parse time. |
| `auth_jwks_url <url>` | 1 | `""` (auth disabled) | JWKS endpoint for verifying bearer tokens (RS256), refreshed on a background loop. |
| `auth_audience <string>` | 1 | `""` | Expected JWT `aud` claim; not itself validated at parse time. |
| `exempt_country <ISO-3166-1 alpha-2>` | 1, repeatable | none | Marks a country as exempt from `country`-dimension penalties (see §5). Exact string match. |
| `ipv6_prefix_length <int>` | 1 | `56` | **Must be exactly `48` or `56`** — any other value is a Caddyfile parse error. |
| `ewma_tick_interval <duration>` | 1 | `1s` | How often the EWMA updater re-evaluates every tracked entity's rate (see §2). |
| `idle_entry_ttl <duration>` | 1 | `10m` | Entities with no traffic for longer than this are garbage-collected. Swept by a fixed, non-configurable 1-minute ticker; reclaimed strictly when idle time is `>` the TTL, not `>=`. |
| `scoring { ... }` | sub-block | absent, or with no `penalty` lines → no dimensions active | See §1.1. |

Any unrecognized top-level token is a Caddyfile parse error
(`unrecognized fairness subdirective '%s'`).

### 1.1 `scoring { }` sub-block

A scoring dimension (§3) is tracked and penalized **only if** a `penalty <dimension>` line names it
here. There is no baseline set of always-active dimensions: a block with no `scoring { }` at all, or
one with zero `penalty` lines, gives every request its class's flat `base_score` with
`total_penalty` always `0`.

```caddyfile
scoring {
    base_score <user_class> <float>                          # repeatable, one of 5 classes
    penalty <dimension>                                       # repeatable, one of 6 dimensions — enables it with built-in default tuning
    penalty <dimension> alpha=<f> soft=<f>:<f> hard=<f>:<f>   # repeatable — enables it with explicit tuning instead
    divisor param <name> <value>                              # repeatable — presence-based priority divisor, see below
    min_score <float>
    max_score <float>
}
```

- `base_score <class> <value>` — sets the starting score for one of the 5 user classes (§4). Both
  args required; the class name must be one of the 5 valid classes. Independent of which dimensions
  are enabled — applies even with zero `penalty` lines.
- `penalty <dimension>` — enables that dimension using its built-in default tuning (§3's table)
  without needing to restate the numbers.
- `penalty <dimension> alpha=.. soft=t:p hard=t:p` — enables that dimension with explicit EWMA/
  penalty tuning (§2/§3) instead of the defaults. `alpha=`, `soft=`, and `hard=` are all required
  together, in any order. `soft=`/`hard=` are `threshold:penalty` pairs; the penalty's sign is
  cosmetic (magnitude is normalized internally), so `soft=20:-10` and `soft=20:10` are equivalent.
- A repeated `penalty <dimension>` line for the same dimension within one block fully overwrites the
  earlier one — including switching between bare and explicit-tuning form. Last line wins.
- `min_score <float>` / `max_score <float>` — clamp bounds for the final score (default `0`/`100`).
  Only explicitly-set values override the defaults; unset stays at the default rather than being
  treated as `0`. Independent of which dimensions are enabled.
- Enabling `asn` requires a working `geoip_asn_db`, `country` requires a working `geoip_city_db`,
  and `user` requires a working `auth_jwks_url` — **Provision fails at config-load time**, not just
  silently degrading to 0-penalty, if:
  - the dimension is enabled but the prerequisite field isn't set at all on this block, or
  - the prerequisite field is set but the resource itself fails to open/initialize (missing GeoIP
    file, corrupt `.mmdb`, unreachable/malformed JWKS URL) — catching a typo'd path/URL that would
    otherwise fail open silently and go unnoticed by the operator.

  `ip`/`ipv4_subnet`/`ipv6_subnet` have no such prerequisite — they derive purely from the parsed client IP.
- There is no cross-field validation beyond the above — nothing stops you from setting `min_score`
  above `max_score` or a `soft` threshold above `hard`; both are accepted as-is.

#### Priority divisor: `divisor param <name> <value>`

Separate from the identity-based dimensions above, `divisor param <name> <value>` (repeatable) lets
a request's *query parameters* — not who's asking, but what they're asking for — adjust its final
score. It's opt-in like everything else in `scoring { }`: no `divisor param` lines at all means every
request gets a divisor of `1` (a no-op), same as the "no `penalty` lines → no dimensions active"
default.

- Presence-based, not value-based: a configured `<name>` contributes its `<value>` as soon as that
  query parameter is present at all, regardless of what it's set to — `?matchType=prefix` and
  `?matchType=` divide the score identically. This deliberately avoids parsing/validating the
  parameter's actual value; presence alone is the signal.
- Multiple present parameters **multiply**, they don't add: `divisor param matchType 1.25` and
  `divisor param timeline 2` both present on the same request combine into a divisor of `2.5`, not
  `3.25`.
- `<value>` must be `> 0` — a Caddyfile parse-time error otherwise. A divisor `> 1` deprioritizes the
  request (an expensive parameter, like CDXJ's `matchType` or Page Search's `timeline`); a divisor
  `< 1` boosts it — symmetric around `1.0`, whichever direction the parameter's actual cost warrants.
- Applied strictly after the identity-based `base_score`/`penalty` computation above: `final_score =
  clamp(base_score[user_class] - total_penalty, min_score, max_score) / divisor`. It never touches
  `adaptive_admission`'s concurrency/capacity accounting (§6/§7) — every ticket still costs exactly
  `1` unit of capacity; the divisor only reorders the priority queue.
- A repeated `divisor param` line for the same `<name>` within one block fully overwrites the earlier
  one, same last-line-wins rule as `penalty`.


## 2. What EWMA is, and why

Each of the up to 6 scoring dimensions (§3) that a `scoring { }` block enables via `penalty
<dimension>` tracks how fast traffic from a given entity (one IP, one `/24`, one ASN, ...) is
arriving, so it can apply a penalty once that rate is sustained rather than a one-off burst. A
dimension never named by a `penalty` line is not tracked at all. The mechanism is an
**exponentially weighted moving average (EWMA)** of requests
per second, not a rolling window / sliding count — this is a deliberate departure from a naive
"count requests in the last N seconds" approach, because a fixed window either forgets a sustained
abuser the instant they pause for N seconds, or requires storing individual request timestamps
(expensive at scale). EWMA instead keeps exactly one floating-point number per tracked entity and
updates it on a fixed tick:

```
rate  = requests_since_last_tick / tick_interval_seconds
ewma  = alpha * rate + (1 - alpha) * ewma_previous
```

- **`ewma_tick_interval`** (this system's version of a "window" — default `1s`) is how often this
  update runs, for every tracked entity, across every enabled dimension. It also sets the denominator
  for `rate`: a 2-second tick that saw 10 requests computes `rate = 5`, not `10` — the EWMA always
  operates on a normalized per-second rate regardless of tick length.
- **`alpha`** (per-dimension, default `0.2`) controls how much weight the *most recent* tick gets
  vs. everything before it. A higher alpha reacts to a rate change faster but is noisier; a lower
  alpha smooths out brief spikes but takes longer to reflect sustained load.
- Between ticks, requests just increment a pending counter — the EWMA math itself only runs at
  tick boundaries, and penalties are evaluated against the EWMA value as of the *last completed
  tick*, never a mid-tick estimate.

**Worked trace** (`alpha = 0.2`, `tick_interval = 1s`, starting `ewma = 0`), one request arriving
in every tick for 4 seconds straight:

| Tick | requests this tick | rate | `ewma = 0.2*rate + 0.8*ewma_prev` |
|---|---|---|---|
| 1 | 1 | 1.0 | `0.2*1.0 + 0.8*0.0` = **0.20** |
| 2 | 1 | 1.0 | `0.2*1.0 + 0.8*0.20` = **0.36** |
| 3 | 1 | 1.0 | `0.2*1.0 + 0.8*0.36` = **0.49** |
| 4 | 1 | 1.0 | `0.2*1.0 + 0.8*0.49` = **0.59** |

The EWMA climbs toward the steady-state rate (1.0 here) but never jumps straight to it — a
sustained rate is required to actually cross a threshold, while a single-tick burst decays back out
almost as fast as it arrived (see [`scenarios.md`](scenarios.md) for a full walkthrough of a normal
user's browsing burst vs. a sustained crawler).

## 3. Soft vs. hard penalties

Each of the 6 recognized dimensions has its own `PenaltyConfig{alpha, soft_threshold, soft_penalty,
hard_threshold, hard_penalty}`, used when that dimension is enabled via `penalty <dimension>` (§1.1)
— a dimension never named by a `penalty` line contributes nothing at all, not even a `0` entry.
Given an enabled dimension's current EWMA rate:

```
rps > hard_threshold  → hard_penalty
rps > soft_threshold  → soft_penalty     (and rps <= hard_threshold)
otherwise             → 0
```

Boundaries are **strictly exclusive** (`>`, not `>=`): a rate exactly equal to the soft threshold
contributes no penalty yet; a rate exactly equal to the hard threshold still only gets the soft
penalty. Soft and hard are **not additive within a dimension** — only the single highest-qualifying
tier applies. Across dimensions, though, contributions **do** sum: a request classified into a
penalized `ip` *and* a penalized `asn` pays both, if both are enabled. The final score is:

```
final = clamp(base_score[user_class] - sum_of_enabled_dimension_penalties, min_score, max_score)
```

### Default per-dimension tuning

Applied to a dimension when it's enabled via a bare `penalty <dimension>` line (§1.1) with no
explicit `alpha=`/`soft=`/`hard=` given:

| Dimension | Tracks | Applies to | alpha | soft (threshold:penalty) | hard (threshold:penalty) |
|---|---|---|---|---|---|
| `ip` | single client IP | any resolved IP | 0.2 | 20 : 10 | 100 : 40 |
| `ipv4_subnet` | IPv4 `/24` subnet | IPv4 only | 0.2 | 100 : 10 | 500 : 40 |
| `ipv6_subnet` | IPv6 `/48` or `/56` (per `ipv6_prefix_length`) | IPv6 only | 0.2 | 100 : 10 | 500 : 40 |
| `asn` | autonomous system | GeoIP ASN DB configured & resolves | 0.2 | 500 : 10 | 2000 : 40 |
| `country` | country | GeoIP city DB configured & resolves | 0.2 | 2000 : 10 | 10000 : 40 |
| `user` | JWT subject | authenticated requests only | 0.2 | 20 : 10 | 100 : 40 |

**Why aggregate dimensions get much higher thresholds than `ip`/`user`:** a single IP or user
sustaining 20+ rps is unusual behavior worth penalizing lightly, but a `/24` subnet, an ASN, or a
whole country legitimately carries far more traffic from many distinct real users — a shared campus
network, a mobile carrier's NAT gateway, or a large ISP can easily produce hundreds of req/s of
completely ordinary browsing. Penalizing at `ip`-dimension thresholds for these aggregate
dimensions would punish innocent traffic sharing an address block. The defaults above are a
starting point, not a guarantee — see [`scenarios.md`](scenarios.md) for a case where the defaults
under-react to a genuinely abusive ASN and need a backend-level override.

## 4. User classes & base scores

| Class | Meaning | Default `base_score` |
|---|---|---|
| `researcher` | JWT-verified, trusted | 100 |
| `service_account` | JWT-verified, trusted | 100 |
| `internal` | JWT-verified, trusted | 100 |
| `anonymous` | no bearer token presented | 60 |
| `unknown` | token presented but unverifiable (e.g. JWKS unreachable, bad signature) | 60 |

Classification is identity-only — behavior (request rate, penalties) is never folded back into the
class itself, only into the score via the 6 dimensions above. `unknown` deliberately shares
`anonymous`'s base score rather than being penalized further: an unverifiable token is not evidence
of bad intent (it may just mean the JWKS endpoint is temporarily unreachable — a fail-open
condition), so it isn't trusted *less* than presenting no token at all.

## 5. Exempt countries

`exempt_country <CC>` (repeatable, exact ISO 3166-1 alpha-2 match, no wildcards/case-folding) marks
a country whose `country`-dimension penalty never contributes to `total_penalty`. This only has an
observable effect if `country` is actually enabled via `penalty country` (§1.1) — otherwise there's
no `country` penalty to exempt from in the first place. When enabled, the dimension is still tracked
and counted for observability (visible via `/fairness/status`'s `dimension_entry_counts`, see
[`monitoring.md`](monitoring.md)) even for exempt countries — exemption only suppresses its penalty
contribution, and has no effect on the other dimensions (`ip`/`ipv4_subnet`/`ipv6_subnet`/`asn`/`user` are
evaluated independently regardless of country).

## 6. `adaptive_admission` block

```caddyfile
adaptive_admission {
    backend <string>

    controller fixed {
        limit <int>
    }
    # or:
    controller adaptive {
        min_concurrency        <int>
        initial_concurrency    <int>
        max_concurrency        <int>
        target_p95             <duration>
        timeout_rate_threshold <float>
        error_rate_threshold   <float>
        adjust_interval        <duration>
    }

    queue_max_size <int>
    queue_timeout  <duration>
}
```

| Directive | Default | Notes |
|---|---|---|
| `backend <string>` | `"default"` | Label only, as in `fairness`. |
| `controller <fixed\|adaptive>` | — (required) | Selects the capacity-control strategy for this backend. |
| `queue_max_size <int>` | `0` (unbounded) | Max tickets the priority queue holds before rejecting new arrivals with `queue_full`. |
| `queue_timeout <duration>` | `0` (unbounded) | Max Little's-law-projected wait before rejecting with `queue_wait_exceeded` (§7). |

`controller fixed { limit <int> }` — a static concurrency ceiling. `limit` must be `> 0`.

`controller adaptive { ... }` — self-tuning concurrency, re-evaluated every `adjust_interval`
(default 30s if unset). `min_concurrency`, `initial_concurrency`, and `max_concurrency` are all
**required** (each must be `> 0`); `target_p95`/`timeout_rate_threshold`/`error_rate_threshold`
default to `0` (disabling the p95-driven branches entirely) if left unset.

### Adaptive adjustment table

At each `adjust_interval` tick, at most **one** branch fires, checked in this exact priority order:

| # | Condition | Multiplier | Direction | Cooldown |
|---|---|---|---|---|
| 1 | timeout rate > `timeout_rate_threshold` | ×0.60 | shrink | 60s (own timer) |
| 2 | error rate > `error_rate_threshold` | ×0.75 | shrink | 30s (own timer) |
| 3 | p95 latency > 2 × `target_p95` | ×0.70 | shrink | 30s (shared with #4) |
| 4 | p95 latency > `target_p95` | ×0.85 | shrink | 30s (shared with #3) |
| 5 | p95 latency < 0.5 × `target_p95` | ×1.05 | grow | none |

A shrink never drops the limit below 1 (regardless of `min_concurrency`, as a deadlock guard); a
grow makes forward progress even when the multiplier would otherwise round down to no change (e.g.
limit 1 growing always becomes at least 2). Every change is clamped to
`[min_concurrency, max_concurrency]`. Growing the limit immediately wakes enough blocked requests
to use the new capacity — it doesn't wait for the next request to finish and release its slot.

## 7. Queue semantics

The priority queue orders tickets by **score descending**, then **arrival order (FIFO)** within
equal scores — a higher-scored request is always served first, but two requests with the same
score are served in the order they arrived. Two distinct rejection reasons, both surfaced as HTTP
429 but logged/labeled separately (see [`monitoring.md`](monitoring.md)):

- **`queue_full`** — the queue already holds `queue_max_size` tickets when a new one arrives.
- **`queue_wait_exceeded`** — a Little's-law-style projection already exceeds `queue_timeout`
  before the ticket even joins the queue:

  ```
  projected_wait = queue_depth * mean_latency / concurrency_limit
  ```

  This projection is skipped (never rejects) until at least one request has completed and produced
  a real latency sample — an empty/cold queue never gets rejected on a wait estimate that doesn't
  exist yet.

## 8. How `fairness` and `adaptive_admission` hand off

`fairness`, if present, must run before `adaptive_admission` in the chain — both directives
register an explicit ordering position (`fairness` immediately before `adaptive_admission`, which
in turn runs immediately before `reverse_proxy`), so a bare Caddyfile with both directives at the
top level of a route orders correctly without needing an explicit `route { }` wrapper (though
wrapping in `route { }` still works and is sometimes clearer). The two modules never import each
other's Go internals — the only coupling is Caddy's own `caddyhttp.SetVar`/`GetVar` request-scoped
variable mechanism:

- `fairness` writes the computed score under a `fairness_score` variable.
- `adaptive_admission` reads it via `GetVar`; if `fairness` wasn't chained ahead at all (or the
  variable isn't a `float64` for any reason), it falls back to a neutral score of `0` — every
  request hitting this fallback is treated identically, neither privileged nor penalized, rather
  than causing an error.
- `fairness` also writes a `fairness_log_fields` variable (IP, ASN, country, user class, exemption
  flag, per-dimension score breakdown) that `adaptive_admission` folds into its own structured log
  line — `fairness` never logs a request on its own (see [`monitoring.md`](monitoring.md)).

## 9. Example: Keycloak as the JWT issuer (researcher queue priority)

`auth_issuer`/`auth_jwks_url`/`auth_audience` (§1) work with any standards-compliant OIDC provider —
this walks through Keycloak specifically, since "give researchers priority" is just "get a verified
`researcher` `user_class` claim into the JWT" (§4.2's `authClaims` shape) plus the `scoring { }`
tuning already covered above. See [`examples/fairness-keycloak.Caddyfile`](../examples/fairness-keycloak.Caddyfile)
for a complete, runnable file.

**Keycloak-side setup** (once per realm/client):

1. Create or pick the realm your researchers authenticate against (e.g. `arquivo`), and the client
   this API's callers use to obtain tokens (confidential client + client-credentials grant for
   service-to-service researcher tooling, or a public/confidential client with the auth-code grant
   for interactive logins — either way, the resulting JWT shape is the same).
2. Create a realm role (or group) — e.g. `researcher` — and assign it to trusted researcher
   accounts.
3. Add a protocol mapper on that client that emits a `user_class` claim of `"researcher"` for
   members of that role/group (a "Hardcoded claim" mapper scoped to the role, or a group-membership
   mapper mapping to that literal string — Keycloak's admin console calls this
   Clients → *your client* → Client scopes → *dedicated scope* → Add mapper). The claim name must be
   exactly `user_class` and its value one of the 3 claimable classes (`researcher`,
   `service_account`, `internal` — §4.2's `validClaimedUserClasses`); anything else classifies as
   `unknown`, not a parse error.
4. Note the realm's issuer and JWKS URLs, both fixed paths for any realm:
   - issuer: `https://<keycloak-host>/realms/<realm>`
   - JWKS: `https://<keycloak-host>/realms/<realm>/protocol/openid-connect/certs`
5. Confirm the client's tokens carry the `aud` claim you intend to put in `auth_audience` — Keycloak
   doesn't always include a client's own client ID as `aud` by default; add an audience mapper on the
   client if needed.

**Caddyfile side** — point `auth_issuer`/`auth_jwks_url`/`auth_audience` (§1) at the values from
step 4/5, and give `researcher` a higher `base_score` than `anonymous` (§4, already the default —
100 vs. 60):

```caddyfile
fairness {
	auth_issuer   https://idp.example.org/realms/arquivo
	auth_jwks_url https://idp.example.org/realms/arquivo/protocol/openid-connect/certs
	auth_audience page-search-api

	scoring {
		base_score researcher 100
		base_score anonymous  60
		penalty user alpha=0.2 soft=20:10 hard=100:40
	}
}
```

No code change and no rejection logic is involved: a researcher's request that carries a valid,
Keycloak-issued bearer token classifies as `UserClassResearcher` (§4.2), gets `base_score 100`
instead of `anonymous`'s 60, and — paired with `adaptive_admission` (§6/§7) — is dequeued ahead of
lower-scored traffic under load. A missing token, an expired one, or a JWKS endpoint that's
temporarily unreachable all fail open to `anonymous`/`unknown` (§1's `auth_jwks_url` note; §4.2) —
Keycloak being down never turns into a 401/403 for anyone, only a loss of the researcher-priority
boost until it recovers.
