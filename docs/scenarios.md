# Scenarios

Two worked examples showing how the 6 scoring dimensions (§3 of
[`configuration.md`](configuration.md)) actually behave against real traffic shapes: a distributed
crawler designed to stay under per-IP rate limits, and a normal human browsing session. Both
walkthroughs assume every dimension discussed has actually been enabled via a `penalty <dimension>`
line in a `scoring { }` block (§1.1 of [`configuration.md`](configuration.md)) — dimensions are
opt-in, not on by default, so if your own config only enables a subset, only those apply. Read
[`configuration.md`](configuration.md) first if you haven't already — this document assumes you
know what EWMA, `alpha`, and soft/hard thresholds mean and just walks the numbers.

## Scenario A — a distributed, low-and-slow crawler

**The traffic:** an aggressive crawler, hosted on a single large cloud/mobile-carrier ASN, wants
100 requests/second of aggregate throughput against arquivo.pt without tripping any per-IP rate
limit. It does this the obvious way: spread the load across a very large pool of source IPs, so
that any *individual* IP only sends about 5 requests per hour (`100 req/s * 3600s / 5 req` ≈
72,000 distinct IPs needed — plausible for a large NAT/CGNAT deployment or a botnet). This is
exactly the pattern classic per-IP rate limiting is blind to.

### Walking the dimensions

**`ip` (default: alpha=0.2, soft=20:10, hard=100:40).** Each individual IP's EWMA sees roughly one
request every 720 seconds. Even a tick interval of `1s` means almost every tick contributes
`rate = 0`, so that IP's EWMA decays toward 0 between its rare hits and never gets anywhere near
the soft threshold of 20 rps. **This dimension is structurally blind to this attack — that is the
entire point of spreading across so many IPs.**

**`ipv4_subnet` / `ipv6_subnet` (default: alpha=0.2, soft=100:10, hard=500:40).** If the crawler's IP pool is
itself spread across many different `/24` (or `/48`/`/56` for IPv6) subnets — plausible for a big
enough hosting provider or mobile carrier — then even the subnet-level aggregation dilutes the
rate. 100 req/s spread over, say, 300 different `/24`s is about 0.33 req/s per subnet: still well
under the soft threshold. **These dimensions help, but only if the attacker's IP pool happens to be
subnet-concentrated — not guaranteed.**

**`asn` (default: alpha=0.2, soft=500:10, hard=2000:40).** This is the one dimension that cannot be
diluted by spreading across more IPs or subnets: every request from this crawler, regardless of
source IP, resolves to the *same* ASN. Its EWMA converges toward the true aggregate rate:

| Tick | requests this tick | rate | `ewma = 0.2*rate + 0.8*ewma_prev` |
|---|---|---|---|
| ... | (steady state reached after ~15-20 ticks at `alpha=0.2`) | | |
| steady-state | ~100/tick | 100 | **≈ 100** |

So the `asn` dimension's EWMA settles around **100 rps** — real, visible, and attributable to one
entity. But notice: **100 is still well under the default `asn` soft threshold of 500.** With
default tuning, this crawler pays *zero* penalty on any enabled dimension. This is the central
lesson of this scenario: the default aggregate thresholds are tuned to tolerate legitimate
high-traffic ASNs (large ISPs, campus networks — see [`configuration.md`](configuration.md) §3),
which means a moderately-sized distributed crawler can sit comfortably below them too. Defaults are
a starting point, not a guarantee.

### Detecting and reacting to it

The operator's signal isn't a penalty firing — it's `/fairness/status`'s `dimension_entry_counts`
(see [`monitoring.md`](monitoring.md)) showing this ASN tracking an unusually large number of
distinct `ip` entries relative to its request volume (tens of thousands of nearly-idle IP entries
under one ASN is itself a strong signal, independent of any EWMA value). Once identified, the fix
is a backend-level override tightening just the `asn` dimension:

```caddyfile
fairness {
	geoip_asn_db  /etc/caddy/GeoLite2-ASN.mmdb
	geoip_city_db /etc/caddy/GeoLite2-City.mmdb

	scoring {
		# Every dimension used in this walkthrough must be explicitly
		# enabled — dimensions are opt-in. ip/ipv4_subnet/ipv6_subnet/country/user
		# keep their built-in default tuning (bare form); only asn is tightened.
		penalty ip
		penalty ipv4_subnet
		penalty ipv6_subnet
		penalty country
		penalty user
		# alpha=0.3 reacts faster than the 0.2 default since we now know
		# this specific pattern is worth catching quickly.
		# soft=50 means 50+ rps sustained from one ASN gets a mild -10
		# penalty (still served, just deprioritized in the queue) — this
		# crawler's observed ~100 rps steady-state sits above it.
		# hard=200 is intentionally left above this crawler's observed
		# rate: this override demotes it rather than blocking it outright.
		penalty asn alpha=0.3 soft=50:10 hard=200:40
	}
}
```

With `soft=50:10`, this crawler's ~100 rps steady-state EWMA now sits above the soft threshold and
below the hard threshold, so every request from this ASN now carries a **-10 penalty**. That's not
a block — it's a demotion. In the priority queue (§7 of [`configuration.md`](configuration.md)), a
`researcher` request (base 100) still outranks this crawler's `anonymous` request (base 60, now 50
after penalty) exactly as before, but under load, the crawler's requests are now measurably more
likely to be queued behind legitimate traffic, or to hit `queue_wait_exceeded` first if the queue
is under pressure. If you want this ASN blocked outright rather than demoted, tighten `hard` below
its observed EWMA instead (e.g. `hard=80:99` against a `max_score` of 100, effectively zeroing its
score).

## Scenario B — a normal browsing session

**The traffic:** a human visitor lands on the homepage, reads for a bit, then clicks through to a
search results page and a couple of item pages — 5 requests total over about 90 seconds, in two
small bursts (the initial page load pulling 2-3 sub-resources at once, then single clicks with
seconds-to-minutes of think-time between them).

### Walking the dimensions

With `ewma_tick_interval=1s` and `alpha=0.2` (all defaults), consider the busiest moment: the
initial page load, where 3 requests might land in the same 1-second tick.

| Tick | requests this tick | rate | `ewma = 0.2*rate + 0.8*ewma_prev` |
|---|---|---|---|
| 1 (page load) | 3 | 3.0 | `0.2*3.0 + 0.8*0.0` = **0.60** |
| 2-90 (think time, no requests) | 0 | 0.0 | decays toward 0: `0.60 * 0.8^n` — already **≈0.10** by tick 5, **≈0.0004** by tick 30 |
| ~30s later (one click) | 1 | 1.0 | `0.2*1.0 + 0.8*0.0004` ≈ **0.20** |

The `ip` EWMA never gets close to its soft threshold of **20** — it peaks at 0.60 for a single tick
and spends the overwhelming majority of the session decaying toward zero. The same math applies at
every other dimension (`ipv4_subnet`, `ipv6_subnet`, `asn`, `country`, `user` if authenticated) since this
session contributes at most 3 requests/tick to any of them — several orders of magnitude under
even the tightest default soft threshold (20, on `ip`/`user`).

**Result:** `total_penalty = 0` across all 6 enabled dimensions for this entire session. The final score is
just the base score for this visitor's class — 60 if anonymous, 100 if this happens to be an
authenticated `researcher`/`internal`/`service_account` session — completely untouched by the
fairness layer. This is the intended baseline: ordinary bursty-then-idle human browsing should
never accumulate enough sustained rate on any dimension to cross a soft threshold, no matter how
low `alpha` or how short `ewma_tick_interval` is set. Contrast this against Scenario A's `asn`
dimension, which converges toward a real, sustained, non-decaying rate precisely because that
traffic never stops arriving.
