# Load test report — Phase 11 concurrency sweep

Captured by TestLoadTest_FullChain_ConcurrencySweep (loadtest_e2e_test.go) at 2026-08-07T22:45:38Z.

Chain under test: fairness -> adaptive_admission (fixed controller, limit=300)
-> reverse_proxy, against a dummy upstream with a fixed 15ms latency across 3
endpoints ([/ /search /api/lookup]), matching REQUIREMENTS.md §8's methodology
(ramp-up/hold-open/multi-endpoint concurrency sweep, measuring p50/p95/p99 and
throughput vs. offered concurrency) and the 50->250 concurrency range the
original Python system's own investigation used, extended here up to 1000 to
confirm capacity holds well beyond that range.

The 50-250 levels stay under the controller's limit=300, so they measure the
chain's raw, non-limiting throughput ceiling. The 400-1000 levels exceed the
limit, so at those levels the sweep is instead exercising adaptive_admission's
bounded priority queue (queue_max_size=1000, queue_timeout=30s) absorbing
offered concurrency the fixed controller won't admit to the backend directly
-- a different thing than raw chain throughput, but still zero errors and no
throughput inversion or collapse under 3-4x sustained overload.

Each level: 1s ramp-up (staggered worker start), then 3s steady-state hold
measured for throughput/percentiles.

```
concurrency  requests   errors   throughput(req/s) p50        p95        p99       
50           8951       0        2983.7           16ms       19ms       22ms      
100          17843      0        5947.7           16ms       20ms       24ms      
150          23629      0        7876.3           17ms       28ms       35ms      
200          30191      0        10063.7          18ms       31ms       37ms      
250          36413      0        12137.7          19ms       32ms       39ms      
400          44572      0        14857.3          25ms       40ms       48ms      
600          45746      0        15248.7          38ms       53ms       60ms      
800          46091      0        15363.7          50ms       69ms       78ms      
1000         45876      0        15292.0          64ms       84ms       92ms      
```

No throughput inversion detected: peak 15363.7 req/s at concurrency 800, and throughput does not drop >=15% below that peak at any higher concurrency level swept.
