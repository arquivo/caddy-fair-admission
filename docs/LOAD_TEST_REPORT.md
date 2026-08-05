# Load test report — Phase 11 concurrency sweep

Captured by TestLoadTest_FullChain_ConcurrencySweep (loadtest_e2e_test.go) at 2026-08-04T14:36:13Z.

Chain under test: fairness -> adaptive_admission (fixed controller, limit=300,
i.e. non-limiting for this sweep's 50-250 range) -> reverse_proxy, against a
dummy upstream with a fixed 15ms latency across 3 endpoints ([/ /search /api/lookup]), matching
REQUIREMENTS.md §8's methodology (ramp-up/hold-open/multi-endpoint concurrency
sweep, measuring p50/p95/p99 and throughput vs. offered concurrency) and the
50->250 concurrency range the original Python system's own investigation used.

Each level: 1s ramp-up (staggered worker start), then 3s steady-state hold
measured for throughput/percentiles.

```
concurrency  requests   errors   throughput(req/s) p50        p95        p99       
50           8744       0        2914.7           17ms       20ms       22ms      
100          17318      0        5772.7           17ms       21ms       25ms      
150          23704      0        7901.3           17ms       26ms       31ms      
200          29468      0        9822.7           19ms       31ms       36ms      
250          32620      0        10873.3          20ms       37ms       47ms      
```

No throughput inversion detected: peak 10873.3 req/s at concurrency 250, and throughput does not drop >=15% below that peak at any higher concurrency level swept.
