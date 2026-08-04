// Package fairness — Prometheus metrics (§4.8). Collectors are package-level
// vars, constructed exactly once (via sync.Once) and registered against
// whichever *prometheus.Registry each config load provides. This mirrors
// Caddy's own registration pattern (modules/caddyhttp/reverseproxy/metrics.go)
// rather than routing through ctx.App(...): caddy.Context.App panics on a
// zero-value Context (confirmed against Caddy v2.11.4's source), which two of
// adaptiveadmission's existing unit tests construct directly, so metrics
// registration must only ever touch ctx.GetMetricsRegistry() (nil-safe) and
// never ctx.App(...).
package fairness

import (
	"errors"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type fairnessMetricsSet struct {
	init sync.Once

	scoreDistribution *prometheus.HistogramVec
}

var fairnessMetrics fairnessMetricsSet

func init() {
	// Guarantees the collectors are always non-nil and safely usable (e.g.
	// from a test that builds a Handler directly and never calls Provision),
	// per promauto's documented nil-registerer safety.
	initFairnessMetrics(nil)
}

// initFairnessMetrics constructs the collectors once (regardless of how many
// times this is called) and, given a non-nil registry, registers them against
// it — swallowing prometheus.AlreadyRegisteredError, which is expected when
// multiple fairness Handler blocks in the same config register against the
// same registry.
func initFairnessMetrics(registry *prometheus.Registry) {
	fairnessMetrics.init.Do(func() {
		fairnessMetrics.scoreDistribution = promauto.With(nil).NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "fairness",
			Name:      "score_distribution",
			Help:      "Distribution of computed fairness scores.",
			Buckets:   prometheus.LinearBuckets(0, 10, 11),
		}, []string{"backend", "user_class"})
	})

	if registry == nil {
		return
	}
	for _, c := range []prometheus.Collector{fairnessMetrics.scoreDistribution} {
		var already prometheus.AlreadyRegisteredError
		if err := registry.Register(c); err != nil && !errors.As(err, &already) {
			panic("fairness: registering metric: " + err.Error())
		}
	}
}
