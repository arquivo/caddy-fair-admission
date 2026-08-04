// Package adaptiveadmission — Prometheus metrics (§4.8). Collectors are
// package-level vars, constructed exactly once (via sync.Once) and registered
// against whichever *prometheus.Registry each config load provides. This
// mirrors Caddy's own registration pattern
// (modules/caddyhttp/reverseproxy/metrics.go) rather than routing through
// ctx.App(...): caddy.Context.App panics on a zero-value Context (confirmed
// against Caddy v2.11.4's source), which two of this package's own existing
// unit tests construct directly (TestHandler_ProvisionAndCleanup_*), so
// metrics registration must only ever touch ctx.GetMetricsRegistry()
// (nil-safe) and never ctx.App(...).
package adaptiveadmission

import (
	"errors"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type admissionMetricsSet struct {
	init sync.Once

	requestsInFlight  *prometheus.GaugeVec
	concurrencyLimit  *prometheus.GaugeVec
	queueSize         *prometheus.GaugeVec
	requestsTotal     *prometheus.CounterVec
	requestsAdmitted  *prometheus.CounterVec
	requestsRejected  *prometheus.CounterVec
	backendErrors     *prometheus.CounterVec
	backendTimeouts   *prometheus.CounterVec
	limitChanges      *prometheus.CounterVec
	requestDuration   *prometheus.HistogramVec
	queueWaitDuration *prometheus.HistogramVec
}

var admissionMetrics admissionMetricsSet

func init() {
	// Guarantees the collectors are always non-nil and safely usable (e.g.
	// from a test that builds a Handler directly and never calls Provision),
	// per promauto's documented nil-registerer safety.
	initAdmissionMetrics(nil)
}

// initAdmissionMetrics constructs the collectors once (regardless of how many
// times this is called) and, given a non-nil registry, registers them against
// it — swallowing prometheus.AlreadyRegisteredError, which is expected when
// multiple adaptive_admission Handler blocks in the same config register
// against the same registry.
func initAdmissionMetrics(registry *prometheus.Registry) {
	admissionMetrics.init.Do(func() {
		f := promauto.With(nil)
		admissionMetrics.requestsInFlight = f.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "adaptive_admission", Name: "requests_in_flight",
			// Can read up to 1 higher than genuinely in-flight work while
			// the backend is idle -- see Controller.InFlight's doc
			// (capacity.go) for why.
			Help: "Requests currently admitted and in flight.",
		}, []string{"backend"})
		admissionMetrics.concurrencyLimit = f.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "adaptive_admission", Name: "concurrency_limit",
			Help: "Current controller concurrency limit.",
		}, []string{"backend"})
		admissionMetrics.queueSize = f.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "adaptive_admission", Name: "queue_size",
			Help: "Current number of queued (not yet admitted) requests.",
		}, []string{"backend"})
		admissionMetrics.requestsTotal = f.NewCounterVec(prometheus.CounterOpts{
			Namespace: "adaptive_admission", Name: "requests_total",
			Help: "Total requests seen.",
		}, []string{"backend"})
		admissionMetrics.requestsAdmitted = f.NewCounterVec(prometheus.CounterOpts{
			Namespace: "adaptive_admission", Name: "requests_admitted_total",
			Help: "Total requests admitted (dispatched to next handler).",
		}, []string{"backend"})
		admissionMetrics.requestsRejected = f.NewCounterVec(prometheus.CounterOpts{
			Namespace: "adaptive_admission", Name: "requests_rejected_total",
			Help: "Total requests rejected, by reason.",
		}, []string{"backend", "reason"})
		admissionMetrics.backendErrors = f.NewCounterVec(prometheus.CounterOpts{
			Namespace: "adaptive_admission", Name: "backend_errors_total",
			Help: "Total dispatched requests whose outcome was a 5xx/error.",
		}, []string{"backend"})
		admissionMetrics.backendTimeouts = f.NewCounterVec(prometheus.CounterOpts{
			Namespace: "adaptive_admission", Name: "backend_timeouts_total",
			Help: "Total dispatched requests whose outcome was a timeout.",
		}, []string{"backend"})
		admissionMetrics.limitChanges = f.NewCounterVec(prometheus.CounterOpts{
			Namespace: "adaptive_admission", Name: "adaptive_limit_changes_total",
			Help: "Total adaptive-controller limit changes, by direction.",
		}, []string{"backend", "direction"})
		admissionMetrics.requestDuration = f.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "adaptive_admission", Name: "backend_request_duration_seconds",
			Help:    "Dispatched request duration.",
			Buckets: prometheus.DefBuckets,
		}, []string{"backend"})
		admissionMetrics.queueWaitDuration = f.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "adaptive_admission", Name: "queue_wait_duration_seconds",
			Help:    "Time an admitted request spent queued before admission.",
			Buckets: prometheus.DefBuckets,
		}, []string{"backend"})
	})

	if registry == nil {
		return
	}
	collectors := []prometheus.Collector{
		admissionMetrics.requestsInFlight,
		admissionMetrics.concurrencyLimit,
		admissionMetrics.queueSize,
		admissionMetrics.requestsTotal,
		admissionMetrics.requestsAdmitted,
		admissionMetrics.requestsRejected,
		admissionMetrics.backendErrors,
		admissionMetrics.backendTimeouts,
		admissionMetrics.limitChanges,
		admissionMetrics.requestDuration,
		admissionMetrics.queueWaitDuration,
	}
	for _, c := range collectors {
		var already prometheus.AlreadyRegisteredError
		if err := registry.Register(c); err != nil && !errors.As(err, &already) {
			panic("adaptive_admission: registering metric: " + err.Error())
		}
	}
}
