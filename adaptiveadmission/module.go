// Package adaptiveadmission implements the http.handlers.adaptive_admission
// Caddy module: capacity control, priority queue/scheduler, and dispatch
// (REQUIREMENTS.md §4.4-§4.7).
package adaptiveadmission

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("adaptive_admission", parseCaddyfile)

	// See fairness/module.go's init() for why this anchors to a *different*
	// standard directive ("reverse_proxy") rather than to "fairness"
	// directly — RegisterDirectiveOrder cannot anchor one plugin directive
	// relative to another. "request_header" (fairness's anchor) always
	// precedes "reverse_proxy" in Caddy's defaultDirectiveOrder, so
	// fairness < adaptive_admission < reverse_proxy holds regardless of
	// init() order between the two plugin packages (§3.1, §7 Q7).
	httpcaddyfile.RegisterDirectiveOrder("adaptive_admission", httpcaddyfile.Before, "reverse_proxy")
}

// fairnessScoreVarKey mirrors fairness's own fairnessScoreVarKey constant
// (fairness/module.go) by string value only — fairness and adaptiveadmission
// deliberately never import each other's internals (§3.4); the
// caddyhttp.SetVar/GetVar hand-off is the only coupling point (§3.1).
const fairnessScoreVarKey = "fairness_score"

// neutralScore is used when no fairness_score var was set (fairness wasn't
// chained ahead of this directive, or the var isn't a float64). Its absolute
// value is inconsequential: every request hitting this fallback gets the
// same score, so they're served FIFO relative to each other — neutral, not
// privileged or penalized (fail-open per §3.1).
const neutralScore float64 = 0

// fairnessLogFieldsVarKey mirrors fairness's own logFieldsVarKey constant
// (fairness/module.go) by string value only, per the same cross-package
// convention as fairnessScoreVarKey above.
const fairnessLogFieldsVarKey = "fairness_log_fields"

// Handler is the http.handlers.adaptive_admission middleware. It admits a
// request through a priority queue backed by a capacity controller
// (queue.go/capacity.go), then dispatches to the next handler in the chain
// — normally Caddy's own reverse_proxy directive (§4.6/§4.7) — timing the
// call to record its outcome back onto the controller.
//
// ServeHTTP uses a pointer receiver because controller/scheduler are
// constructed once in Provision and must be shared, not copied, across
// concurrent requests.
type Handler struct {
	Config

	controller *Controller
	scheduler  *Scheduler

	// app is the adaptive_admission App this Handler registered itself
	// with in Provision (nil if that registration was skipped — see
	// Provision's doc — or if Provision never ran at all). Cleanup only
	// unregisters when non-nil.
	app *App

	// logger is set in Provision (nil-Context-safe via ctx.Logger()'s own
	// dev-logger fallback). Several existing unit tests construct a Handler
	// directly without ever calling Provision, so every use of logger below
	// guards against nil rather than assuming Provision ran.
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.adaptive_admission",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision constructs this instance's Controller and Scheduler fresh —
// mirroring fairness's scoringState placement (§7 Q6), this state is never
// carried over across a config reload (§3.3): every Provision call starts
// from configured defaults with brand-new background goroutines. It also
// registers this config load's Prometheus collectors (metrics.go) against
// ctx's registry, sets up structured logging (§4.9), and registers this
// instance with the adaptive_admission App so the admin API (admin.go, §4.10)
// can report its live state.
//
// The App registration is skipped when ctx is the zero-value caddy.Context
// (detected via the embedded ctx.Context field being nil, which no
// real Caddy-constructed Context ever is) — two of this file's own existing
// unit tests (TestHandler_ProvisionAndCleanup_FixedController,
// TestHandler_Provision_InvalidControllerConfigReturnsError) construct
// exactly such a Context directly, and caddy.Context.App panics on it (it
// dereferences a nil internal *caddy.Config). A production Provision call
// always carries a real Context from Caddy's own module-loading path, so
// this guard never affects real deployments — see metrics.go's near-identical
// comment for the same underlying hazard.
func (h *Handler) Provision(ctx caddy.Context) error {
	controller, err := h.Config.Controller.buildController()
	if err != nil {
		return err
	}

	initAdmissionMetrics(ctx.GetMetricsRegistry())
	h.logger = ctx.Logger()

	backend := h.Config.backendLabel()
	admissionMetrics.concurrencyLimit.WithLabelValues(backend).Set(float64(controller.Limit()))
	controller.SetOnLimitChange(func(oldLimit, newLimit int) {
		direction := "grow"
		if newLimit < oldLimit {
			direction = "shrink"
		}
		admissionMetrics.limitChanges.WithLabelValues(backend, direction).Inc()
		admissionMetrics.concurrencyLimit.WithLabelValues(backend).Set(float64(newLimit))
	})
	controller.Start()

	scheduler := NewScheduler(h.Config.queueConfig(), controller)
	scheduler.Start()

	h.controller = controller
	h.scheduler = scheduler

	if ctx.Context != nil {
		appIface, err := ctx.App("adaptive_admission")
		if err != nil {
			return err
		}
		app, ok := appIface.(*App)
		if !ok {
			return fmt.Errorf("adaptive_admission: unexpected app module type %T", appIface)
		}
		h.app = app
		app.registerHandler(backend, h)
	}

	return nil
}

// Cleanup stops this instance's scheduler and controller, in that order
// (the scheduler's dispatch loop must exit before the controller it drives
// is torn down), and unregisters it from the App if it was registered.
func (h *Handler) Cleanup() error {
	if h.scheduler != nil {
		h.scheduler.Stop()
	}
	if h.controller != nil {
		h.controller.Stop()
	}
	if h.app != nil {
		h.app.unregisterHandler(h.Config.backendLabel(), h)
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler. It reads the fairness
// score that fairness (or another earlier handler) set via caddyhttp.SetVar,
// enqueues the request, waits for admission, then dispatches (§4.5),
// recording metrics and emitting one structured log line per request (§4.8,
// §4.9).
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	backend := h.Config.backendLabel()
	admissionMetrics.requestsTotal.WithLabelValues(backend).Inc()

	score := neutralScore
	if v := caddyhttp.GetVar(r.Context(), fairnessScoreVarKey); v != nil {
		if f, ok := v.(float64); ok {
			score = f
		}
	}

	enqueuedAt := time.Now()
	ticket, reason := h.scheduler.Enqueue(score)
	admissionMetrics.queueSize.WithLabelValues(backend).Set(float64(h.scheduler.Depth()))

	if reason != RejectNone {
		admissionMetrics.requestsRejected.WithLabelValues(backend, reason.String()).Inc()
		h.logDecision(r, logDecisionParams{backend: backend, admitted: false, rejectReason: reason})
		return caddyhttp.Error(http.StatusTooManyRequests, fmt.Errorf("adaptive_admission: %s", reason))
	}

	<-ticket.Granted()
	queueWait := time.Since(enqueuedAt)
	admissionMetrics.queueWaitDuration.WithLabelValues(backend).Observe(queueWait.Seconds())
	admissionMetrics.requestsAdmitted.WithLabelValues(backend).Inc()
	// InFlight() can read up to 1 higher than genuinely in-flight work here
	// and below -- see Controller.InFlight's doc (capacity.go).
	admissionMetrics.requestsInFlight.WithLabelValues(backend).Set(float64(h.controller.InFlight()))

	outcome, err := h.dispatch(w, r, next)
	admissionMetrics.requestsInFlight.WithLabelValues(backend).Set(float64(h.controller.InFlight()))

	h.logDecision(r, logDecisionParams{
		backend:    backend,
		admitted:   true,
		queueWait:  queueWait,
		latency:    outcome.latency,
		statusCode: outcome.statusCode,
	})

	return err
}

// logDecisionParams carries the fields logDecision needs beyond what it
// reads from r's fairness_log_fields var.
type logDecisionParams struct {
	backend      string
	admitted     bool
	rejectReason RejectReason
	queueWait    time.Duration
	latency      time.Duration
	statusCode   int
}

// logDecision emits the single structured log line per admission decision
// (§4.9), folding in fairness's classification/score-breakdown fields (read
// via caddyhttp.GetVar, never a Go import of the fairness package — §3.4).
// A nil logger (a Handler used without Provision, as in several existing
// unit tests) makes this a no-op rather than panicking.
func (h *Handler) logDecision(r *http.Request, p logDecisionParams) {
	if h.logger == nil {
		return
	}
	fields := []zap.Field{
		zap.String("backend", p.backend),
		zap.Bool("admitted", p.admitted),
	}
	if p.admitted {
		fields = append(fields,
			zap.Int64("queue_wait_ms", p.queueWait.Milliseconds()),
			zap.Int64("backend_latency_ms", p.latency.Milliseconds()),
			zap.Int("status_code", p.statusCode),
		)
	} else {
		fields = append(fields, zap.String("reject_reason", p.rejectReason.String()))
	}

	if lf, ok := caddyhttp.GetVar(r.Context(), fairnessLogFieldsVarKey).(map[string]any); ok {
		if v, ok := lf["ip"].(string); ok {
			fields = append(fields, zap.String("ip", v))
		}
		if v, ok := lf["asn"].(uint64); ok {
			fields = append(fields, zap.Uint64("asn", v))
		}
		if v, ok := lf["country"].(string); ok {
			fields = append(fields, zap.String("country", v))
		}
		if v, ok := lf["user_class"].(string); ok {
			fields = append(fields, zap.String("user_class", v))
		}
		if v, ok := lf["exempt"].(bool); ok {
			fields = append(fields, zap.Bool("exempt", v))
		}
		if v, ok := lf["score_breakdown"].(map[string]float64); ok {
			fields = append(fields, zap.Any("score_breakdown", v))
		}
	}

	h.logger.Info("admission_decision", fields...)
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens, per the §5
// schema. Grammar:
//
//	adaptive_admission {
//	    controller fixed {
//	        limit <int>
//	    }
//	    # or:
//	    controller adaptive {
//	        min_concurrency        <int>
//	        initial_concurrency    <int>
//	        max_concurrency        <int>
//	        target_p95             <duration>
//	        timeout_rate_threshold <float>
//	        error_rate_threshold   <float>
//	        adjust_interval        <duration>
//	    }
//	    queue_max_size <int>
//	    queue_timeout  <duration>
//	}
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "backend":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.Backend = d.Val()

			case "controller":
				if err := h.unmarshalController(d); err != nil {
					return err
				}

			case "queue_max_size":
				if !d.NextArg() {
					return d.ArgErr()
				}
				n, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("invalid queue_max_size %q: %v", d.Val(), err)
				}
				h.QueueMaxSize = n

			case "queue_timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid queue_timeout %q: %v", d.Val(), err)
				}
				h.QueueTimeout = dur

			default:
				return d.Errf("unrecognized adaptive_admission subdirective '%s'", d.Val())
			}
		}
	}
	return nil
}

// unmarshalController parses a `controller fixed { ... }` or
// `controller adaptive { ... }` sub-block.
func (h *Handler) unmarshalController(d *caddyfile.Dispenser) error {
	args := d.RemainingArgs()
	if len(args) != 1 {
		return d.ArgErr()
	}
	kind := args[0]
	if kind != controllerKindFixed && kind != controllerKindAdaptive {
		return d.Errf("unrecognized controller kind %q (want %q or %q)", kind, controllerKindFixed, controllerKindAdaptive)
	}
	h.Controller.Kind = kind

	for d.NextBlock(1) {
		switch d.Val() {
		case "limit":
			if !d.NextArg() {
				return d.ArgErr()
			}
			n, err := strconv.Atoi(d.Val())
			if err != nil {
				return d.Errf("invalid limit %q: %v", d.Val(), err)
			}
			h.Controller.Limit = n

		case "min_concurrency":
			if !d.NextArg() {
				return d.ArgErr()
			}
			n, err := strconv.Atoi(d.Val())
			if err != nil {
				return d.Errf("invalid min_concurrency %q: %v", d.Val(), err)
			}
			h.Controller.MinConcurrency = n

		case "initial_concurrency":
			if !d.NextArg() {
				return d.ArgErr()
			}
			n, err := strconv.Atoi(d.Val())
			if err != nil {
				return d.Errf("invalid initial_concurrency %q: %v", d.Val(), err)
			}
			h.Controller.InitialConcurrency = n

		case "max_concurrency":
			if !d.NextArg() {
				return d.ArgErr()
			}
			n, err := strconv.Atoi(d.Val())
			if err != nil {
				return d.Errf("invalid max_concurrency %q: %v", d.Val(), err)
			}
			h.Controller.MaxConcurrency = n

		case "target_p95":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid target_p95 %q: %v", d.Val(), err)
			}
			h.Controller.TargetP95 = dur

		case "timeout_rate_threshold":
			if !d.NextArg() {
				return d.ArgErr()
			}
			f, err := strconv.ParseFloat(d.Val(), 64)
			if err != nil {
				return d.Errf("invalid timeout_rate_threshold %q: %v", d.Val(), err)
			}
			h.Controller.TimeoutRateThreshold = f

		case "error_rate_threshold":
			if !d.NextArg() {
				return d.ArgErr()
			}
			f, err := strconv.ParseFloat(d.Val(), 64)
			if err != nil {
				return d.Errf("invalid error_rate_threshold %q: %v", d.Val(), err)
			}
			h.Controller.ErrorRateThreshold = f

		case "adjust_interval":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid adjust_interval %q: %v", d.Val(), err)
			}
			h.Controller.AdjustInterval = dur

		default:
			return d.Errf("unrecognized controller subdirective '%s'", d.Val())
		}
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Handler
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return &m, err
}

// Interface guards.
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)
