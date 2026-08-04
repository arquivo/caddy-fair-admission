// Package adaptiveadmission implements the http.handlers.adaptive_admission
// Caddy module: capacity control, priority queue/scheduler, and dispatch
// (REQUIREMENTS.md §4.4-§4.7).
package adaptiveadmission

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
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
// from configured defaults with brand-new background goroutines.
func (h *Handler) Provision(_ caddy.Context) error {
	controller, err := h.Config.Controller.buildController()
	if err != nil {
		return err
	}
	controller.Start()

	scheduler := NewScheduler(h.Config.queueConfig(), controller)
	scheduler.Start()

	h.controller = controller
	h.scheduler = scheduler
	return nil
}

// Cleanup stops this instance's scheduler and controller, in that order
// (the scheduler's dispatch loop must exit before the controller it drives
// is torn down).
func (h *Handler) Cleanup() error {
	if h.scheduler != nil {
		h.scheduler.Stop()
	}
	if h.controller != nil {
		h.controller.Stop()
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler. It reads the fairness
// score that fairness (or another earlier handler) set via caddyhttp.SetVar,
// enqueues the request, waits for admission, then dispatches (§4.5).
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	score := neutralScore
	if v := caddyhttp.GetVar(r.Context(), fairnessScoreVarKey); v != nil {
		if f, ok := v.(float64); ok {
			score = f
		}
	}

	ticket, reason := h.scheduler.Enqueue(score)
	if reason != RejectNone {
		return caddyhttp.Error(http.StatusTooManyRequests, fmt.Errorf("adaptive_admission: %s", reason))
	}

	<-ticket.Granted()
	return h.dispatch(w, r, next)
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
