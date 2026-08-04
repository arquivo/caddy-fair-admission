package adaptiveadmission

import (
	"fmt"
	"time"
)

const (
	controllerKindFixed    = "fixed"
	controllerKindAdaptive = "adaptive"
)

// Config is the adaptive_admission handler's configuration surface for
// capacity control (§4.4) and the priority queue/scheduler (§4.5, §5). It is
// embedded directly in Handler so both Caddyfile (via UnmarshalCaddyfile)
// and JSON config flow through the same struct.
//
// Load balancing and dispatch (§4.6/§4.7) are deliberately NOT configured
// here, even though REQUIREMENTS.md §5's illustrative sketch nests
// upstream/backup_upstream/connect_timeout/backend_timeout/sticky_sessions
// fields inside the adaptive_admission block (that sketch explicitly leaves
// open whether "adaptive_admission composes with reverse_proxy directly").
// This module instead relies on Caddy's own reverse_proxy directive, chained
// immediately afterward via RegisterDirectiveOrder (module.go) — ServeHTTP's
// next.ServeHTTP call *is* that reverse_proxy handler. This avoids
// re-implementing reverse_proxy's upstream/health-check/stickiness surface
// and matches Phase 8's own "fairness + adaptive_admission + reverse_proxy
// chained" done-when wording literally.
type Config struct {
	Controller ControllerConfig `json:"controller,omitempty"`

	// QueueMaxSize is QueueConfig.MaxSize (§4.5). Zero/unset means
	// unbounded.
	QueueMaxSize int `json:"queue_max_size,omitempty"`
	// QueueTimeout is QueueConfig.WaitTimeout (§4.5). Zero/unset means the
	// Little's-law wait-projection check never rejects.
	QueueTimeout time.Duration `json:"queue_timeout,omitempty"`
}

// ControllerConfig selects and tunes the backend's Controller (capacity.go,
// §4.4).
type ControllerConfig struct {
	// Kind is "fixed" or "adaptive". Empty defaults to "fixed".
	Kind string `json:"kind,omitempty"`

	// Limit is the static concurrency limit, for kind=fixed only.
	Limit int `json:"limit,omitempty"`

	// The remaining fields apply only to kind=adaptive; see AdaptiveConfig
	// (capacity.go) for their meaning.
	MinConcurrency       int           `json:"min_concurrency,omitempty"`
	InitialConcurrency   int           `json:"initial_concurrency,omitempty"`
	MaxConcurrency       int           `json:"max_concurrency,omitempty"`
	TargetP95            time.Duration `json:"target_p95,omitempty"`
	TimeoutRateThreshold float64       `json:"timeout_rate_threshold,omitempty"`
	ErrorRateThreshold   float64       `json:"error_rate_threshold,omitempty"`
	AdjustInterval       time.Duration `json:"adjust_interval,omitempty"`
}

// buildController constructs the Controller this config describes.
func (cc ControllerConfig) buildController() (*Controller, error) {
	switch cc.Kind {
	case "", controllerKindFixed:
		if cc.Limit <= 0 {
			return nil, fmt.Errorf("adaptive_admission: fixed controller requires limit > 0")
		}
		return NewFixedController(cc.Limit), nil

	case controllerKindAdaptive:
		if cc.MinConcurrency <= 0 || cc.InitialConcurrency <= 0 || cc.MaxConcurrency <= 0 {
			return nil, fmt.Errorf("adaptive_admission: adaptive controller requires min_concurrency, initial_concurrency, and max_concurrency > 0")
		}
		return NewAdaptiveController(AdaptiveConfig{
			MinConcurrency:       cc.MinConcurrency,
			InitialConcurrency:   cc.InitialConcurrency,
			MaxConcurrency:       cc.MaxConcurrency,
			TargetP95:            cc.TargetP95,
			TimeoutRateThreshold: cc.TimeoutRateThreshold,
			ErrorRateThreshold:   cc.ErrorRateThreshold,
			AdjustInterval:       cc.AdjustInterval,
		}), nil

	default:
		return nil, fmt.Errorf("adaptive_admission: unrecognized controller kind %q", cc.Kind)
	}
}

// queueConfig derives this handler's QueueConfig (queue.go).
func (c Config) queueConfig() QueueConfig {
	return QueueConfig{MaxSize: c.QueueMaxSize, WaitTimeout: c.QueueTimeout}
}
