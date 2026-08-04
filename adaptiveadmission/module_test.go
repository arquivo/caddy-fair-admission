package adaptiveadmission

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func newVarsRequest(score *float64) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	vars := map[string]any{}
	if score != nil {
		vars[fairnessScoreVarKey] = *score
	}
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
	return req.WithContext(ctx)
}

// --- ServeHTTP: dispatch + capacity release -----------------------------------

func TestHandler_ServeHTTP_DispatchesAndReleasesCapacityOnSuccess(t *testing.T) {
	c := NewFixedController(1)
	s := NewScheduler(QueueConfig{MaxSize: 10}, c)
	s.Start()
	defer s.Stop()

	h := &Handler{controller: c, scheduler: s}

	req := newVarsRequest(nil)
	rec := httptest.NewRecorder()
	called := false
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		w.WriteHeader(http.StatusCreated)
		return nil
	})

	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if !called {
		t.Fatal("next handler was not called")
	}
	if got := c.InFlight(); got != 0 {
		t.Errorf("InFlight() after ServeHTTP returned = %d, want 0 (capacity released)", got)
	}
	if got := c.window.total; got != 1 {
		t.Fatalf("outcome window total = %d, want 1", got)
	}
	if last := c.window.ring[(c.window.pos+c.window.size-1)%c.window.size]; last.isError {
		t.Errorf("recorded outcome isError = true for a 201 response, want false")
	}
}

func TestHandler_ServeHTTP_RejectsQueueFull_As429(t *testing.T) {
	c := NewFixedController(1)
	c.Acquire(1) // hold the only slot permanently; dispatch loop never started

	s := NewScheduler(QueueConfig{MaxSize: 1}, c)
	// Fill the queue directly (depth 0 -> 1), without ever starting the
	// dispatch loop -- mirrors queue_test.go's TestScheduler_RejectsQueueFull.
	if _, reason := s.Enqueue(1); reason != RejectNone {
		t.Fatalf("seed Enqueue rejected: %v", reason)
	}

	h := &Handler{controller: c, scheduler: s}

	req := newVarsRequest(nil)
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		t.Fatal("next must not be called when the request is rejected")
		return nil
	})

	err := h.ServeHTTP(rec, req, next)
	if err == nil {
		t.Fatal("expected an error for a queue-full rejection, got nil")
	}
	var he caddyhttp.HandlerError
	if !errors.As(err, &he) {
		t.Fatalf("ServeHTTP error = %v, want a caddyhttp.HandlerError", err)
	}
	if he.StatusCode != http.StatusTooManyRequests {
		t.Errorf("StatusCode = %d, want %d", he.StatusCode, http.StatusTooManyRequests)
	}
}

func TestHandler_ServeHTTP_UpstreamHandlerError_ClassifiesGatewayTimeout(t *testing.T) {
	c := NewFixedController(1)
	s := NewScheduler(QueueConfig{MaxSize: 10}, c)
	s.Start()
	defer s.Stop()

	h := &Handler{controller: c, scheduler: s}

	req := newVarsRequest(nil)
	rec := httptest.NewRecorder()
	upstreamErr := caddyhttp.Error(http.StatusGatewayTimeout, errors.New("boom"))
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return upstreamErr
	})

	err := h.ServeHTTP(rec, req, next)
	if !errors.Is(err, upstreamErr) {
		t.Fatalf("ServeHTTP returned %v, want the upstream error passed through unchanged", err)
	}
	if got := c.window.timeouts; got != 1 {
		t.Errorf("recorded timeouts = %d, want 1", got)
	}
	if got := c.InFlight(); got != 0 {
		t.Errorf("InFlight() after ServeHTTP returned = %d, want 0 (capacity released even on error)", got)
	}
}

// --- ServeHTTP: fairness_score var read + fail-open + priority ordering ------

func TestHandler_ServeHTTP_NoScoreVarSet_DoesNotPanicAndDispatches(t *testing.T) {
	c := NewFixedController(1)
	s := NewScheduler(QueueConfig{MaxSize: 10}, c)
	s.Start()
	defer s.Stop()

	h := &Handler{controller: c, scheduler: s}

	req := newVarsRequest(nil)
	rec := httptest.NewRecorder()
	called := false
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})

	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if !called {
		t.Fatal("next handler was not called")
	}
}

func TestHandler_ServeHTTP_PrioritizesHigherScoreUnderSaturation(t *testing.T) {
	c := NewFixedController(1)
	c.Acquire(1) // hold the only slot so nothing dispatches until released
	s := NewScheduler(QueueConfig{MaxSize: 10}, c)
	s.Start()
	defer func() {
		c.Release(1, time.Millisecond, 200, false)
		s.Stop()
	}()

	h := &Handler{controller: c, scheduler: s}

	var dispatchOrder []string
	var mu = make(chan struct{}, 1)
	mu <- struct{}{}
	recordDispatch := func(name string) {
		<-mu
		dispatchOrder = append(dispatchOrder, name)
		mu <- struct{}{}
	}
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		recordDispatch(r.Header.Get("X-Name"))
		return nil
	})

	lowScore, highScore := 1.0, 10.0
	lowReq := newVarsRequest(&lowScore)
	lowReq.Header.Set("X-Name", "low")
	highReq := newVarsRequest(&highScore)
	highReq.Header.Set("X-Name", "high")

	lowDone := make(chan struct{})
	highDone := make(chan struct{})

	go func() {
		if err := h.ServeHTTP(httptest.NewRecorder(), lowReq, next); err != nil {
			t.Errorf("low-score ServeHTTP: %v", err)
		}
		close(lowDone)
	}()
	// Ensure the low-score request is enqueued first (arrives earlier),
	// before the high-score request arrives -- this deliberately tests that
	// a later-arriving higher score still wins, not FIFO order.
	time.Sleep(20 * time.Millisecond)
	go func() {
		if err := h.ServeHTTP(httptest.NewRecorder(), highReq, next); err != nil {
			t.Errorf("high-score ServeHTTP: %v", err)
		}
		close(highDone)
	}()
	time.Sleep(20 * time.Millisecond)

	// Free the one slot the test held: the dispatch loop should now acquire
	// it and pop the current highest-priority (high-score) ticket first.
	c.Release(1, time.Millisecond, 200, false)

	select {
	case <-highDone:
	case <-time.After(time.Second):
		t.Fatal("high-score request never dispatched")
	}
	select {
	case <-lowDone:
	case <-time.After(time.Second):
		t.Fatal("low-score request never dispatched")
	}

	if len(dispatchOrder) != 2 || dispatchOrder[0] != "high" || dispatchOrder[1] != "low" {
		t.Errorf("dispatch order = %v, want [high low]", dispatchOrder)
	}
}

// --- Provision / Cleanup lifecycle --------------------------------------------

func TestHandler_ProvisionAndCleanup_FixedController(t *testing.T) {
	h := &Handler{Config: Config{Controller: ControllerConfig{Kind: controllerKindFixed, Limit: 5}}}
	if err := h.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if h.controller == nil || h.scheduler == nil {
		t.Fatal("Provision did not populate controller/scheduler")
	}
	if got := h.controller.Limit(); got != 5 {
		t.Errorf("Limit() = %d, want 5", got)
	}
	if err := h.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
}

func TestHandler_Provision_InvalidControllerConfigReturnsError(t *testing.T) {
	h := &Handler{Config: Config{Controller: ControllerConfig{Kind: controllerKindFixed}}} // Limit unset
	if err := h.Provision(caddy.Context{}); err == nil {
		t.Fatal("expected an error for a fixed controller with limit <= 0, got nil")
	}
}

func TestHandler_Cleanup_SafeWithoutProvision(t *testing.T) {
	h := &Handler{}
	if err := h.Cleanup(); err != nil {
		t.Fatalf("Cleanup on an unprovisioned Handler: %v", err)
	}
}

// --- Caddyfile parsing ---------------------------------------------------------

func TestUnmarshalCaddyfile_ControllerFixed(t *testing.T) {
	input := `adaptive_admission {
		controller fixed {
			limit 50
		}
		queue_max_size 500
		queue_timeout 10s
	}`
	d := caddyfile.NewTestDispenser(input)
	var h Handler
	if err := h.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}
	if h.Controller.Kind != controllerKindFixed {
		t.Errorf("Controller.Kind = %q, want %q", h.Controller.Kind, controllerKindFixed)
	}
	if h.Controller.Limit != 50 {
		t.Errorf("Controller.Limit = %d, want 50", h.Controller.Limit)
	}
	if h.QueueMaxSize != 500 {
		t.Errorf("QueueMaxSize = %d, want 500", h.QueueMaxSize)
	}
	if h.QueueTimeout != 10*time.Second {
		t.Errorf("QueueTimeout = %v, want 10s", h.QueueTimeout)
	}
}

func TestUnmarshalCaddyfile_ControllerAdaptive(t *testing.T) {
	input := `adaptive_admission {
		controller adaptive {
			min_concurrency        10
			initial_concurrency    40
			max_concurrency        200
			target_p95             800ms
			timeout_rate_threshold 0.05
			error_rate_threshold   0.05
			adjust_interval        30s
		}
	}`
	d := caddyfile.NewTestDispenser(input)
	var h Handler
	if err := h.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}
	want := ControllerConfig{
		Kind:                 controllerKindAdaptive,
		MinConcurrency:       10,
		InitialConcurrency:   40,
		MaxConcurrency:       200,
		TargetP95:            800 * time.Millisecond,
		TimeoutRateThreshold: 0.05,
		ErrorRateThreshold:   0.05,
		AdjustInterval:       30 * time.Second,
	}
	if h.Controller != want {
		t.Errorf("Controller = %+v, want %+v", h.Controller, want)
	}
}

func TestUnmarshalCaddyfile_Controller_UnrecognizedKind(t *testing.T) {
	input := `adaptive_admission {
		controller bogus {
			limit 5
		}
	}`
	var h Handler
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
		t.Fatal("expected error for unrecognized controller kind, got nil")
	}
}

func TestUnmarshalCaddyfile_Controller_UnrecognizedSubdirective(t *testing.T) {
	input := `adaptive_admission {
		controller fixed {
			not_a_real_thing 1
		}
	}`
	var h Handler
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
		t.Fatal("expected error for unrecognized controller subdirective, got nil")
	}
}

func TestUnmarshalCaddyfile_UnrecognizedTopLevelDirective(t *testing.T) {
	input := `adaptive_admission {
		not_a_real_directive foo
	}`
	var h Handler
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
		t.Fatal("expected error for unrecognized subdirective, got nil")
	}
}

func TestUnmarshalCaddyfile_NonNumericLimit(t *testing.T) {
	input := `adaptive_admission {
		controller fixed {
			limit notanumber
		}
	}`
	var h Handler
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
		t.Fatal("expected error for non-numeric limit, got nil")
	}
}
