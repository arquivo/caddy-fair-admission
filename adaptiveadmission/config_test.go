package adaptiveadmission

import (
	"testing"
	"time"
)

func TestControllerConfig_BuildController_FixedRequiresPositiveLimit(t *testing.T) {
	cases := []struct {
		name    string
		cfg     ControllerConfig
		wantErr bool
	}{
		{"zero limit", ControllerConfig{Kind: controllerKindFixed, Limit: 0}, true},
		{"negative limit", ControllerConfig{Kind: controllerKindFixed, Limit: -1}, true},
		{"valid limit", ControllerConfig{Kind: controllerKindFixed, Limit: 10}, false},
		{"empty kind defaults to fixed, valid limit", ControllerConfig{Limit: 10}, false},
		{"empty kind defaults to fixed, invalid limit", ControllerConfig{Limit: 0}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := tc.cfg.buildController()
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("buildController: %v", err)
			}
			if got := c.Kind(); got != ControllerFixed {
				t.Errorf("Kind() = %v, want %v", got, ControllerFixed)
			}
			if got := c.Limit(); got != tc.cfg.Limit {
				t.Errorf("Limit() = %d, want %d", got, tc.cfg.Limit)
			}
		})
	}
}

func TestControllerConfig_BuildController_AdaptiveRequiresConcurrencyBounds(t *testing.T) {
	base := ControllerConfig{
		Kind:                 controllerKindAdaptive,
		MinConcurrency:       5,
		InitialConcurrency:   20,
		MaxConcurrency:       100,
		TargetP95:            500 * time.Millisecond,
		TimeoutRateThreshold: 0.1,
		ErrorRateThreshold:   0.1,
		AdjustInterval:       10 * time.Second,
	}

	cases := []struct {
		name    string
		mutate  func(cc *ControllerConfig)
		wantErr bool
	}{
		{"valid", func(cc *ControllerConfig) {}, false},
		{"zero min_concurrency", func(cc *ControllerConfig) { cc.MinConcurrency = 0 }, true},
		{"zero initial_concurrency", func(cc *ControllerConfig) { cc.InitialConcurrency = 0 }, true},
		{"zero max_concurrency", func(cc *ControllerConfig) { cc.MaxConcurrency = 0 }, true},
		{"negative min_concurrency", func(cc *ControllerConfig) { cc.MinConcurrency = -1 }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cc := base
			tc.mutate(&cc)
			c, err := cc.buildController()
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("buildController: %v", err)
			}
			if got := c.Kind(); got != ControllerAdaptive {
				t.Errorf("Kind() = %v, want %v", got, ControllerAdaptive)
			}
			if got := c.Limit(); got != cc.InitialConcurrency {
				t.Errorf("Limit() = %d, want initial concurrency %d", got, cc.InitialConcurrency)
			}
		})
	}
}

func TestControllerConfig_BuildController_UnrecognizedKind(t *testing.T) {
	cc := ControllerConfig{Kind: "bogus", Limit: 10}
	if _, err := cc.buildController(); err == nil {
		t.Fatal("expected an error for unrecognized kind, got nil")
	}
}

func TestConfig_QueueConfig(t *testing.T) {
	c := Config{QueueMaxSize: 100, QueueTimeout: 5 * time.Second}
	got := c.queueConfig()
	want := QueueConfig{MaxSize: 100, WaitTimeout: 5 * time.Second}
	if got != want {
		t.Errorf("queueConfig() = %+v, want %+v", got, want)
	}
}
