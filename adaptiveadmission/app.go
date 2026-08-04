package adaptiveadmission

import (
	"sort"
	"sync"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(new(App))
}

// App is the adaptive_admission app module (namespace "adaptive_admission").
// It holds a registry of this config load's Handler instances, keyed by
// backend label, so the admin introspection API (admin.go, §4.10) can report
// live per-backend controller/queue state without a bespoke pubsub mechanism.
// Load-balancer/upstream state is deliberately not tracked here — see
// admin.go's doc comment.
type App struct {
	mu       sync.Mutex
	handlers map[string]*Handler
}

// CaddyModule returns the Caddy module information.
func (*App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "adaptive_admission",
		New: func() caddy.Module { return new(App) },
	}
}

// Provision initializes the handler registry.
func (a *App) Provision(_ caddy.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.handlers = make(map[string]*Handler)
	return nil
}

// Start starts the app module.
func (a *App) Start() error {
	return nil
}

// Stop stops the app module.
func (a *App) Stop() error {
	return nil
}

// registerHandler records h as the live Handler for backend, overwriting any
// previous registration under the same label (a config reload replaces
// rather than accumulates).
func (a *App) registerHandler(backend string, h *Handler) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.handlers == nil {
		a.handlers = make(map[string]*Handler)
	}
	a.handlers[backend] = h
}

// unregisterHandler removes backend's registration, if h is still the
// currently-registered Handler for it (guards against a Cleanup racing a
// newer Provision during a reload from clobbering the newer registration).
func (a *App) unregisterHandler(backend string, h *Handler) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.handlers[backend] == h {
		delete(a.handlers, backend)
	}
}

// snapshotHandlers returns the currently registered Handlers, sorted by
// backend label for deterministic admin API output.
func (a *App) snapshotHandlers() []*Handler {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]*Handler, 0, len(a.handlers))
	for _, h := range a.handlers {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Config.backendLabel() < out[j].Config.backendLabel()
	})
	return out
}

// Interface guards.
var (
	_ caddy.App         = (*App)(nil)
	_ caddy.Provisioner = (*App)(nil)
)
