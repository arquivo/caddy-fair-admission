package adaptiveadmission

import "github.com/caddyserver/caddy/v2"

func init() {
	caddy.RegisterModule(App{})
}

// App is the adaptive_admission app module (namespace "adaptive_admission").
// It will hold per-backend capacity-controller state and load-balancer state
// (REQUIREMENTS.md §3.1). Currently a no-op scaffold.
type App struct{}

// CaddyModule returns the Caddy module information.
func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "adaptive_admission",
		New: func() caddy.Module { return new(App) },
	}
}

// Start starts the app module.
func (a *App) Start() error {
	return nil
}

// Stop stops the app module.
func (a *App) Stop() error {
	return nil
}

// Interface guards.
var _ caddy.App = (*App)(nil)
