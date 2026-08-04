package fairness

import "github.com/caddyserver/caddy/v2"

func init() {
	caddy.RegisterModule(App{})
}

// App is the fairness app module (namespace "fairness"). It will hold the
// GeoIP DB readers and JWKS refresh loops, deduped by resource identity
// across fairness handler blocks (REQUIREMENTS.md §3.1). Currently a no-op
// scaffold.
type App struct{}

// CaddyModule returns the Caddy module information.
func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "fairness",
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
