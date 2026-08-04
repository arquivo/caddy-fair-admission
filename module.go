// Package caddyaac blank-imports both fairness and adaptive_admission so a
// single `xcaddy build --with github.com/arquivo/caddy-adaptive-admission-controller`
// pulls in both modules (REQUIREMENTS.md §3.4). Either subpackage remains
// independently importable on its own.
package caddyaac

import (
	_ "github.com/arquivo/caddy-adaptive-admission-controller/adaptiveadmission"
	_ "github.com/arquivo/caddy-adaptive-admission-controller/fairness"
)
