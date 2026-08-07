## [3.0.0](https://github.com/arquivo/caddy-fair-admission/compare/v2.1.0...v3.0.0) (2026-08-07)


### ⚠ BREAKING CHANGES

* **fairness:** the top-level `exempt_country` Caddyfile directive is removed. Move it onto the relevant `penalty <dimension>` line(s) as exempt_country=<cc>[,<cc>...].

### Code Refactoring

* **fairness:** make exempt_country a per-penalty-dimension arg ([a479629](https://github.com/arquivo/caddy-fair-admission/commit/a4796295497962b4c3f9a0c8b055f9fc86d32bb5))

## [2.1.0](https://github.com/arquivo/caddy-fair-admission/compare/v2.0.0...v2.1.0) (2026-08-07)


### Features

* **fairness:** add presence-based priority divisor to scoring block ([94d4ab8](https://github.com/arquivo/caddy-fair-admission/commit/94d4ab8284214f6f56be29bee3ede43d5a254196))

## [2.0.0](https://github.com/arquivo/caddy-fair-admission/compare/v1.1.0...v2.0.0) (2026-08-07)


### ⚠ BREAKING CHANGES

* **fairness:** the `net24`/`net6` scoring dimension names are renamed to `ipv4_subnet`/`ipv6_subnet` across the Caddyfile `penalty` directive, the JSON config surface, and admin API output. Existing Caddyfiles using `penalty net24`/`penalty net6` must be updated to `penalty ipv4_subnet`/`penalty ipv6_subnet`; no backward-compatible alias is provided.

### Code Refactoring

* **fairness:** rename net24/net6 scoring dimensions to ipv4_subnet/ipv6_subnet ([f971840](https://github.com/arquivo/caddy-fair-admission/commit/f97184054e522933f4ec8728bd26cfbf084895bd))

## [1.1.0](https://github.com/arquivo/caddy-fair-admission/compare/v1.0.0...v1.1.0) (2026-08-07)


### Features

* **fairness:** make scoring dimensions opt-in via `penalty <dim>` ([9f520d5](https://github.com/arquivo/caddy-fair-admission/commit/9f520d50ffb8cf2ce3fb51311bc5068c127dd385))

## 1.0.0 (2026-08-06)


### Features

* add Dockerfile to build caddy with this module via xcaddy ([3a1a12d](https://github.com/arquivo/caddy-fair-admission/commit/3a1a12d0e42bb0c9e10602fd7c2a1baa60317595))
* **adaptive-admission:** wire fairness -> adaptive_admission -> reverse_proxy end-to-end ([f9930fe](https://github.com/arquivo/caddy-fair-admission/commit/f9930fe8c4fbdf6ae954ae70740bf7dd96ba34ea))
* **adaptive_admission:** add bounded priority queue/scheduler ([49c1110](https://github.com/arquivo/caddy-fair-admission/commit/49c111070a8fc76bb963d0f93a1d93262d5074a7))
* **adaptive_admission:** add fixed/adaptive capacity controller ([aff3441](https://github.com/arquivo/caddy-fair-admission/commit/aff3441c49773226dde6a540a9ffc2fc21c1f27d))
* **admin:** add per-backend introspection API for both modules ([14749ae](https://github.com/arquivo/caddy-fair-admission/commit/14749ae64694019d8c4761fdd6f8b8e8bb2e32bc))
* **fairness:** add EWMA-based scoring and penalty computation ([9843244](https://github.com/arquivo/caddy-fair-admission/commit/9843244f4826d7ff4ff337d6b0b1930f8ecd4a08))
* **fairness:** add ingress consumption and request classification ([96ca2c9](https://github.com/arquivo/caddy-fair-admission/commit/96ca2c95b7afc1c70686bdac4bf58773245a45c5))
* **loadtest:** add concurrency ramp/sweep tool and full-chain validation ([e4e9de0](https://github.com/arquivo/caddy-fair-admission/commit/e4e9de0e9e459e9e8e59de87511d57df05057c1e))
* **metrics:** register 14-metric surface and structured admission logging ([314cbb6](https://github.com/arquivo/caddy-fair-admission/commit/314cbb64da885e1c8a01e3734f19040223bf310a))
* **scaffold:** register no-op fairness and adaptive_admission modules ([b7927bf](https://github.com/arquivo/caddy-fair-admission/commit/b7927bf320fa2c974a6df72ad726ca1b91a6b7cb))
