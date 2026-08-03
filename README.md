# caddy-adaptive-admission-controller

A native [Caddy](https://caddyserver.com/) module implementing adaptive, p95-latency-driven
admission control (concurrency limiting, EWMA-based scoring/penalties, priority queueing, and
least-in-flight load balancing) in front of arquivo.pt's backends.

This is a from-scratch Go port of an existing Python system
(`adaptive-admission-controller`, FastAPI/Starlette), designed to run as goroutines inside the
same `caddy` process that fronts arquivo.pt — replacing a standalone uvicorn process — once the
Apache→Caddy web-server migration lands.

## Status

Planning stage — no module code has been written yet. See [REQUIREMENTS.md](REQUIREMENTS.md) for
the full functional spec, architecture shape, and open design questions.

## Contributing

This repository enforces [Conventional Commits](https://www.conventionalcommits.org/) on every
pull request via commitlint (see `.github/workflows/commitlint.yml`). Format commit messages as:

```
<type>(<optional scope>): <description>
```

Common types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`.
