# syntax=docker/dockerfile:1

# Builder stage: caddy's own official xcaddy-equipped image, pinned to the
# same Caddy version this module is built/tested against (see go.mod's
# github.com/caddyserver/caddy/v2 requirement) so the compiled plugin ABI
# always matches the base Caddy it's embedded into.
FROM caddy:2.11.4-builder AS builder

WORKDIR /src
COPY . .

# Build against this checkout (`=/src`) rather than a tagged release on the
# module proxy, so a local/in-progress change to fairness or
# adaptive_admission is always what ends up in the image. xcaddy writes the
# binary to the current directory (./caddy, i.e. /src/caddy here), not
# /usr/bin/caddy -- that only gets overwritten in the final stage below.
RUN xcaddy build \
	--with github.com/arquivo/caddy-adaptive-admission-controller=/src

# Runtime stage: caddy's own minimal runtime image, unchanged except for the
# custom-built binary swapped in. Inherits the base image's user, entrypoint,
# and default `caddy run --config /etc/caddy/Caddyfile --adapter caddyfile`.
FROM caddy:2.11.4

COPY --from=builder /src/caddy /usr/bin/caddy
