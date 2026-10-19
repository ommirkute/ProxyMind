# ProxyMind container image: the proxy, web UI, API, MCP server and a
# headless Chromium for XSS proofs.
#
#   docker build -t proxymind .
#   docker run --rm -it -v proxymind:/data \
#     -p 127.0.0.1:7777:7777 -p 127.0.0.1:8080:8080 proxymind
#
# First give the project its rules of engagement:
#   docker run --rm -v proxymind:/data -v "$PWD/roe.yaml:/roe.yaml:ro" proxymind roe use /roe.yaml
# The login link is printed by `docker logs`. Publish ports on 127.0.0.1
# only: the UI and proxy are for you, not your network. Behind a TLS-intercepting proxy, pass its CA to the build with
#   --secret id=extra_ca,src=/path/to/ca.pem

# ---- web UI ---------------------------------------------------------------
FROM node:22-bookworm-slim AS ui
WORKDIR /src/ui
COPY ui/package.json ui/package-lock.json ./
RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -f /run/secrets/extra_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/extra_ca; fi; \
    npm ci --no-audit --no-fund
COPY ui/ ./
RUN npm run build

# ---- binary ---------------------------------------------------------------
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
COPY --from=ui /src/ui/dist ui/dist
RUN --mount=type=secret,id=extra_ca,required=false \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    if [ -f /run/secrets/extra_ca ]; then \
      cat /run/secrets/extra_ca >> /etc/ssl/certs/ca-certificates.crt; \
    fi; \
    cargo build --release --locked -p pm-cli && cp target/release/proxymind /usr/local/bin/proxymind

# ---- runtime --------------------------------------------------------------
FROM debian:bookworm-slim
ARG WITH_CHROMIUM=true
RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -f /run/secrets/extra_ca ]; then \
      mkdir -p /etc/apt/apt.conf.d && echo 'Acquire::https::CaInfo "/run/secrets/extra_ca";' > /etc/apt/apt.conf.d/99ca; \
    fi; \
    apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tini \
    && if [ "$WITH_CHROMIUM" = "true" ]; then apt-get install -y --no-install-recommends chromium fonts-liberation; fi \
    && rm -rf /var/lib/apt/lists/* /etc/apt/apt.conf.d/99ca \
    && useradd --create-home --uid 10001 proxymind \
    && mkdir -p /data && chown proxymind /data
COPY --from=build /usr/local/bin/proxymind /usr/local/bin/proxymind
# Chromium's own sandbox needs user namespaces, which Docker's default
# seccomp profile blocks; the container is the isolation boundary here, and
# XSS proofs block all page traffic anyway (ADR-0011).
ENV PROXYMIND_PROJECT=/data/project.pmproj \
    PROXYMIND_HOME=/data/home \
    PROXYMIND_CHROMIUM=/usr/bin/chromium \
    PROXYMIND_CHROMIUM_NO_SANDBOX=1
USER proxymind
WORKDIR /data
VOLUME ["/data"]
EXPOSE 7777 8080
ENTRYPOINT ["/usr/bin/tini", "--", "proxymind"]
CMD ["ui", "--listen", "0.0.0.0:7777", "--proxy", "0.0.0.0:8080", "--bind-any"]
