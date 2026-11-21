# syntax=docker/dockerfile:1.7
# One Dockerfile, one target per deployable:
#   core       ivar-core service and the attack replay library runner
#   sensors    Linux host agent, network, database, log collector, AI gateway
#   control    ivar-control (policy, TUF, flags, plugins) and the replay runner
#   connectors ivar-connector (cloud, identity, Kubernetes, telco, indicators)
#   edge-filter  the proxy-wasm filter as an OCI image for Istio WasmPlugin
#
#   docker build -f deploy/docker/Dockerfile --target core -t ivar/core .

FROM rust:1.97-bookworm AS rust
WORKDIR /src
RUN rustup target add wasm32-wasip1
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY sensors sensors
COPY proto proto
COPY third_party third_party
COPY replay-library replay-library
RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/src/target \
    cargo build --release --locked \
      -p ivar-server -p ivar-linux-agent -p ivar-network-sensor -p ivar-database-sensor -p ivar-log-collector -p ivar-ai-gateway \
 && cargo build --release --locked -p ivar-abi -p ivar-edge-filter --target wasm32-wasip1 \
 && mkdir -p /out/bin /out/wasm /out/empty \
 && cp target/release/ivar-core target/release/ivar-replay-library target/release/ivar-linux-agent target/release/ivar-network-sensor \
       target/release/ivar-database-sensor target/release/ivar-log-collector target/release/ivar-ai-gateway /out/bin/ \
 && cp target/wasm32-wasip1/release/ivar_abi.wasm /out/wasm/ivar_core.wasm \
 && cp target/wasm32-wasip1/release/ivar_edge_filter.wasm /out/wasm/plugin.wasm

FROM golang:1.24-bookworm AS go
WORKDIR /src
COPY sdk/go sdk/go
COPY go go
COPY --from=rust /out/wasm/ivar_core.wasm sdk/go/wasm/ivar_core.wasm
RUN --mount=type=cache,target=/root/go/pkg/mod cd go \
 && CGO_ENABLED=0 go build -trimpath -o /out/ivar-control ./cmd/ivar-control \
 && CGO_ENABLED=0 go build -trimpath -o /out/ivar-connector ./cmd/ivar-connector

FROM gcr.io/distroless/cc-debian12:nonroot AS core
COPY --from=rust /out/bin/ivar-core /out/bin/ivar-replay-library /usr/local/bin/
COPY replay-library /usr/share/ivar/replay-library
# The evidence directory exists in the image and belongs to nonroot, so a
# fresh volume mounted there is writable without running as root.
COPY --from=rust --chown=65532:65532 /out/empty /var/lib/ivar
USER nonroot
EXPOSE 8080 7443
ENTRYPOINT ["/usr/local/bin/ivar-core"]
CMD ["serve", "--config", "/etc/ivar/core.yaml"]

# The host agent needs root and host namespaces; the chart grants them only to
# the DaemonSet.
FROM debian:bookworm-slim AS sensors
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates nftables && rm -rf /var/lib/apt/lists/*
COPY --from=rust /out/bin/ivar-linux-agent /out/bin/ivar-network-sensor /out/bin/ivar-database-sensor /out/bin/ivar-log-collector /out/bin/ivar-ai-gateway /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/ivar-linux-agent"]

FROM gcr.io/distroless/cc-debian12:nonroot AS control
COPY --from=go /out/ivar-control /usr/local/bin/ivar-control
COPY --from=rust /out/bin/ivar-replay-library /usr/local/bin/ivar-replay-library
COPY replay-library /usr/share/ivar/replay-library
USER nonroot
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/ivar-control"]
CMD ["serve", "--bundle", "/etc/ivar/policy/policy.bundle", "--tuf-keys", "/etc/ivar/tuf", "--flags-key", "/etc/ivar/keys/flags-1.seed", "--operators", "/etc/ivar/operators.json", "--cosign", "/etc/ivar/keys/cosign.pub"]

FROM gcr.io/distroless/static-debian12:nonroot AS connectors
COPY --from=go /out/ivar-connector /usr/local/bin/ivar-connector
USER nonroot
EXPOSE 8085
ENTRYPOINT ["/usr/local/bin/ivar-connector"]

# Istio WasmPlugin and Envoy OCI image layout: a single plugin.wasm.
FROM scratch AS edge-filter
COPY --from=rust /out/wasm/plugin.wasm /plugin.wasm
