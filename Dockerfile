# syntax=docker/dockerfile:1

# ============================================================
#  NetCut control plane
#  Multi-stage: build the static binary, ship it on a minimal
#  base. The dashboard is embedded in the binary, so the runtime
#  image needs no assets, no Node, and no package manager.
# ============================================================

FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_TIME=unknown

WORKDIR /src

# Dependencies first: this layer only rebuilds when go.mod/go.sum change.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO is off so the result is a static binary: the SQLite driver is pure Go
# (modernc.org/sqlite) and the dashboard is embedded. That keeps the runtime
# image free of any libc variant and makes cross-arch builds trivial.
ENV CGO_ENABLED=0
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
        -trimpath \
        -ldflags "-s -w \
            -X github.com/kevinantoniowiyonolauw/netcut/internal/version.Version=${VERSION} \
            -X github.com/kevinantoniowiyonolauw/netcut/internal/version.Commit=${COMMIT} \
            -X github.com/kevinantoniowiyonolauw/netcut/internal/version.BuildTime=${BUILD_TIME}" \
        -o /out/netcut ./cmd/netcut

# ---- runtime ----
FROM alpine:3.21

# ca-certificates is required: the container talks to the agent over HTTPS and
# the agent's reverse path may be verified. tzdata makes log timestamps local.
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -S -g 10001 netcut \
 && adduser  -S -u 10001 -G netcut -h /data -s /sbin/nologin netcut \
 && mkdir -p /data \
 && chown -R netcut:netcut /data

COPY --from=build /out/netcut /usr/local/bin/netcut

# The service runs unprivileged. The data volume is the only writable path.
USER netcut:netcut

ENV NETCUT_ADDR=:8080 \
    NETCUT_DB=/data/netcut.db \
    NETCUT_DATA_DIR=/data \
    NETCUT_LOG_LEVEL=info \
    TZ=Asia/Jakarta

VOLUME ["/data"]
EXPOSE 8080

# The binary probes its own endpoint, so the healthcheck needs no curl in the
# image and stays correct if the listen address is overridden.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/netcut", "-healthcheck"]

ENTRYPOINT ["/usr/local/bin/netcut"]
