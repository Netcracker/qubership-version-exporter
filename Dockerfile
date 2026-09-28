# Build the manager binary
FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine3.24@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS builder
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH

ENV SOURCES_DIR=./cmd/qubership-version-exporter \
    GO111MODULE=on

WORKDIR /workspace

# Copy the Go sources
COPY go.* /workspace
COPY cmd/ cmd/
COPY pkg/ pkg/

# Build
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o version_exporter ${SOURCES_DIR}/

# Use alpine tiny images as a base
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

ENV USER_UID=2001 \
    USER_NAME=appuser \
    GROUP_NAME=appuser

WORKDIR /
COPY --from=builder --chown=${USER_UID} /workspace/version_exporter /version_exporter

USER ${USER_UID}

ENTRYPOINT [ "/version_exporter" ]
