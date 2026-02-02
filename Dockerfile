# Build the manager binary
FROM --platform=$BUILDPLATFORM golang:1.25.6-alpine3.22 AS builder
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
FROM alpine:3.23.2

ENV USER_UID=2001 \
    USER_NAME=appuser \
    GROUP_NAME=appuser

WORKDIR /
COPY --from=builder --chown=${USER_UID} /workspace/version_exporter /version_exporter

USER ${USER_UID}

ENTRYPOINT [ "/version_exporter" ]
