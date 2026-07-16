# Build the manager binary
FROM --platform=$BUILDPLATFORM golang:1.26.5-alpine3.23@sha256:622e56dbc11a8cfe87cafa2331e9a201877271cbff918af53d3be315f3da88cc AS builder
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
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

ENV USER_UID=2001 \
    USER_NAME=appuser \
    GROUP_NAME=appuser

WORKDIR /
COPY --from=builder --chown=${USER_UID} /workspace/version_exporter /version_exporter

USER ${USER_UID}

ENTRYPOINT [ "/version_exporter" ]
