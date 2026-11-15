# Build the manager binary
FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine3.24@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS builder
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
FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

ENV USER_UID=2001 \
    USER_NAME=appuser \
    GROUP_NAME=appuser

WORKDIR /
COPY --from=builder --chown=${USER_UID} /workspace/version_exporter /version_exporter

USER ${USER_UID}

ENTRYPOINT [ "/version_exporter" ]
