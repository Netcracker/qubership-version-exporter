FROM golang:1.24.2-alpine3.21 AS builder

ENV SOURCES_DIR=./cmd/qubership-version-exporter \
    GO111MODULE=on

WORKDIR /workspace

COPY go.mod go.mod
COPY go.sum go.sum

RUN go mod download
COPY collector/ collector/
COPY cmd/ cmd/
COPY model/ model/
COPY validation/ validation/

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o qubership-version-exporter ${SOURCES_DIR}/

FROM alpine:3.21.3

WORKDIR /qubership-version-exporter
ENV USER_UID=2001 \
    USER_NAME=appuser \
    GROUP_NAME=appuser

COPY --from=builder /workspace/qubership-version-exporter /qubership-version-exporter/

RUN chmod +x  /qubership-version-exporter/qubership-version-exporter \
    && addgroup ${GROUP_NAME} \
    && adduser -D -G ${GROUP_NAME} -u ${USER_UID} ${USER_NAME}

USER ${USER_UID}

ENTRYPOINT [ "/qubership-version-exporter/qubership-version-exporter" ]

