# syntax=docker/dockerfile:1.18@sha256:dabfc0969b935b2080555ace70ee69a5261af8a8f1b4df97b9e7fbcf6722eddf

FROM golang:1.26.7-alpine3.24@sha256:28d89ee9cc0ff9fec75c82ca201e6bf7fdf9a679d4b7b24dfa04f2bb766bb468 AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/servworx ./cmd/servworx \
    && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/servworx-docker-broker ./cmd/servworx-docker-broker

FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS runtime

RUN apk upgrade --no-cache \
    && apk add --no-cache ca-certificates \
    && addgroup -S -g 65532 servworx \
    && adduser -S -D -H -u 65532 -G servworx servworx

FROM runtime AS app

WORKDIR /app
COPY --from=builder --chown=65532:65532 --chmod=0555 /out/servworx /usr/local/bin/servworx
COPY --from=builder --chown=65532:65532 /src/templates ./templates
COPY --from=builder --chown=65532:65532 /src/static ./static
RUN mkdir -p /app/config && chown 65532:65532 /app/config

USER 65532:65532
EXPOSE 5000
ENTRYPOINT ["/usr/local/bin/servworx"]

FROM runtime AS broker

COPY --from=builder --chown=65532:65532 --chmod=0555 /out/servworx-docker-broker /usr/local/bin/servworx-docker-broker
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/servworx-docker-broker"]
