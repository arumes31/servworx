FROM golang:1.26.4-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o servworx ./cmd/servworx

FROM alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
RUN apk add --no-cache docker-cli

WORKDIR /app
COPY --from=builder /app/servworx .
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static
RUN mkdir -p /app/config

EXPOSE 5000
CMD ["./servworx"]