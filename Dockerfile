FROM golang:1.26.9-alpine@sha256:3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o servworx ./cmd/servworx

FROM alpine@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache docker-cli 'libcrypto3>=3.5.9-r0' 'libssl3>=3.5.9-r0'

WORKDIR /app
COPY --from=builder /app/servworx .
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static
RUN mkdir -p /app/config

EXPOSE 5000
CMD ["./servworx"]