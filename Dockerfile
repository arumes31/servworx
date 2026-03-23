FROM golang:1.26.1-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o servworx .

FROM alpine@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659
RUN apk add --no-cache docker-cli

WORKDIR /app
COPY --from=builder /app/servworx .
COPY --from=builder /app/templates /app/templates

EXPOSE 5000
CMD ["./servworx"]