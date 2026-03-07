FROM golang:1.26.1-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o servworx .

FROM alpine:3.19
RUN apk add --no-cache docker-cli

WORKDIR /app
COPY --from=builder /app/servworx .
COPY --from=builder /app/templates /app/templates

EXPOSE 5000
CMD ["./servworx"]