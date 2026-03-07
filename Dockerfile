FROM golang:1.26.1-alpine AS builder

WORKDIR /app
COPY go.mod ./
# RUN go mod download (if there are external dependencies)
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o servworx .

FROM alpine:latest
RUN apk add --no-cache docker-cli

WORKDIR /app
COPY --from=builder /app/servworx .
COPY --from=builder /app/templates /app/templates

EXPOSE 5000
CMD ["./servworx"]