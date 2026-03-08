FROM golang:1.24.3 AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -o /out/server ./cmd/server && \
    CGO_ENABLED=0 go build -o /out/apikeyctl ./cmd/apikeyctl

FROM alpine:3.22

RUN addgroup -S app && adduser -S app -G app

WORKDIR /app

COPY --from=builder /out/server /usr/local/bin/server
COPY --from=builder /out/apikeyctl /usr/local/bin/apikeyctl
COPY models ./models
RUN mkdir -p /app/storage && chown -R app:app /app

USER app

EXPOSE 8080

ENV LISTEN_ADDR=:8080 \
    DATABASE_PATH=/app/storage/llm_guard.db \
    CLASSIFIER_PATH=/app/models/classifier_v1.json \
    GEOIP_DB_PATH=/app/storage/GeoLite2-Country.mmdb \
    FAIL_CLOSED=true \
    TRUST_PROXY_HEADERS=false

ENTRYPOINT ["/usr/local/bin/server"]
