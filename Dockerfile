FROM node:24-alpine AS web
WORKDIR /src
COPY web/package.json ./web/
RUN cd web && npm install --no-audit --no-fund
COPY web/ ./web/
COPY scripts/Connect-Server.ps1 ./scripts/Connect-Server.ps1
RUN node web/build.mjs

FROM golang:1.26-alpine AS test
WORKDIR /src
COPY go.mod ./
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN go test ./... && go vet ./...

FROM test AS api
RUN CGO_ENABLED=0 go build -trimpath -o /out/sentinel ./cmd/sentinel

FROM alpine:3.22
RUN apk add --no-cache ca-certificates openssh-client-default && addgroup -S -g 65532 sentinel && adduser -S -D -H -u 65532 -G sentinel sentinel && mkdir -p /app/data && chown 65532:65532 /app/data
WORKDIR /app
COPY --from=api /out/sentinel /usr/local/bin/sentinel
COPY --from=web /src/web/dist /app/web/dist
COPY config/agent-linux.yaml /app/config/agent-linux.yaml
USER 65532:65532
ENV MONITOR_ADDR=:8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/sentinel"]
