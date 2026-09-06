FROM golang:1.25-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG GIT_COMMIT=unknown
ARG BUILD_TIME=unknown
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/suoten/serverguard/internal/version.GitCommit=${GIT_COMMIT} -X github.com/suoten/serverguard/internal/version.BuildTime=${BUILD_TIME}" -o serverguard-agent ./cmd/serverguard-agent
ARG GIT_COMMIT=unknown
ARG BUILD_TIME=unknown
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/suoten/serverguard/internal/version.GitCommit=${GIT_COMMIT} -X github.com/suoten/serverguard/internal/version.BuildTime=${BUILD_TIME}" -o serverguard-hub ./cmd/serverguard-hub
ARG GIT_COMMIT=unknown
ARG BUILD_TIME=unknown
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/suoten/serverguard/internal/version.GitCommit=${GIT_COMMIT} -X github.com/suoten/serverguard/internal/version.BuildTime=${BUILD_TIME}" -o sgctl ./cmd/sgctl

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /opt/serverguard
COPY --from=builder /build/serverguard-agent /opt/serverguard/serverguard-agent
COPY --from=builder /build/serverguard-hub /opt/serverguard/serverguard-hub
COPY --from=builder /build/sgctl /usr/local/bin/sgctl
COPY configs/ /opt/serverguard/configs/

ENTRYPOINT ["/opt/serverguard/serverguard-agent"]
CMD ["-config", "/opt/serverguard/configs/serverguard-agent.yaml"]