FROM golang:1.25-alpine AS build
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/pds-pro ./cmd/pds-pro

# Build goat alongside so the runtime image has both binaries available.
FROM golang:1.25-alpine AS goat-build
RUN apk add --no-cache git
ARG GOAT_VERSION=v0.2.3
WORKDIR /src
RUN git clone https://github.com/bluesky-social/goat.git . && git checkout ${GOAT_VERSION}
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/goat .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates dumb-init && adduser -D -u 10001 sgcadmin
COPY --from=build /out/pds-pro /usr/local/bin/pds-pro
COPY --from=goat-build /out/goat /usr/local/bin/goat
COPY web/templates /app/web/templates
WORKDIR /app
USER sgcadmin
EXPOSE 8080
ENTRYPOINT ["dumb-init", "--"]
CMD ["pds-pro", "--config", "/etc/pds-pro/config.yaml", "--templates", "/app/web/templates"]

LABEL org.opencontainers.image.source=https://github.com/P3X-118/pds-pro
LABEL org.opencontainers.image.description="SGC PDS admin web UX wrapping goat pds admin"
LABEL org.opencontainers.image.licenses=MIT
