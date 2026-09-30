FROM golang:alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o vortexdns -ldflags="-w -s" .

FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata bind-tools bash jq

WORKDIR /app
COPY --from=builder /app/vortexdns .
COPY scripts/vortex-reset.sh /usr/local/bin/vortex-reset
COPY scripts/entrypoint.sh /usr/local/bin/entrypoint
RUN chmod +x /usr/local/bin/vortex-reset /usr/local/bin/entrypoint

# Bundle default offline blocklist into a seed dir. The entrypoint copies it
# into the mounted volume on first run (the volume would otherwise hide it).
COPY vortex_db/lists/82bbcf0fb464ac35c8f796c63097bbbb.txt /app/seed/lists/82bbcf0fb464ac35c8f796c63097bbbb.txt

RUN mkdir -p /app/vortex_db /app/logs

# DNS, DoH, DoT/DoQ, dashboard
EXPOSE 53/udp 53/tcp
EXPOSE 443/tcp
EXPOSE 853/tcp 853/udp
EXPOSE 8080/tcp

# Forgot the password? From the host:
#   docker compose exec vortexdns vortex-reset --password   # with VORTEX_ADMIN_PASSWORD set
#   docker compose exec -it vortexdns vortex-reset          # interactive menu
ENTRYPOINT ["/usr/local/bin/entrypoint"]
