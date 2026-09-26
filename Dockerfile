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
RUN chmod +x /usr/local/bin/vortex-reset

RUN mkdir -p /app/vortex_db /app/logs

# DNS, DoH, DoT/DoQ, dashboard
EXPOSE 53/udp 53/tcp
EXPOSE 443/tcp
EXPOSE 853/tcp 853/udp
EXPOSE 8080/tcp

# Forgot the password? From the host:
#   docker compose exec vortexdns vortex-reset --password   # with VORTEX_ADMIN_PASSWORD set
#   docker compose exec -it vortexdns vortex-reset          # interactive menu
CMD ["./vortexdns"]
