# VortexDNS

Server DNS adblocking berperforma tinggi dengan dashboard web modern, mendukung
DNS klasik, DoH, DoT, DoQ, recursive resolver, dan DNSSEC.

> DNS · DoH · DoT · DoQ · Recursive · DNSSEC

---

## Fitur Utama

- **Adblocking** — blocklist remote (StevenBlack dkk) + blacklist/whitelist kustom, wildcard, regex.
- **Protokol lengkap** — DNS (UDP/TCP), DNS-over-HTTPS, DNS-over-TLS, DNS-over-QUIC.
- **Recursive resolver** + DNSSEC validation.
- **Dashboard web** — statistik real-time, query log, manajemen rules, clients, upstream, cache.
- **Keamanan** — Safe Browsing, parental control, DNS rebinding protection, ACL allow/deny.
- **Lanjutan** — conditional forwarding, split-horizon, zone records, block page, Prometheus metrics.
- **First-run setup** — tanpa kredensial default; admin dibuat sendiri saat pertama jalan.

---

## Mulai Cepat (Docker)

```bash
git clone https://github.com/MangOleh22/VortexDNS.git
cd VortexDNS
docker compose up -d --build
```

Port default (bisa diubah di [`docker-compose.yml`](docker-compose.yml)):

| Layanan   | Host        | Container |
|-----------|-------------|-----------|
| DNS       | `10053`     | `53`      |
| Dashboard | `18080`     | `8080`    |

Buka dashboard: `http://localhost:18080`

Saat pertama kali, halaman login menampilkan form **Buat Akun** — buat username &
password admin Anda sendiri. Tidak ada kredensial default.

---

## Instalasi

Panduan lengkap (skrip otomatis, manual/systemd, Docker/Podman/Kubernetes, reset
password, uninstall) ada di [INSTALL.md](INSTALL.md).

---

## Konfigurasi

Semua pengaturan disimpan di `config.json` (di-generate otomatis saat pertama jalan).
Kolom penting:

- `bind_address` — alamat listen DNS (mis. `:53`, `:5353`)
- `dashboard_address` — alamat dashboard (mis. `0.0.0.0:8080`)
- `upstream_servers` — DNS upstream (Cloudflare, Google, Quad9 sbg default)
- `blocklist_urls`, `custom_blacklist`, `custom_whitelist`
- `doh_enabled` / `dot_enabled` / `doq_enabled` + alamat masing-masing
- `dnssec_enabled`, `recursive_resolver`

`config.json` **tidak** disertakan di repo (berisi hash password & session secret);
file di-generate lokal saat pertama dijalankan.

---

## Reset Password

```bash
# Docker
docker compose exec -it vortexdns vortex-reset

# systemd
sudo vortex-reset
```

Detail (non-interaktif, Kubernetes) di [INSTALL.md — Bagian 4](INSTALL.md).

---

## Build dari Sumber

```bash
CGO_ENABLED=0 go build -ldflags="-s -w" -o vortexdns .
```

Butuh Go >= 1.21.

---

## Lisensi

Dirilis di bawah [Lisensi MIT](LICENSE.md).
