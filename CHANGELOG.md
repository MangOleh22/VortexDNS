# Changelog — VortexDNS (Branch: development)

Semua perubahan yang tercatat di branch `development`.

---

## [Unreleased] — Rencana

- **Migrasi API dashboard ke Rust** — Opsi arsitektur & trade-off didokumentasikan di
  `rencana_migrasi_rust.md`. Belum diputuskan/dieksekusi.

---

## 2026-09-30

### Dihapus — Fitur Scanner & AI Detection (di luar konteks)
- **Package `scanner/` dihapus total** — Website Intelligence & URL Scanner, AI stack
  detection, Lighthouse, TLS/tech/secret scanning, report engine (PDF/JSON/CSV/JSONL).
  Di luar konteks kebutuhan DNS server.
- **Dashboard**: hapus field `scannerMgr`, semua route `/api/v1/scans*`, handler scanner,
  metrik scanner Prometheus, import `vortexdns/scanner` + `path/filepath` yang tak terpakai.
- **Web UI**: hapus halaman "Website Intelligence" (nav, page, tab, view) di index.html
  dan seluruh logika `wiState`/scanner di app.js (~960 baris).
- **Docs**: hapus `SCANNER_SECURITY.md`, `AI_DETECTION.md`, `PRODUCT_QUALITY_SCORECARD.md`,
  `WEB_INTELLIGENCE_ARCHITECTURE.md`, `SCAN_SCHEMA.md`, `OBSERVABILITY_ARCHITECTURE.md`.
- **OpenAPI**: hapus semua path `/api/v1/scans*` dan skema Scan/ScanReport/Lighthouse/dll
  (docs + web).
- **Cleanup**: hapus dir `vortex_db/scans`, `vortex_db/reports` + aturan `.gitignore` terkait.
- Build + `go vet` + `go test` bersih; endpoint scanner kini 404; DNS & dashboard tetap jalan.

### Perbaikan Bug (dari testing)
- **Blocklist lokal tak ter-load** — Path relatif seperti `vortex_db/lists/…` dikira URL
  remote (gagal download). Ditambah `isLocalPath()`: apa pun yang bukan `http(s)://`
  diperlakukan sebagai file lokal. Test `updater_test.go` ditambahkan.
- **Blocklist bundled ke-hide volume** — File di image tertutup oleh mount `vortex_data`.
  Ditambah `scripts/entrypoint.sh` yang men-seed blocklist bundled dari `/app/seed/lists`
  ke volume saat pertama jalan (tak menimpa yang sudah ada). Dockerfile pakai ENTRYPOINT.
  Hasil: 2130 rules ter-load, domain blocklist (mis. `tracking.miui.com`) → NXDOMAIN.

---

## 2026-09-29

### Fitur Baru — Storage SQLite (Fase 1-5, LENGKAP)
- **Package `storage/`** — SQLite embedded (WAL mode) via `modernc.org/sqlite`
  (pure-Go, tanpa CGO). File tunggal `vortex_db/vortex.db`. Tabel terindeks:
  `query_log`, `audit_log`, `stats_hourly`, `accounts`.
- **Query log → SQLite** — Tiap query DNS di-mirror ke tabel `query_log` via query hook
  di `advanced.WriteAccessLog` (`SetQueryHook`). access.log file tetap ditulis (backward compat).
- **Stats per-jam → SQLite** — `stats_hourly` di-upsert tiap query (total, blocked,
  avg latency, unique clients). Bertahan antar-restart.
- **Akun admin → SQLite** — Login & setup memakai tabel `accounts` (source of truth),
  di-mirror ke config.json. Migrasi otomatis akun lama dari config.json saat pertama jalan.
  `-reset-password` juga sinkron ke SQLite.
- **Audit log persisten** — Ditulis ke SQLite via `recordAudit()`, `/api/audit` baca dari DB.
- **Auto-prune** — Query log & stats di-prune per jam sesuai `stats_retention_hours` (default 24).
- **WAL mode** — Baca & tulis konkuren tanpa blocking, crash-safe (seperti Pi-hole).
- Unit test `storage_test.go` — open, tabel, insert/select query+audit+stats+accounts. PASS.

---

## 2026-09-26

### Fitur Baru
- **First-run setup otomatis** — Fresh install menghasilkan `config.json` dengan admin
  kosong (`admin_username: ""`, `admin_password_hash: ""`). Server masuk mode setup:
  user buat akun admin sendiri lewat dashboard, tidak ada kredensial default.
- **Auto-generate session secret** — `session_secret` di-generate random (32-byte hex)
  saat pertama load. Config lama dengan placeholder `vortex-secret-change-me` di-upgrade
  otomatis, lalu disimpan.
- **config.example.json** — Template konfigurasi kosongan dengan upstream DNS default
  (1.1.1.1, 8.8.8.8, 9.9.9.9) dan blocklist manual bawaan. User cukup
  `cp config.example.json config.json`.

### Perubahan UI (Halaman Login)
- **Ikon toggle password** — Diganti dari emoji (👁/🙈) ke **SVG mata** (Feather-style).
  Mata terbuka = password tersembunyi, mata dicoret = password terlihat.
- **Hapus live strip** — Kotak bawah login (queries/blocked/latency/uptime) dihapus
  seluruhnya beserta div `login-strip`.
- **Hapus baris versi di footer** — `VortexDNS v1.0.0 · HG680P · <clock>` dihapus.
  Tersisa hanya `DNS · DoH · DoT · DoQ · Recursive · DNSSEC`.

### Perubahan Backend
- **`config.go` — `generateSessionSecret()`** ditambahkan dan di-wire di `Load()`:
  - Fresh install: secret random langsung di-set.
  - Config existing: placeholder di-upgrade + di-persist otomatis.

### Dokumentasi Baru
- **README.md** — Ikhtisar proyek, quick-start Docker, tabel port, link ke INSTALL.md.
- **INSTALL.md** — Ditambah:
  - Bagian 0: "Menyiapkan Berkas Konfigurasi" (`cp config.example.json config.json`).
  - Bagian 6: "Setup Awal (First-Run)" — alur buat akun admin sendiri.
  - Docker Compose langkah `cp` template.
- **LICENSE.md** — MIT License (2026 MangOleh22).
- **SECURITY.md** — Kebijakan keamanan, cara lapor via GitHub Security Advisories,
  cakupan, praktik keamanan (jangan commit config.json).
- **CODE_OF_CONDUCT.md** — Contributor Covenant v1.4 (bahasa Indonesia).
- **CONTRIBUTING.md** — Panduan kontribusi: cara lapor bug, usul fitur, alur PR
  (fork dari `development`), standar kode Go.

### Repo & Deploy
- **Blocklist manual** (`vortex_db/lists/82bbcf0fb464ac35c8f796c63097bbbb.txt`) —
  Disertakan di repo (2717 domain: YouTube, Spotify, Xiaomi tracking, dll).
  `.gitignore` dikecualikan khusus untuk file ini.
- **`.gitignore`** — `config.json` (rahasia), `vortex_db/` (runtime kecuali blocklist
  manual + `.gitkeep`), binary `vortexdns`, `*.log` dikecualikan.
- **Push ke GitHub** — https://github.com/MangOleh22/VortexDNS branch `development`.

---

## Riwayat Commit

| Commit | Pesan |
|--------|-------|
| `4eb456a` | feat: sertakan blocklist manual di repo, jadikan default di config.example.json |
| `9935b70` | docs: add CONTRIBUTING guide |
| `e615a99` | docs: add LICENSE (MIT), SECURITY, CODE_OF_CONDUCT |
| `391b309` | docs: langkah salin config.example.json ke config.json |
| `f4537dd` | chore: add config.example.json, keep vortex_db structure |
| `79bfbc6` | docs: add README |
| `448e04c` | VortexDNS: adblocking DNS server with dashboard, DoH/DoT/DoQ, first-run setup |
