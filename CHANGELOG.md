# Changelog — VortexDNS (Branch: development)

Semua perubahan yang tercatat di branch `development`.

---

## [Unreleased] — Rencana

- **Migrasi storage SQLite (lanjutan)** — Fase 3-5: query log, stats historis, akun &
  blocklist metadata akan menyusul dipindah ke SQLite. Rencana detail di `rencana_sqlite.md`.

---

## 2026-09-29

### Fitur Baru — Storage SQLite (Fase 1-2)
- **Package `storage/`** — Fondasi SQLite embedded (WAL mode) via `modernc.org/sqlite`
  (pure-Go, tanpa CGO). File tunggal `vortex_db/vortex.db`. Tabel: `query_log`,
  `audit_log`, `stats_hourly` (semua terindeks).
- **Audit log persisten** — Sebelumnya in-memory (hilang saat restart). Sekarang ditulis
  ke SQLite via `recordAudit()`, dibaca `/api/audit` dari DB. Bertahan antar-restart.
- **WAL mode** — Baca & tulis konkuren tanpa blocking, crash-safe (seperti Pi-hole).
- Unit test `storage_test.go` — verifikasi open, create tabel, insert/select. PASS.

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
