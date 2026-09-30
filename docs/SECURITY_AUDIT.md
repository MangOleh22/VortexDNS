# Audit Keamanan & Kualitas Kode — VortexDNS

> Tanggal audit: 2026-09-30 · Cakupan: web/dashboard, core DNS, blocker, cache,
> scanner, config, main, storage. Metode: telaah kode manual + `go vet` + `go test`.

## Ringkasan Eksekutif

Kode VortexDNS secara umum **solid dan aman**. Fondasi keamanan sudah benar:
proteksi SSRF lengkap, TLS 1.3, hashing bcrypt, cookie `HttpOnly`+`Secure`+`SameSite=Strict`,
token sesi via `crypto/rand`, rate limiter DNS dengan proteksi anti-OOM, panic recovery,
dan tidak ada SQL injection / command injection / path traversal.

Audit menemukan **10 hal** untuk diperbaiki: 5 prioritas sedang, 5 prioritas rendah.
Tidak ada temuan kritis (tidak ada RCE, tidak ada auth bypass, tidak ada kebocoran ke publik).

---

## Daftar Temuan

| # | Prioritas | Area | Ringkasan |
|---|-----------|------|-----------|
| 1 | 🔴 Sedang | web | CORS `Access-Control-Allow-Origin: *` di API terautentikasi |
| 2 | 🔴 Sedang | web/auth | Endpoint login tanpa rate-limit (rentan brute-force) |
| 3 | 🔴 Sedang | web/auth | `rand.Read` tidak dicek error saat generate token sesi |
| 7 | 🔴 Sedang | web/auth | Token sesi bocor memori (tidak ada cleanup periodik) |
| 8 | 🔴 Sedang | web | Tombol restart mati di Docker (`systemctl` tak ada) |
| 10 | 🟡 Rendah | web | Config GET membocorkan `admin_password_hash` + `session_secret` ke frontend |
| 4 | 🟡 Rendah | scanner | `go vet`: format `%s:%d` salah untuk alamat IPv6 |
| 5 | 🟡 Rendah | web/config | Path `config.json` di-hardcode (11 lokasi), abaikan flag `-config` |
| 9 | 🟡 Rendah | web/auth | Endpoint setup tanpa rate-limit / proteksi race |
| 6 | 🟡 Rendah | semua | Sebagian file belum `gofmt` |

---

## Detail Temuan

### 🔴 #1 — CORS wildcard di API terautentikasi
- **Lokasi**: [dashboard.go:306](file:///root/vortexdns/dashboard/dashboard.go#L306),
  [dashboard.go:554](file:///root/vortexdns/dashboard/dashboard.go#L554) (`writeJSON`).
- **Masalah**: Semua respons mengirim `Access-Control-Allow-Origin: *`.
- **Dampak**: Terbatas — auth memakai cookie `SameSite=Strict`, sehingga browser
  tidak mengirim kredensial pada request lintas-situs. Bukan celah langsung, tapi
  praktik buruk pada API admin.
- **Rekomendasi**: Hapus header CORS wildcard, atau batasi ke origin sendiri.

### 🔴 #2 — Login tanpa rate-limit
- **Lokasi**: [handleAuthLogin](file:///root/vortexdns/dashboard/dashboard.go#L436).
- **Masalah**: Tidak ada throttle/lockout untuk percobaan gagal. bcrypt memperlambat
  tiap percobaan, tapi tidak menghentikan brute-force otomatis.
- **Rekomendasi**: Rate-limit per-IP (mis. 5 gagal / menit) atau backoff progresif.

### 🔴 #3 — `rand.Read` tidak dicek error
- **Lokasi**: [dashboard.go:505](file:///root/vortexdns/dashboard/dashboard.go#L505).
- **Masalah**: Jika RNG gagal (sangat jarang), token bisa lemah.
- **Rekomendasi**: Cek error; tolak login (HTTP 500) bila gagal.

### 🔴 #7 — Token sesi bocor memori
- **Lokasi**: `sessionTokens` map, [dashboard.go:508](file:///root/vortexdns/dashboard/dashboard.go#L508).
- **Masalah**: Pembersihan hanya lazy (saat token diakses). Token yang tak pernah
  dipakai lagi menetap di memori sampai proses mati.
- **Rekomendasi**: Goroutine cleanup periodik (pola sama seperti `RateLimiter`).

### 🔴 #8 — Restart service mati di Docker
- **Lokasi**: [dashboard.go:866](file:///root/vortexdns/dashboard/dashboard.go#L866).
- **Masalah**: `systemctl restart vortexdns.service` gagal senyap di container
  (tak ada systemd). Error `.Run()` diabaikan.
- **Rekomendasi**: Deteksi lingkungan; di container `os.Exit(0)` dan andalkan
  `restart: unless-stopped` pada compose.

### 🟡 #10 — Config GET membocorkan rahasia
- **Lokasi**: [handleAdvancedConfig](file:///root/vortexdns/dashboard/dashboard.go#L873).
- **Masalah**: `writeJSON(w, 200, ds.cfg)` mengirim seluruh struct termasuk
  `admin_password_hash` dan `session_secret`. Hanya admin login yang bisa akses,
  tapi rahasia tak seharusnya dikirim ke frontend.
- **Rekomendasi**: Salin config ke DTO tanpa field sensitif sebelum kirim.

### 🟡 #4 — `go vet`: format IPv6
- **Lokasi**: [scanner/tls.go:18](file:///root/vortexdns/scanner/tls.go#L18).
- **Masalah**: `fmt.Sprintf("%s:%d", host, port)` salah untuk IPv6.
- **Rekomendasi**: Pakai `net.JoinHostPort(host, strconv.Itoa(port))`.

### 🟡 #5 — Path config.json hardcoded
- **Lokasi**: 11 lokasi di dashboard.go (mis. baris 454, 964, 1321, …).
- **Masalah**: `config.Save("config.json", …)` mengabaikan flag `-config`. Jika
  server dijalankan dengan config di path lain, perubahan lewat dashboard tersimpan
  ke lokasi salah.
- **Rekomendasi**: Simpan `configPath` di struct `DashboardServer`, pakai di semua Save.

### 🟡 #9 — Setup tanpa proteksi
- **Lokasi**: [handleAuthSetup](file:///root/vortexdns/dashboard/dashboard.go#L394).
- **Masalah**: Sebelum admin dibuat, siapa pun dengan akses port bisa membuat akun
  admin lebih dulu (race).
- **Rekomendasi**: Lakukan setup hanya di jaringan tepercaya (sudah didokumentasikan
  di INSTALL.md), atau tambahkan token setup opsional.

### 🟡 #6 — gofmt
- **Lokasi**: beberapa file (blocker, cache, dashboard, main, scanner).
- **Masalah**: Kosmetik; tak memengaruhi fungsi.
- **Rekomendasi**: Jalankan `gofmt -w .`.

---

## Yang Sudah Aman (Terverifikasi)

- **SSRF**: [ValidateTargetURL](file:///root/vortexdns/scanner/ssrf.go#L181) memblok
  IP privat/loopback/link-local/cloud-metadata (IPv4 & IPv6), userinfo, skema non-http.
- **SQL injection**: nihil — semua query SQLite parameterized (`?` placeholder).
- **Command injection**: nihil — `exec.Command` memakai argumen array, bukan shell.
- **Path traversal**: nihil — tidak ada `filepath.Join` dari input mentah pengguna.
- **TLS**: `MinVersion: tls.VersionTLS13` untuk DoH/DoT/DoQ.
- **Password**: bcrypt (`DefaultCost`), token sesi `crypto/rand` 32-byte.
- **Cookie**: `HttpOnly`, `Secure`, `SameSite=Strict`, TTL 24 jam.
- **DoS**: rate limiter DNS + cap 100k IP anti-OOM; `MaxBytesReader` 5 MB pada body JSON;
  cache dengan eviksi per-shard.
- **Panic recovery**: middleware `recover()` di pipeline `ServeDNS`.
- **`InsecureSkipVerify: true`** pada [scanner/tls.go:22](file:///root/vortexdns/scanner/tls.go#L22)
  adalah **disengaja** (scanner memeriksa & memvalidasi sertifikat secara manual untuk
  laporan) — bukan celah.

---

## Rencana Perbaikan (usulan urutan)

1. #10 bocor rahasia (cepat, penting) → mask field sensitif.
2. #3 cek `rand.Read` (cepat).
3. #7 cleanup sesi periodik.
4. #2 rate-limit login.
5. #8 restart Docker-aware.
6. #5 config path dari flag.
7. #1 CORS.
8. #4 IPv6 format + #9 setup note + #6 gofmt.

> [!NOTE]
> Semua temuan berada di lapisan dashboard/scanner. Core DNS resolver, blocker,
> cache, dan storage SQLite tidak memiliki temuan keamanan.
