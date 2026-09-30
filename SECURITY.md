# Kebijakan Keamanan (Security Policy)

## Versi yang Didukung

| Versi   | Didukung          |
|---------|-------------------|
| 1.0.x   | ✅ Ya             |
| < 1.0   | ❌ Tidak          |

## Melaporkan Kerentanan (Reporting a Vulnerability)

Kami menanggapi laporan keamanan dengan serius. **Jangan** membuka Issue publik
untuk kerentanan keamanan.

Cara melapor:
1. Gunakan **GitHub Security Advisories** — buka tab **Security → Report a vulnerability**
   di repositori: https://github.com/MangOleh22/VortexDNS/security/advisories/new
2. Sertakan sebanyak mungkin detail:
   - Deskripsi kerentanan dan dampaknya
   - Langkah reproduksi (proof-of-concept bila ada)
   - Versi/commit yang terpengaruh
   - Konfigurasi terkait (tanpa menyertakan kredensial asli)

## Waktu Tanggapan

- **Konfirmasi penerimaan**: dalam 72 jam
- **Penilaian awal**: dalam 7 hari
- **Perbaikan**: sesuai tingkat keparahan; kerentanan kritis diprioritaskan

Setelah perbaikan dirilis, kami akan mengkredit pelapor (kecuali diminta anonim).

## Cakupan

Termasuk dalam cakupan:
- Bypass autentikasi dashboard
- Kebocoran kredensial (`config.json`, session secret)
- Injeksi (DNS, command, log)
- DNS rebinding / cache poisoning
- Denial of service pada resolver

Di luar cakupan:
- Kerentanan pada dependensi hulu (laporkan ke proyek terkait)
- Serangan yang butuh akses fisik atau root ke host

## Praktik Keamanan yang Disarankan

- **Jangan** commit `config.json` ke repositori — file ini berisi hash password
  admin dan session secret. Gunakan `config.example.json` sebagai template.
- Ganti kredensial admin default melalui form setup saat pertama kali jalan.
- Jalankan dashboard di belakang reverse proxy dengan TLS untuk akses publik.
- Batasi akses port dashboard (8080) hanya ke jaringan tepercaya.
