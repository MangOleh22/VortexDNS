# Panduan Instalasi VortexDNS (VortexDNS Installation Guide)

Dokumen ini berisi panduan lengkap untuk melakukan instalasi, konfigurasi, pengelolaan, dan pencopotan (uninstall) VortexDNS di sistem operasi Linux.

---

## Prasyarat Sistem (System Requirements)
* **Sistem Operasi**: Linux (Ubuntu, Debian, CentOS, RHEL, dll.)
* **Arsitektur CPU**: x86_64, i386, arm64, armv7, riscv64
* **Hak Akses**: Root (atau `sudo`)
* **Dependensi Opsional**: Go compiler (jika kompilasi manual/otomatis), `curl` atau `wget`

---

## 0. Menyiapkan Berkas Konfigurasi

Repositori **tidak** menyertakan `config.json` (berisi kredensial). Yang tersedia adalah
template `config.example.json`. Salin dulu sebelum menjalankan:

```bash
cp config.example.json config.json
```

Template ini sudah berisi upstream DNS default (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`) tetapi
kolom admin dikosongkan (`admin_username`, `admin_password_hash`, `session_secret` = `""`),
sehingga server masuk **mode setup** — Anda membuat akun admin sendiri lewat dashboard saat
pertama kali jalan (lihat **Bagian 6**). Ubah upstream, blocklist, atau port sesuai
kebutuhan sebelum start bila perlu.

> Jika `config.json` belum ada saat server dijalankan, VortexDNS otomatis men-generate
> config default (efeknya sama dengan menyalin template di atas).

---

## 1. Metode Instalasi Otomatis (Direkomendasikan)

VortexDNS menyediakan skrip instalasi premium yang mendeteksi arsitektur CPU Anda, mengunduh kompiler Go (jika belum ada), membangun binary, mengonfigurasi direktori, dan memasang layanan `systemd`.

### Cara Menjalankan Skrip Instalasi:
Jalankan perintah berikut di dalam direktori `vortexdns`:

```bash
sudo chmod +x scripts/install.sh
sudo ./scripts/install.sh
```

### Apa yang Dilakukan oleh Skrip:
1. **Pemeriksaan Hak Akses**: Memastikan skrip dijalankan dengan hak akses root.
2. **Deteksi Sistem**: Mengidentifikasi sistem operasi dan arsitektur CPU untuk Go target build.
3. **Penyusunan Compiler**: Mengunduh dan mengonfigurasi Go compiler versi `1.21.5` jika belum terinstal di sistem.
4. **Kompilasi Binary**: Melakukan `go build -ldflags="-s -w" -o vortexdns main.go`.
5. **Penempatan Berkas**: 
   * Menyalin binary ke `/usr/local/bin/vortexdns`.
   * Menyalin konfigurasi default ke `/etc/vortexdns/config.json`.
   * Membuat direktori kerja di `/var/lib/vortexdns`.
6. **Integrasi Systemd**: Membuat service berkas di `/etc/systemd/system/vortexdns.service`.
7. **Resolusi Konflik Port**: Mendeteksi dan menonaktifkan `DNSStubListener` bawaan dari `systemd-resolved` (jika aktif) agar port 53 bisa digunakan oleh VortexDNS.
8. **Menjalankan Layanan**: Menjalankan VortexDNS dan memastikan statusnya aktif.

---

## 2. Metode Instalasi Manual

Jika Anda ingin mengompilasi dan memasang berkas secara mandiri, ikuti langkah-langkah di bawah ini:

### Langkah 1: Kompilasi Kode Sumber
Pastikan Go Compiler sudah terinstal (`go version` >= 1.21).
```bash
cd /root/vortexdns
CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o vortexdns main.go
```

### Langkah 2: Pindahkan Binary & Konfigurasi
```bash
# Salin binary ke system path
sudo cp vortexdns /usr/local/bin/vortexdns
sudo chmod 755 /usr/local/bin/vortexdns

# Buat direktori konfigurasi dan salin config.json
sudo mkdir -p /etc/vortexdns
sudo cp config.json /etc/vortexdns/config.json
sudo chmod 644 /etc/vortexdns/config.json

# Buat direktori data untuk database
sudo mkdir -p /var/lib/vortexdns
sudo chmod 755 /var/lib/vortexdns
```

### Langkah 3: Konfigurasi Service Systemd
Buat berkas unit systemd `/etc/systemd/system/vortexdns.service`:
```ini
[Unit]
Description=VortexDNS High-Performance Adblocking DNS Server
After=network.target

[Service]
Type=simple
WorkingDirectory=/var/lib/vortexdns
ExecStart=/usr/local/bin/vortexdns -config /etc/vortexdns/config.json
StandardOutput=append:/var/log/vortexdns/vortex.log
StandardError=append:/var/log/vortexdns/vortex.log
Restart=always
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

> Catatan: `StandardOutput`/`StandardError` menulis log proses ke `/var/log/vortexdns/vortex.log` (dibaca oleh panel **Log > System** di dashboard). Buat dulu direktorinya: `sudo mkdir -p /var/log/vortexdns`.

Terapkan service tersebut:
```bash
sudo systemctl daemon-reload
sudo systemctl enable vortexdns.service
sudo systemctl start vortexdns.service
```

---

## 3. Pengelolaan Layanan (Service Management)

Setelah terinstal, Anda dapat mengelola layanan VortexDNS dengan perintah standar `systemctl`:

* **Melihat Status Layanan**:
  ```bash
  systemctl status vortexdns
  ```
* **Menghentikan Layanan**:
  ```bash
  systemctl stop vortexdns
  ```
* **Memulai Layanan**:
  ```bash
  systemctl start vortexdns
  ```
* **Memuat Ulang Layanan setelah Mengedit Konfigurasi**:
  ```bash
  systemctl restart vortexdns
  ```
* **Melihat Log secara Real-time**:
  ```bash
  journalctl -u vortexdns -f
  ```

---

## 4. Reset Password Admin (Lupa Password)

Seluruh metode di bawah memakai mekanisme yang sama: binary `vortexdns` dengan flag
`-reset-password`. Binary meng-hash password (bcrypt) dan menuliskannya ke `config.json`.
Password baru diambil dari variabel lingkungan `VORTEX_ADMIN_PASSWORD` bila diisi, atau dari
stdin bila kosong. Tambahkan `-reset-username <nama>` untuk sekaligus mengganti username.

Syarat: password minimal 6 karakter, dan `config.json` harus berada di lokasi yang persisten.
Setelah reset, **restart** VortexDNS agar berlaku.

### a. Instalasi di Host (systemd)
Installer memasang CLI `vortex-reset` ke `/usr/local/bin`:
```bash
# Interaktif (diminta mengetik password)
sudo vortex-reset

# Non-interaktif
sudo VORTEX_ADMIN_PASSWORD='PasswordBaru123' vortex-reset --password
```
`vortex-reset` otomatis me-restart service `vortexdns` setelah berhasil.

### b. Docker Compose
```bash
cd /path/ke/vortexdns   # folder berisi docker-compose.yml

# Interaktif
docker compose exec -it vortexdns vortex-reset

# Non-interaktif
docker compose exec -e VORTEX_ADMIN_PASSWORD='PasswordBaru123' vortexdns vortex-reset --password

docker compose restart vortexdns
```
Bila container gagal start (tidak bisa `exec`), pakai container sekali-pakai:
```bash
docker compose run --rm -e VORTEX_ADMIN_PASSWORD='PasswordBaru123' \
  vortexdns ./vortexdns -reset-password
docker compose up -d vortexdns
```

### c. Docker (tanpa Compose)
```bash
docker exec -it vortexdns_test vortex-reset
# atau non-interaktif:
docker exec -e VORTEX_ADMIN_PASSWORD='PasswordBaru123' vortexdns_test vortex-reset --password
docker restart vortexdns_test
```

### d. Kubernetes
```bash
# Interaktif ke pod
kubectl exec -it deploy/vortexdns -- vortex-reset

# Non-interaktif
kubectl exec deploy/vortexdns -- \
  env VORTEX_ADMIN_PASSWORD='PasswordBaru123' ./vortexdns -reset-password

kubectl rollout restart deploy/vortexdns
```

> **Peringatan keamanan**: Password yang ditulis inline (`VORTEX_ADMIN_PASSWORD=...`) tercatat di
> riwayat shell dan terlihat via `docker inspect`. Aman untuk sekali reset, tetapi **jangan**
> menaruh variabel ini permanen di `docker-compose.yml` atau manifest Kubernetes.

> **Persistensi**: Reset menulis ke `config.json`. Pada container, pastikan file ini berada di
> volume/bind-mount atau ConfigMap yang persisten. Jika `config.json` ikut di dalam image, hasil
> reset akan hilang saat container dibuat ulang.

---

## 5. Deployment via Container (Docker / Podman / Kubernetes)

Repositori menyertakan `Dockerfile` (multi-stage, image akhir Alpine) dan `docker-compose.yml`.

### Docker Compose (paling ringkas)
```bash
cd /path/ke/vortexdns
cp config.example.json config.json   # lewati jika sudah ada
docker compose up -d --build
```
Port default yang dipetakan: `10053->53` (DNS) dan `18080->8080` (dashboard). `config.json`,
database, dan log di-mount ke host agar persisten.

### Docker manual
```bash
docker build -t vortexdns .
docker run -d --name vortexdns \
  -p 10053:53/udp -p 10053:53/tcp -p 18080:8080/tcp \
  -v "$PWD/config.json:/app/config.json" \
  -v vortex_data:/app/vortex_db \
  vortexdns
```

### Podman
Perintah identik dengan Docker; ganti `docker` menjadi `podman`.

### Kubernetes
Gunakan image hasil build di atas. Simpan `config.json` sebagai `ConfigMap` (atau PVC) dan
mount ke `/app/config.json` agar setup admin dan reset password tetap persisten antar-pod.

---

## 6. Setup Awal (First-Run) — Buat Akun Admin Sendiri

VortexDNS **tidak** punya username/password default. Saat pertama kali dijalankan
(fresh install), server men-generate `config.json` otomatis dengan kolom admin kosong,
sehingga masuk ke **mode setup**.

Langkah:
1. Jalankan VortexDNS (systemd/Docker), lalu buka dashboard di browser.
2. Karena belum ada admin, halaman login otomatis menampilkan form **"Buat Akun"**.
3. Isi **username** (min. 3 karakter) dan **password** (min. 6 karakter) pilihan Anda.
4. Klik **Buat Akun & Mulai**. Kredensial di-hash (bcrypt) dan disimpan ke `config.json`.
5. Login memakai username & password yang baru Anda buat.

Detail teknis:
* `admin_username` dan `admin_password_hash` awalnya kosong → memicu mode setup.
* `session_secret` di-generate acak (32-byte) otomatis saat pertama load; config lama
  yang masih memakai placeholder `vortex-secret-change-me` akan di-upgrade sekali secara
  otomatis lalu disimpan.
* Endpoint setup (`POST /api/auth/setup`) menolak permintaan bila admin sudah dibuat,
  sehingga akun tidak bisa ditimpa lewat form.

> **Persistensi**: Pastikan `config.json` berada di volume/bind-mount atau ConfigMap yang
> persisten (lihat bagian Docker/Kubernetes), agar akun yang Anda buat tidak hilang saat
> container dibuat ulang.

Lupa password setelah setup? Lihat **Bagian 4 — Reset Password Admin**.

---

## 7. Informasi Akses & Konfigurasi Utama

* **Dashboard Web UI**: `http://localhost:8080` (Dapat diubah lewat parameter `dashboard_address` di file konfigurasi).
* **Lokasi Berkas Konfigurasi**: `/etc/vortexdns/config.json`.
* **Port Layanan**: Port 53 (atau port kustom yang dikonfigurasi pada parameter `bind_address`).

---

## 8. Metode Pencopotan (Uninstall)

Untuk membersihkan instalasi VortexDNS dari sistem secara keseluruhan, gunakan skrip uninstaller bawaan:

```bash
sudo chmod +x scripts/uninstall.sh
sudo ./scripts/uninstall.sh
```

Skrip ini akan menghentikan servis, mengembalikan pengaturan stub resolver `systemd-resolved`, menghapus berkas konfigurasi `/etc/vortexdns`, menghapus database di `/var/lib/vortexdns`, dan menghapus binary di `/usr/local/bin/vortexdns`.
