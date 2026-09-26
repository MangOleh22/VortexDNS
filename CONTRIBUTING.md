# Panduan Kontribusi (Contributing to VortexDNS)

Terima kasih atas minat Anda berkontribusi ke VortexDNS! Panduan ini menjelaskan
cara ikut serta.

## Kode Etik

Proyek ini mengikuti [Kode Etik](CODE_OF_CONDUCT.md). Dengan berpartisipasi, Anda
diharapkan menghormatinya.

## Cara Berkontribusi

### Melaporkan Bug
1. Cek [Issues](https://github.com/MangOleh22/VortexDNS/issues) untuk memastikan bug
   belum dilaporkan.
2. Buka Issue baru dengan menyertakan:
   - Langkah reproduksi yang jelas
   - Perilaku yang diharapkan vs yang terjadi
   - Versi/commit, OS, dan cara deploy (Docker/systemd)
   - Log relevan (**tanpa** kredensial atau data sensitif)

> Untuk kerentanan keamanan, **jangan** buka Issue publik. Ikuti [SECURITY.md](SECURITY.md).

### Mengusulkan Fitur
Buka Issue dengan label `enhancement`, jelaskan masalah yang ingin diselesaikan dan
usulan solusinya sebelum mulai menulis kode besar.

### Pull Request
1. Fork repositori dan buat branch dari `development`:
   ```bash
   git checkout -b fitur/nama-fitur development
   ```
2. Terapkan perubahan dengan diff sekecil mungkin dan fokus pada satu tujuan.
3. Pastikan kode lolos build dan test:
   ```bash
   go build ./...
   go vet ./...
   go test ./...
   ```
4. Commit dengan pesan yang deskriptif (disarankan gaya
   [Conventional Commits](https://www.conventionalcommits.org): `feat:`, `fix:`,
   `docs:`, `chore:`, dll).
5. Push branch Anda dan buka Pull Request ke branch `development`, jelaskan apa yang
   diubah dan cara mengujinya.

## Standar Kode

- **Bahasa**: Go (≥ 1.21). Format wajib dengan `gofmt`/`go fmt`.
- **Dependensi**: hindari menambah dependensi baru untuk hal yang bisa diselesaikan
  dengan stdlib atau beberapa baris kode.
- **Keamanan**: validasi input di batas kepercayaan, jangan pernah commit `config.json`
  atau rahasia lainnya.
- **Test**: sertakan test untuk logika non-trivial.

## Lisensi Kontribusi

Dengan mengirim kontribusi, Anda setuju bahwa karya Anda dilisensikan di bawah
[Lisensi MIT](LICENSE.md) yang sama dengan proyek ini.
