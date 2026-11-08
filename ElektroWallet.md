# Elektro Wallet

> Aplikasi dompet digital (e-wallet) berbasis C++ dengan antarmuka konsol dan halaman pembayaran web yang diakses lewat QR Code. Proyek ini dikembangkan menuju fitur-fitur yang terinspirasi dari aplikasi e-wallet populer seperti GoPay.

| | |
|---|---|
| **Nama proyek** | Elektro Wallet |
| **Bahasa** | C++17 (satu file: `ElektroWalletSystem.cpp`, ±2.800 baris) |
| **Platform** | Windows, Linux, macOS (kode lintas platform) |
| **Penyimpanan data** | File teks (`users.txt`, `transactions.txt`) |
| **Antarmuka** | Konsol (menu angka) + web server tertanam (HTML) untuk bayar via HP |
| **Dependensi eksternal** | Tidak ada (hanya standard library + socket OS) |
| **Status** | Prototipe fungsional (versi 1) |

---

## 1. Ringkasan Proyek

Elektro Wallet adalah simulasi dompet digital. Pengguna mendaftar, login, mengisi saldo, mentransfer ke pengguna lain, dan menerima pembayaran lewat **QR Code**. QR Code berisi URL halaman pembayaran yang dilayani oleh web server yang berjalan di dalam program itu sendiri, sehingga HP di jaringan Wi-Fi yang sama dapat memindai QR lalu membayar tanpa menginstal aplikasi.

Sebagian besar komponen dibangun dari nol tanpa library: generator QR Code (ISO/IEC 18004), web server HTTP berbasis socket, hashing, dan penyimpanan data.

---

## 2. Berkas yang Dipelajari

| Berkas | Isi | Catatan |
|---|---|---|
| `ElektroWalletSystem.cpp` | Seluruh source code | Sumber utama |
| `ElektroWallet.exe` | Hasil kompilasi Windows 64-bit (console) | String di dalamnya cocok dengan source code, jadi ini build dari file `.cpp` yang sama |
| `users.txt` | Data pengguna | 2 akun contoh: `fira123` (Syafira) dan `dmr123` (Damar) |
| `transactions.txt` | Riwayat transaksi | 5 baris contoh (top up dan satu pembayaran QR) |

Data contoh konsisten: Damar top up 100.000 + 50.000 lalu menerima 10.000 dari Syafira = **160.000**. Syafira top up 50.000 lalu membayar 10.000 = **40.000**. Keduanya sama dengan saldo di `users.txt`.

---

## 3. Fitur yang Sudah Ada (v1)

### 3.1 Menu Utama
1. Login Akun
2. Registrasi Akun Baru
3. Lupa Password
4. Keluar Program

Layar utama juga menampilkan jumlah pengguna terdaftar, IP laptop, dan status web server.

### 3.2 Dashboard Pengguna (setelah login)
| No | Menu | Deskripsi |
|---|---|---|
| 1 | Cek Saldo | Menampilkan ID, nama, dan saldo |
| 2 | Top Up Saldo | Tambah saldo, dikonfirmasi PIN, menghasilkan bukti top up |
| 3 | Transfer Saldo | Kirim ke User ID lain, konfirmasi PIN, bukti transfer |
| 4 | QR Code Pembayaran | Tampilkan QR milik pengguna untuk menerima pembayaran |
| 5 | Riwayat Transaksi | Daftar transaksi (terbaru di atas) + opsi cetak ke file teks |
| 6 | Profil Pengguna | Nama, ID, email, status, tanggal dibuat |
| 7 | Ubah / Lupa PIN | Ganti PIN setelah verifikasi password |
| 8 | Logout | Keluar dari akun |

### 3.3 Aturan Validasi
- **Password**: minimal 8 karakter, wajib huruf besar, huruf kecil, dan angka.
- **PIN**: tepat 6 digit angka.
- **User ID dan Email**: harus unik.
- Input password dan PIN disamarkan dengan `*`.
- Transfer ke akun sendiri ditolak; saldo harus mencukupi.

### 3.4 Pembatasan Percobaan (Anti Brute-force)
| Fitur | Batas | Kunci |
|---|---|---|
| Login konsol | 3 kali salah | Dikunci 60 detik |
| Lupa password | 3 kali salah | Dikunci 60 detik |
| Transfer (salah ID penerima) | 3 kali salah | Dikunci 60 detik |
| PIN transfer | 3 kali salah | Transaksi dibatalkan |
| Login web (bayar QR) | 5 kali salah per ID | Dikunci 60 detik |

### 3.5 Pembayaran via QR Code (Web)
Penerima membuka menu QR di konsol. Program mendeteksi IP LAN laptop, membentuk URL, lalu menampilkan QR di terminal (atau versi SVG yang lebih tajam di browser lewat `/qr`).

Contoh isi QR:
```
http://192.168.1.10:8080/payment?merchant=dmr123
```

Alur pembayar dari HP:
```
Pindai QR  →  GET /payment?merchant=ID      (tampil penerima + form login)
           →  POST /payment/login           (verifikasi ID + password pengirim)
           →  POST /payment/review          (isi nominal, lihat ringkasan)
           →  POST /payment/confirm         (proses transaksi + bukti pembayaran)
```

Detail penting:
- Sesi pembayaran berlaku **300 detik** dan **sekali pakai** (mencegah pembayaran ganda saat halaman di-refresh).
- Nominal minimal **Rp 1.000**, hanya bilangan bulat.
- Output HTML di-escape (`htmlEscape`) untuk mencegah HTML injection dari nama atau ID.
- Endpoint tambahan: `GET /health` (cek server) dan `GET /qr?merchant=ID`.
- Menu QR menyediakan: buka QR di browser, ganti IP manual, dan tes server.

### 3.6 Konfigurasi (Environment Variable)
| Variabel | Fungsi | Default |
|---|---|---|
| `EWALLET_PORT` | Port web server (1024–65535) | `8080` |
| `EWALLET_HOST_IP` | Paksa IP yang ditanam di QR | Deteksi otomatis |

Deteksi IP otomatis memprioritaskan Wi-Fi/hotspot (192.168.x.x, lalu 172.16–31.x.x, lalu 10.x.x.x) dan menghindari adaptor virtual (Docker, VirtualBox). Alamat loopback tidak pernah dipakai di QR karena HP akan menganggapnya sebagai dirinya sendiri.

---

## 4. Arsitektur Saat Ini

```
┌────────────────────────────────────────────────────────────┐
│                  ElektroWallet.exe (1 proses)               │
│                                                            │
│  ┌──────────────────┐        ┌───────────────────────────┐ │
│  │ ElektroWalletApp │        │    EWalletWebServer       │ │
│  │ (menu konsol)    │        │ (thread terpisah, port    │ │
│  │ login, top up,   │        │  8080, 1 thread/koneksi)  │ │
│  │ transfer, QR ... │        │ /payment, /qr, /health    │ │
│  └────────┬─────────┘        └─────────────┬─────────────┘ │
│           │      std::mutex (dbMutex)      │               │
│           └──────────┬─────────────────────┘               │
│                      ▼                                     │
│            ┌──────────────────┐   ┌─────────────────────┐  │
│            │ DatabaseManager  │──▶│ users.txt           │  │
│            │ (vector + mutex) │   │ transactions.txt    │  │
│            └──────────────────┘   └─────────────────────┘  │
│                                                            │
│  Utilitas: SimpleQRGenerator, hashSecurity, validasi,      │
│            deteksi IP, urlEncode/Decode, htmlEscape        │
└────────────────────────────────────────────────────────────┘
        ▲
        │ HTTP (Wi-Fi yang sama)
   ┌────┴─────┐
   │ HP pembayar │
   └──────────┘
```

### Komponen dalam source code
| Bagian | Isi |
|---|---|
| 1. Lintas platform | Abstraksi socket, `clearScreen`, `customGetch`, mode VT |
| 2. Deteksi IP LAN | `detectRouteIP`, `getLocalIPCandidates`, `ipRank` |
| 3. `SimpleQRGenerator` | QR byte mode, ECC level L, versi 1–9, Reed-Solomon, 8 mask + penalty, render konsol dan SVG |
| 4. Helper | Hash, validasi, URL encode/decode, `htmlEscape`, format Rupiah |
| 5. Model data | `struct User`, `struct Transaction`, `DatabaseManager` |
| 6. `EWalletWebServer` | Server HTTP, sesi bayar, halaman HTML |
| 7. `ElektroWalletApp` | Semua menu konsol |
| 8. `main()` | Membuat `ElektroWalletApp` lalu `run()` |

---

## 5. Model Data dan Format File

Pemisah kolom adalah karakter `|`. Satu baris = satu record.

### 5.1 `users.txt`
```
id | nama | email | passwordHash | pinHash | saldo | status | createdAt
```
Contoh (hash dipotong):
```
dmr123|Damar|dmr@gmail.com|14b6f011...|2afcd74b...|160000.00|Aktif|2026-10-09 14:34:59
```

| Kolom | Tipe | Keterangan |
|---|---|---|
| `id` | string | Unik, dipakai sebagai identitas dan isi QR |
| `nama` | string | Nama lengkap |
| `email` | string | Unik, dipakai verifikasi lupa password |
| `passwordHash` | hex 16 karakter | Hash password |
| `pinHash` | hex 16 karakter | Hash PIN |
| `saldo` | double (2 desimal) | Saldo dalam Rupiah |
| `status` | string | `Aktif` (selain itu dianggap terblokir) |
| `createdAt` | timestamp | `YYYY-MM-DD HH:MM:SS` |

### 5.2 `transactions.txt`
```
trxId | userId | tipe | nominal | targetId | timestamp | status
```
Contoh:
```
1004|fira123|QR PAYMENT OUT|10000.00|dmr123|2026-10-09 15:46:14|BERHASIL
1005|dmr123|QR PAYMENT IN|10000.00|fira123|2026-10-09 15:46:14|BERHASIL
```

| Tipe transaksi | Arti |
|---|---|
| `TOP UP` | Isi saldo (target `-`) |
| `TRANSFER OUT` / `TRANSFER IN` | Transfer lewat menu konsol |
| `QR PAYMENT OUT` / `QR PAYMENT IN` | Pembayaran via QR di web |

Setiap transfer menghasilkan **dua baris** (sisi pengirim dan sisi penerima) dengan timestamp sama. ID transaksi berurutan mulai dari 1001.

---

## 6. Cara Build dan Menjalankan

```bash
# Linux / macOS
g++ -std=c++17 -O2 -pthread ElektroWalletSystem.cpp -o ElektroWallet
./ElektroWallet

# Windows (MinGW-w64)
g++ -std=c++17 -O2 ElektroWalletSystem.cpp -o ElektroWallet.exe -lws2_32
ElektroWallet.exe
```

Catatan:
- `users.txt` dan `transactions.txt` dibaca dari folder tempat program dijalankan; jika belum ada, program mulai dengan data kosong dan membuatnya saat pertama menyimpan.
- Di Windows, izinkan program di Windows Firewall untuk port 8080 agar HP bisa mengakses.
- HP dan laptop harus berada di jaringan Wi-Fi/hotspot yang sama.

---

## 7. Evaluasi Teknis (Temuan dari Source Code)

Prototipe ini sudah rapi untuk tugas/pembelajaran. Berikut hal yang perlu diperbaiki sebelum dikembangkan lebih jauh, diurutkan dari dampak terbesar.

### 7.1 Keamanan
| # | Temuan | Dampak | Saran |
|---|---|---|---|
| 1 | Hash memakai FNV-1a 64-bit dengan salt statis yang tertanam di source | FNV bukan hash kriptografis dan cepat dibobol; PIN 6 digit (1 juta kemungkinan) bisa ditebak dalam hitungan detik jika `users.txt` bocor. Dua pengguna dengan PIN sama menghasilkan hash identik (terlihat di data contoh) | Pakai Argon2id / bcrypt / scrypt dengan **salt acak per pengguna** |
| 2 | Pembayaran QR di web hanya meminta password, **tanpa PIN** | Password saja cukup untuk memindahkan saldo, tidak sekuat alur transfer konsol | Wajibkan PIN pada langkah konfirmasi |
| 3 | Web server memakai HTTP polos | Password terkirim tanpa enkripsi di jaringan | Gunakan HTTPS (TLS) atau minimal peringatan "hanya jaringan tepercaya" |
| 4 | Token sesi dibuat dari `mt19937_64` yang di-seed 64 bit | Bukan generator acak kriptografis | Pakai sumber acak OS (`/dev/urandom`, `BCryptGenRandom`) atau library kripto |
| 5 | Tidak ada proteksi CSRF dan tidak ada rate limit per IP di web | Rentan penyalahgunaan di jaringan yang sama | Token CSRF per form, batasi per IP |
| 6 | Pembatasan percobaan (login, lupa password, transfer) hanya di memori | Reset saat program ditutup; PIN top up tidak dibatasi sama sekali | Simpan hitungan gagal di data persisten; batasi PIN di semua tempat |
| 7 | Lupa password cukup dengan User ID + email | Siapa pun yang tahu keduanya bisa mengambil alih akun | Kirim OTP / tautan reset ke email |
| 8 | Top up tidak melalui pembayaran apa pun | Siapa pun bisa mengisi saldo tak terbatas | Sambungkan ke simulasi payment gateway, atau batasi ke akun admin |

### 7.2 Integritas Data
| # | Temuan | Saran |
|---|---|---|
| 1 | Setiap transaksi **menulis ulang seluruh file** (`trunc`); jika program mati saat menulis, data bisa rusak. Saldo disimpan **sebelum** transaksi dicatat | Tulis ke file sementara lalu rename (atomik), atau pindah ke SQLite dengan transaksi database |
| 2 | Saldo bertipe `double` | Pakai bilangan bulat (satuan Rupiah, `int64_t`) agar tidak ada galat pembulatan |
| 3 | Karakter `\|` pada nama atau email akan merusak parsing baris | Validasi/escape input, atau pindah ke format yang punya quoting (JSON, SQLite) |
| 4 | Transaksi gagal tidak pernah dicatat (status selalu `BERHASIL`) | Catat status `GAGAL` / `DIBATALKAN` untuk audit |
| 5 | Seluruh data dimuat ke memori dan dicari linear | Cukup untuk puluhan akun; butuh indeks/DB untuk ribuan |
| 6 | Nominal top up/transfer di konsol tidak ada batas atas dan tanpa minimal (hanya di web minimal Rp 1.000) | Terapkan aturan nominal yang sama di semua jalur |

### 7.3 Kode
- Satu file 2.800 baris; sebaiknya dipecah menjadi modul (lihat bagian 9).
- Satu thread baru per koneksi HTTP (`detach`); pakai thread pool atau batas koneksi.
- Halaman HTML dibangun lewat penyambungan string; pertimbangkan template terpisah.
- Menu konsol memakai `cin >>` bercampur `getline`, rawan sisa newline.

---

## 8. Roadmap Fitur Menuju Gaya GoPay

Daftar di bawah adalah ide pengembangan yang terinspirasi dari fitur umum e-wallet seperti GoPay. Ini bukan salinan spesifikasi GoPay, melainkan target fungsional untuk Elektro Wallet. Fitur diurutkan per fase dari yang paling mudah dibangun di atas kode sekarang.

Legenda: ✅ sudah ada · 🟡 sebagian · ⬜ belum ada

### Fase 0 — Fondasi (perbaikan sebelum menambah fitur)
- [ ] Ganti hashing ke Argon2id/bcrypt dengan salt acak
- [ ] Saldo ke `int64_t` (Rupiah bulat)
- [ ] Pindah penyimpanan ke **SQLite** (tabel `users`, `transactions`, `sessions`)
- [ ] Pisah kode ke modul (storage, service, web, ui)
- [ ] Wajibkan PIN pada pembayaran QR web
- [ ] Catat transaksi gagal dan log audit

### Fase 1 — Dompet Inti
| Fitur | Status | Catatan pengembangan |
|---|---|---|
| Registrasi, login, lupa password | ✅ | Tambah verifikasi email/OTP |
| Cek saldo | ✅ | |
| Top up saldo | 🟡 | Tambah metode: virtual account simulasi, transfer bank simulasi, kartu |
| Transfer antar pengguna | ✅ | Tambah catatan/berita transfer dan kontak favorit |
| Riwayat transaksi | 🟡 | Tambah filter (tanggal, tipe), pencarian, halaman detail, ekspor PDF/CSV |
| Bukti transaksi | ✅ | Konsol dan web; tambah berbagi struk |
| Ubah PIN | ✅ | |
| Profil | 🟡 | Tambah edit nama/email, foto, nomor HP |

### Fase 2 — Pembayaran QR yang Lebih Lengkap
| Fitur | Status | Catatan |
|---|---|---|
| Terima pembayaran via QR (QR statis akun) | ✅ | |
| QR dengan nominal tetap (dinamis) | ⬜ | Tambah parameter `amount` dan `expiry` di URL QR |
| Pindai QR dari dalam aplikasi | ⬜ | Butuh antarmuka mobile/web dengan kamera |
| QR merchant / toko | ⬜ | Tipe akun `MERCHANT`, nama toko, ID terminal |
| Minta pembayaran (payment request) | ⬜ | Buat tagihan ke pengguna lain, bisa dibayar lewat tautan |
| Bagi tagihan (split bill) | ⬜ | Bagi nominal ke beberapa pengguna dan lacak siapa yang sudah bayar |

### Fase 3 — Layanan Tambahan
| Fitur | Catatan |
|---|---|
| Beli pulsa dan paket data | Katalog produk simulasi, prefiks operator |
| Bayar tagihan (listrik, air, internet) | Input nomor pelanggan, simulasi inquiry lalu payment |
| Transfer ke bank | Daftar bank simulasi, biaya admin |
| Tarik tunai | Kode tarik tunai berlaku singkat (simulasi) |
| Voucher, promo, cashback | Tabel `vouchers`, aturan kuota dan masa berlaku |
| Poin / reward | Poin dari transaksi, tukar dengan voucher |
| Pay Later (cicilan) | Limit kredit, tagihan bulanan, jatuh tempo (simulasi) |

### Fase 4 — Keamanan Lanjutan dan Kepatuhan
- [ ] OTP email/SMS untuk login perangkat baru dan transaksi besar
- [ ] Batas transaksi harian dan batas per transaksi
- [ ] Tingkat akun (basic dan terverifikasi/KYC) dengan batas saldo berbeda
- [ ] Deteksi aktivitas mencurigakan dan blokir otomatis akun
- [ ] Notifikasi transaksi (email atau push)
- [ ] Daftar perangkat dan sesi aktif
- [ ] HTTPS, token CSRF, rate limit per IP

### Fase 5 — Platform
- [ ] REST API (JSON) terpisah dari antarmuka
- [ ] Aplikasi web/mobile (React, Flutter, atau lainnya) sebagai klien
- [ ] Panel admin (kelola akun, blokir, laporan, rekonsiliasi saldo)
- [ ] Dashboard laporan dan grafik pengeluaran pengguna
- [ ] Pengujian otomatis dan CI

---

## 9. Rancangan Arsitektur Target

```
        ┌───────────┐   ┌───────────┐   ┌─────────────┐
        │ Web/Mobile│   │ Panel     │   │ Halaman bayar│
        │ App       │   │ Admin     │   │ QR (HP)     │
        └─────┬─────┘   └─────┬─────┘   └──────┬──────┘
              └───────────────┼────────────────┘
                              ▼  HTTPS + JSON
                    ┌───────────────────┐
                    │    REST API       │  auth, rate limit, validasi
                    └─────────┬─────────┘
                              ▼
        ┌─────────────────────────────────────────────┐
        │ Service layer                                │
        │ AuthService · WalletService · PaymentService │
        │ QrService · BillService · NotificationService│
        └─────────────────────┬───────────────────────┘
                              ▼
                    ┌───────────────────┐
                    │  SQLite / DB lain │  transaksi ACID
                    └───────────────────┘
```

### Struktur folder yang disarankan
```
ElektroWallet/
├── CMakeLists.txt
├── README.md
├── src/
│   ├── main.cpp
│   ├── core/          # User, Transaction, tipe uang, util waktu
│   ├── storage/       # DatabaseManager (SQLite), migrasi
│   ├── services/      # Auth, Wallet, Payment, Bill, Voucher
│   ├── security/      # Hashing, token acak, OTP
│   ├── qr/            # SimpleQRGenerator
│   ├── web/           # HTTP server, handler, template HTML
│   └── ui/            # Menu konsol
├── data/              # users.txt, transactions.txt (data lama untuk migrasi)
├── tests/
└── docs/
```

### Rancangan skema database (usulan)
```sql
CREATE TABLE users (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  email         TEXT UNIQUE NOT NULL,
  phone         TEXT UNIQUE,
  password_hash TEXT NOT NULL,   -- Argon2id, salt di dalam string hash
  pin_hash      TEXT NOT NULL,
  balance       INTEGER NOT NULL DEFAULT 0 CHECK (balance >= 0),  -- Rupiah
  role          TEXT NOT NULL DEFAULT 'USER',      -- USER | MERCHANT | ADMIN
  status        TEXT NOT NULL DEFAULT 'AKTIF',     -- AKTIF | BLOKIR | NONAKTIF
  kyc_level     INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT NOT NULL
);

CREATE TABLE transactions (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ref_no      TEXT UNIQUE NOT NULL,              -- mis. TRX1001
  user_id     TEXT NOT NULL REFERENCES users(id),
  type        TEXT NOT NULL,                     -- TOPUP | TRANSFER | QR_PAYMENT | BILL | ...
  direction   TEXT NOT NULL,                     -- IN | OUT
  amount      INTEGER NOT NULL CHECK (amount > 0),
  fee         INTEGER NOT NULL DEFAULT 0,
  counterparty_id TEXT,
  note        TEXT,
  status      TEXT NOT NULL,                     -- BERHASIL | GAGAL | MENUNGGU
  created_at  TEXT NOT NULL
);

CREATE TABLE pay_sessions (
  token       TEXT PRIMARY KEY,
  sender_id   TEXT NOT NULL,
  merchant_id TEXT NOT NULL,
  amount      INTEGER,                            -- NULL jika diisi pembayar
  expires_at  INTEGER NOT NULL,
  used        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE login_attempts (
  subject     TEXT NOT NULL,                      -- user id atau IP
  failed      INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER
);
```
Semua perpindahan saldo (kurangi pengirim, tambah penerima, catat dua baris transaksi) dibungkus **satu transaksi database** sehingga tidak ada kondisi setengah jadi.

### Migrasi dari file lama
Buat skrip sekali jalan yang membaca `users.txt` dan `transactions.txt`, mengonversi saldo `double` ke integer Rupiah, lalu memasukkannya ke tabel baru. Hash lama (FNV) tidak bisa dipakai di skema baru; minta pengguna mereset password dan PIN saat login pertama.

---

## 10. Rencana Pengujian

### Skenario fungsional
| ID | Skenario | Hasil yang diharapkan |
|---|---|---|
| T-01 | Registrasi dengan password lemah | Ditolak, tampil kriteria |
| T-02 | Registrasi dengan User ID/email yang sudah ada | Ditolak |
| T-03 | Login benar | Masuk dashboard |
| T-04 | Login salah 3 kali | Dikunci 60 detik |
| T-05 | Top up dengan PIN benar | Saldo bertambah, riwayat tercatat, bukti tampil |
| T-06 | Top up dengan PIN salah | Dibatalkan, saldo tetap |
| T-07 | Transfer melebihi saldo | Ditolak |
| T-08 | Transfer ke diri sendiri | Ditolak |
| T-09 | Transfer valid | Saldo pengirim turun, penerima naik, dua baris riwayat |
| T-10 | Pindai QR lalu bayar | Saldo berpindah, bukti web tampil |
| T-11 | Refresh halaman konfirmasi bayar | Tidak terjadi pembayaran ganda |
| T-12 | Sesi bayar melewati 300 detik | Sesi kedaluwarsa |
| T-13 | QR ke akun tidak ada/nonaktif | "QR Code Tidak Dikenali" |
| T-14 | Dua pembayaran bersamaan dari saldo yang sama | Tidak ada saldo negatif |

### Skenario keamanan
- Nama berisi `<script>` tidak tereksekusi di halaman web.
- Nama atau email berisi `|` tidak merusak `users.txt`.
- Nominal negatif, nol, sangat besar, atau berformat `1e9` ditolak.
- Brute-force login web dikunci setelah 5 kali.

---

## 11. Glosarium

| Istilah | Arti |
|---|---|
| **Top up** | Mengisi saldo dompet |
| **QR Code** | Kode dua dimensi; di sini berisi URL halaman pembayaran |
| **Merchant** | Penerima pembayaran (di v1 adalah pemilik akun yang menampilkan QR) |
| **Sesi bayar** | Token sementara yang mengikat pengirim, penerima, dan batas waktu |
| **ECC Level L** | Tingkat koreksi kesalahan QR terendah (±7%), menghasilkan QR paling kecil |
| **KYC** | Verifikasi identitas pengguna |
| **ACID** | Jaminan transaksi database: atomik, konsisten, terisolasi, tahan lama |

---

## 12. Daftar Pekerjaan Berikutnya (Prioritas)

1. Perbaiki fondasi: hashing aman, saldo integer, PIN wajib di bayar QR.
2. Migrasi ke SQLite dan pisah kode menjadi modul.
3. QR dinamis (nominal dan masa berlaku) serta payment request.
4. Riwayat dengan filter dan ekspor.
5. Fitur layanan: pulsa, tagihan, transfer bank (simulasi).
6. Voucher dan poin.
7. REST API lalu antarmuka web/mobile.
8. Panel admin dan batas transaksi.
