# Implementasi Batch Verification Edwards-Curve Digital Signature Algorithm (EdDSA) pada Sistem Verifikasi Dokumen PDF

Implementasi **Ed25519ph (HashEdDSA)** sesuai [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) dengan mekanisme **Batch Verification** menggunakan teknik *Multi-Scalar Multiplication* (MSM) dan *blinding scalar* acak 128-bit untuk mencegah serangan Wagner.

Seluruh operasi kurva eliptik diimplementasikan menggunakan aritmetika integer Python murni tanpa library kriptografi eksternal, menggunakan koordinat Extended Twisted Edwards.

---

## Daftar Isi

1. [Fitur](#fitur)
2. [Prasyarat](#prasyarat)
3. [Instalasi](#instalasi)
4. [Struktur Proyek](#struktur-proyek)
5. [Cara Penggunaan](#cara-penggunaan)
   - [Membuat Dataset PDF Sintetis](#1-membuat-dataset-pdf-sintetis-make_datapy)
   - [Menjalankan GUI](#2-menjalankan-gui-main_guipy)
   - [Tab Penandatanganan](#tab-penandatanganan-dokumen-pdf)
   - [Tab Batch Verification](#tab-batch-verification)
   - [Tab Validasi Program](#tab-validasi-program)
6. [Deskripsi Modul](#deskripsi-modul)
7. [Alur Kerja Sistem](#alur-kerja-sistem)
8. [Format File Output](#format-file-output)
9. [Validasi Program](#validasi-program)

---

## Fitur

- **Ed25519ph (HashEdDSA)** — implementasi lengkap sesuai RFC 8032 §5.1, menggunakan pre-hash SHA-512 `PH(M) = SHA-512(M)`
- **Batch Verification MSM** — memverifikasi banyak tanda tangan sekaligus dalam satu persamaan agregat: `[8·Σzᵢ·Sᵢ]·B = Σ([8·zᵢ]·Rᵢ + [8·zᵢ·hᵢ]·Aᵢ)` dengan blinding scalar `zᵢ` acak 128-bit
- **Fallback verifikasi individual** — jika satu batch gagal, sistem secara otomatis mengisolasi dokumen yang tidak valid satu per satu
- **Antarmuka GUI** tiga tab berbasis CustomTkinter
- **Validasi tiga tahap**: tes vektor RFC 8032, dataset PDF sintetis dengan confusion matrix, dan uji performa waktu & memori (`tracemalloc`)
- **Tanpa library kriptografi eksternal** — semua operasi kurva (penjumlahan titik, penggandaan skalar, dekode/enkode titik) diimplementasikan sendiri

---

## Prasyarat

| Komponen | Versi Minimum |
|---|---|
| Python | 3.10 |
| customtkinter | 5.2.2 |
| matplotlib | 3.7.0 |
| numpy | 1.24.0 |
| openpyxl | 3.1.0 |

> **Catatan:** Modul standar Python (`hashlib`, `secrets`, `tracemalloc`, `csv`, `threading`, `pathlib`, dll.) sudah tersedia dan tidak perlu diinstal terpisah.

---

## Instalasi

```bash
# 1. Clone atau salin seluruh berkas proyek ke satu folder
# 2. Instal dependensi
pip install -r requirements.txt

# 3. (Opsional) Buat dataset PDF sintetis untuk pengujian
python make_data.py 100 100 500 dataset
#   argumen: <jumlah_dokumen> <ukuran_min_KB> <ukuran_maks_KB> <folder_output>

# 4. Jalankan GUI
python main_gui.py
```

---

## Struktur Proyek

```
.
├── main_gui.py               # Antarmuka grafis utama (3 tab)
├── ed25519ph_function.py     # Operasi kurva Edwards25519 dan fungsi bantu Ed25519ph
├── ed25519ph_key_generator.py# Pembangkitan dan pemuatan pasangan kunci
├── ed25519ph_signer.py       # Penandatanganan pesan dan batch PDF
├── ed25519ph_verifier.py     # Verifikasi individual, batch, dan validasi program
├── make_data.py              # Generator dataset PDF sintetis
├── requirements.txt          # Dependensi pihak ketiga
└── README.md                 # Dokumentasi ini
```

**Folder yang dihasilkan saat runtime:**

```
output_signatures/            # Contoh folder output penandatanganan
├── Signature_records.csv     # Rekaman tanda tangan (R, S, prehash, tampered)
└── public_key.hex            # Kunci publik A dalam format hex (64 karakter)

validasi_output/              # Contoh folder output validasi program
├── Signature_records.csv
├── public_key.hex
└── confusion_matrix.png      # Visualisasi confusion matrix Tahap 2

dataset/                      # Folder dataset (dihasilkan make_data.py)
├── pdf/                      # Berkas-berkas PDF sintetis
│   ├── doc_1.pdf
│   ├── doc_2.pdf
│   └── ...
└── metadata.csv              # Metadata dataset (nama file, ukuran, SHA-512)
```

---

## Cara Penggunaan

### 1. Membuat Dataset PDF Sintetis (`make_data.py`)

Script ini menghasilkan berkas PDF sintetis berukuran bervariasi untuk keperluan pengujian.

```bash
# Format
python make_data.py <jumlah> <min_kb> <max_kb> <folder_output>

# Contoh: 100 dokumen, ukuran 100–500 KB, simpan di folder "dataset"
python make_data.py 100 100 500 dataset

# Contoh: 1000 dokumen, ukuran 1–10 MB (default penelitian)
python make_data.py 1000 1000 10000 dataset
```

| Parameter | Default | Keterangan |
|---|---|---|
| `jumlah` | 10000 | Jumlah berkas PDF yang dibuat |
| `min_kb` | 1000 | Ukuran minimum per dokumen (KB) |
| `max_kb` | 10000 | Ukuran maksimum per dokumen (KB) |
| `folder_output` | `dataset` | Folder tujuan (subfolder `pdf/` dibuat otomatis) |

Output: berkas PDF di `<folder_output>/pdf/` dan metadata di `<folder_output>/metadata.csv`.

---

### 2. Menjalankan GUI (`main_gui.py`)

```bash
python main_gui.py
```

GUI terdiri dari tiga tab:

---

### Tab Penandatanganan Dokumen PDF

Digunakan untuk membangkitkan kunci dan menandatangani seluruh dokumen PDF dalam sebuah folder.

**Langkah-langkah:**

1. Klik **Generate Kunci Baru** untuk membangkitkan pasangan kunci Ed25519ph secara acak.
2. Isi parameter:
   - **Folder dataset** — folder berisi berkas PDF yang akan ditandatangani.
   - **Folder output** — folder tujuan penyimpanan hasil.
   - **String konteks** — konteks domain separation (boleh kosong, maks 255 byte).
   - **Temper rate (%)** — persentase dokumen yang sengaja dirusak tanda tangannya (untuk pengujian deteksi). Nilai S dokumen yang dirusak diubah menjadi `S + 1 mod l`.
   - **Limit dokumen** — batas jumlah dokumen yang diproses (0 = semua).
3. Klik **Mulai Tandatangani**.

**Output otomatis di folder output:**
- `Signature_records.csv` — rekaman tanda tangan seluruh dokumen.
- `public_key.hex` — kunci publik A dalam format hex, siap dimuat pada tab Batch Verification.

Log proses menampilkan progres per dokumen: nama file, ukuran (KB), status pre-hash, tanda tangan, dan apakah dokumen dirusak.

---

### Tab Batch Verification

Digunakan untuk memverifikasi tanda tangan seluruh dokumen dari `Signature_records.csv` menggunakan kunci publik yang diperoleh dari sumber terpercaya.

**Langkah-langkah:**

1. Pilih berkas `Signature_records.csv` (klik **Pilih...**).
2. Isi **Kunci publik (hex)** — wajib diisi. Dua cara:
   - Tempel langsung 64 karakter hex pada kolom input.
   - Klik **Muat .hex** untuk memuat dari berkas `public_key.hex`.
3. Atur **Ukuran batch** (0 = satu batch untuk seluruh dokumen) dan **String konteks** (harus sama dengan saat penandatanganan).
4. Klik **Mulai Verifikasi**.

> **Catatan PKI:** Kunci publik tidak disimpan di CSV. Verifikator harus menerima kunci publik dari saluran terpercaya yang terpisah dari berkas tanda tangan, sesuai prinsip PKI.

**Output:** ringkasan valid/tidak valid per dokumen, waktu proses (ms), dapat diekspor ke **TXT** atau **Excel** (.xlsx dengan tiga sheet: Ringkasan, Per Dokumen, Log Proses).

---

### Tab Validasi Program

Menjalankan tiga tahap validasi sekaligus dengan satu tombol. Hasil setiap tahap muncul langsung di panel Output Hasil tanpa menghapus hasil tahap sebelumnya.

**Parameter:**
- **Folder dataset PDF** — folder PDF yang digunakan untuk Tahap 2 dan 3.
- **Folder output** — folder tujuan penyimpanan CSV, `public_key.hex`, dan `confusion_matrix.png`.
- **String konteks** — digunakan sama persis untuk Tahap 2 dan 3.
- **Temper rate (%)** — persentase dokumen yang dirusak pada Tahap 2.
- **Limit dokumen** — batas jumlah dokumen yang diproses (0 = semua).
- **Ukuran batch** — ukuran batch untuk Batch Verification pada Tahap 2 dan 3.

Klik **Jalankan Validasi Lengkap (Tahap 1, 2, 3)**.

#### Tahap 1 — Tes Vektor RFC 8032

Memverifikasi implementasi terhadap vektor uji resmi Ed25519ph dari RFC 8032 §7.3 (TEST abc):
- Membangkitkan kunci publik dari SECRET KEY resmi RFC dan memastikan hasilnya identik dengan PUBLIC KEY pada RFC.
- Melakukan penandatanganan + verifikasi ulang (round-trip) untuk membuktikan konsistensi implementasi.

Hasil: **PASS** jika kunci publik cocok dan verifikasi round-trip berhasil.

#### Tahap 2 — Validasi Dataset PDF (Confusion Matrix)

Menandatangani seluruh dokumen pada folder dataset menggunakan kunci sementara, dengan sejumlah dokumen yang sengaja dirusak sesuai *temper rate*. Batch Verification kemudian dijalankan dan hasilnya dibandingkan dengan kondisi sebenarnya:

| | Prediksi: VALID | Prediksi: TIDAK VALID |
|---|---|---|
| **Aktual: VALID** | TP | FN |
| **Aktual: DIRUSAK** | FP | TN |

Implementasi dinyatakan **VALID** jika dan hanya jika **FP = 0** dan **FN = 0**.

Output otomatis: `confusion_matrix.png` di folder output.

#### Tahap 3 — Uji Performa Waktu & Memori

Mengukur efisiensi waktu dan memori dalam dua fase terpisah:

**Fase 1 — Penandatanganan:** Mengukur peak RAM per dokumen saat proses baca file → pre-hash SHA-512 → tanda tangan. `tracemalloc` di-reset per iterasi untuk membuktikan RAM tetap stabil meskipun ukuran PDF bervariasi.

**Fase 2 — Verifikasi:** Membandingkan Verifikasi Individual vs Batch Verification (MSM) menggunakan rekaman CSV yang sama (hanya membaca pre-hash 64 byte dari CSV, tanpa memuat ulang dokumen PDF asli):

| Metode | Waktu (ms) | Peak RAM (MB) |
|---|---|---|
| Individual | ... | ... |
| Batch (MSM) | ... | ... |

Setelah selesai, klik **Simpan Laporan Lengkap (TXT)** untuk mengekspor gabungan hasil Tahap 1, 2, dan 3 ke satu berkas teks.

---

## Deskripsi Modul

### `ed25519ph_function.py`

Implementasi matematika kurva Edwards25519 dalam koordinat Extended Twisted Edwards `(X:Y:Z:T)`.

| Fungsi / Konstanta | Keterangan |
|---|---|
| `p` | Modulus prima kurva: 2²⁵⁵ − 19 |
| `a` | Koefisien kurva: −1 |
| `d` | Koefisien kurva: −121665/121666 mod p |
| `l` | Orde subgrup: 2²⁵² + 27742317777372353535851937790883648493 |
| `BASE_POINT` | Titik basis B dalam koordinat extended |
| `base_point()` | Menurunkan titik basis dari By = 4/5 mod p sesuai RFC 8032 |
| `point_identity()` | Titik netral (elemen identitas): (0, 1, 1, 0) |
| `point_add(P, Q)` | Penjumlahan titik dalam koordinat extended (algoritma Hisil et al.) |
| `point_double(P)` | Penggandaan titik dalam koordinat extended |
| `scalar_mult(k, P)` | Perkalian skalar dengan algoritma double-and-add |
| `encode_point(P)` | Enkode titik ke 32 byte (little-endian Y + sign bit X di bit 255) |
| `decode_point(b)` | Dekode 32 byte ke titik extended, dengan validasi kurva |
| `scalar_clamping(h32)` | Clamping 32 byte sesuai RFC 8032 §5.1.5 |
| `dom2(phflag, ctx)` | Pembuatan domain separator `dom2` sesuai RFC 8032 §2 |

---

### `ed25519ph_key_generator.py`

Pembangkitan dan pemuatan pasangan kunci Ed25519ph.

| Fungsi | Keterangan |
|---|---|
| `generate_keypair()` | Membangkitkan pasangan kunci acak: seed (32 byte) → SHA-512 → clamping → s → A = [s]B. Mengembalikan `seed_hex`, `privkey_hex`, `pubkey_hex`, `scalar_s`, `prefix`. |
| `load_keypair_from_seed(seed_hex)` | Memulihkan pasangan kunci dari seed hex yang ada. |

---

### `ed25519ph_signer.py`

Penandatanganan dokumen menggunakan Ed25519ph.

| Fungsi | Keterangan |
|---|---|
| `sign_message(seed, ph_message, ctx)` | Menandatangani satu pesan yang sudah di-pre-hash. Nonce `r` dibangkitkan secara deterministik dari `SHA-512(dom2 ‖ prefix ‖ PH(M))`. Mengembalikan `(signature, S_bytes, R_bytes, A_bytes)`. |
| `sign_pdf_batch(pdf_folder, privkey_hex, ctx, temper_rate, limit, output_folder, log_callback)` | Menandatangani seluruh PDF dalam folder. Mengukur peak memory (`tracemalloc`). Menyimpan `Signature_records.csv`. Mengembalikan `(csv_path, peak_memory_mb)`. |

---

### `ed25519ph_verifier.py`

Verifikasi tanda tangan dan validasi program.

**Kelas data:**

| Kelas | Keterangan |
|---|---|
| `SignatureRecord` | Satu rekaman tanda tangan: `filename`, `ph_message`, `R_bytes`, `S_bytes`, `A_bytes`, `tampered` |
| `VerificationResult` | Hasil verifikasi batch: `total`, `valid`, `invalid`, `invalid_files`, `time_taken`, `method` |
| `TestVectorResult` | Hasil tes vektor RFC 8032: `pubkey_match`, `verification_ok`, `passed`, `computed_signature_hex` |
| `DatasetValidationResult` | Hasil Tahap 2: `true_positive`, `true_negative`, `false_positive`, `false_negative`, `passed`, `csv_path`, `pubkey_hex`, `peak_memory_mb` |

**Fungsi:**

| Fungsi | Keterangan |
|---|---|
| `parse_signature_csv(csv_path, pubkey_bytes)` | Membaca `Signature_records.csv` dan menetapkan kunci publik dari parameter (bukan dari CSV). |
| `individual_verification(record, ctx)` | Verifikasi satu tanda tangan: `[8S]B == [8]R + [8h]A`. |
| `batch_verification(batch, ctx)` | Verifikasi batch MSM: `[8·ΣzᵢSᵢ]B == Σ([8zᵢ]Rᵢ + [8zᵢhᵢ]Aᵢ)` dengan blinding scalar 128-bit. |
| `fallback_individual_verification(batch, ctx)` | Fallback: verifikasi satu per satu jika batch gagal. |
| `verify(csv_path, pubkey_hex, ctx, batch_size, log_callback)` | Fungsi verifikasi lengkap: baca CSV → batch verification → fallback jika perlu. |
| `run_rfc8032_test_vectors(log_callback)` | Tahap 1: tes vektor resmi RFC 8032 §7.3. |
| `run_pdf_dataset_validation(pdf_folder, ctx, temper_rate, limit, batch_size, output_folder, log_callback)` | Tahap 2: validasi dataset PDF dengan confusion matrix. |
| `save_confusion_matrix_png(result, output_path, log_callback)` | Menyimpan visualisasi confusion matrix 2×2 sebagai PNG (150 DPI). |
| `ManualValidator(csv_path, pubkey_hex, ctx, pdf_folder)` | Kelas untuk uji performa Tahap 3. Fase 1: `run_signing_memory_phase()` — peak RAM per dokumen. Fase 2: `run_individual()`, `run_batch()`, `compare()` — waktu dan peak RAM Individual vs Batch MSM. |

---

### `make_data.py`

Generator dataset PDF sintetis untuk pengujian.

| Fungsi | Keterangan |
|---|---|
| `buat_pdf(target_kb, nama_file, seed_acak)` | Membangun berkas PDF valid (struktur PDF 1.4 lengkap dengan xref table) berisi teks Lorem Ipsum berukuran mendekati `target_kb` KB. |
| `sha512_file(path)` | Menghitung SHA-512 suatu berkas secara streaming (efisien untuk berkas besar). |
| `generate_dataset(jumlah, min_kb, max_kb, out_dir)` | Menghasilkan `jumlah` berkas PDF dengan ukuran acak dalam rentang `[min_kb, max_kb]` KB dan menyimpan metadata ke `metadata.csv`. |

---

## Alur Kerja Sistem

```
Penandatanganan
───────────────
Folder PDF → [sign_pdf_batch]
  ├─ Baca file PDF (bytes)
  ├─ Pre-hash: PH(M) = SHA-512(M)         ← konten PDF dibuang dari memori
  ├─ Nonce deterministik: r = SHA-512(dom2 ‖ prefix ‖ PH(M)) mod l
  ├─ R = [r]B
  ├─ h = SHA-512(dom2 ‖ R ‖ A ‖ PH(M)) mod l
  ├─ S = (r + h·s) mod l
  └─ Signature = R ‖ S
       ↓
  Signature_records.csv  +  public_key.hex

Verifikasi (Batch)
──────────────────
Signature_records.csv  +  pubkey_hex (dari sumber terpercaya)
       ↓
  [batch_verification] — MSM dengan blinding scalar zᵢ acak 128-bit
  [8·Σ(zᵢ·Sᵢ)]·B  ==  Σ([8·zᵢ]·Rᵢ + [8·zᵢ·hᵢ]·Aᵢ)
       ↓ Gagal?
  [fallback_individual_verification] — isolasi dokumen tidak valid
```

---

## Format File Output

### `Signature_records.csv`

| Kolom | Tipe | Keterangan |
|---|---|---|
| `filename` | string | Nama berkas PDF |
| `prehash` | hex (128 karakter) | SHA-512 dari konten PDF: `PH(M)` |
| `R` | hex (64 karakter) | Komponen R dari tanda tangan (32 byte) |
| `S` | hex (64 karakter) | Komponen S dari tanda tangan (32 byte) |
| `Signature` | hex (128 karakter) | Tanda tangan lengkap `R ‖ S` |
| `tampered` | boolean | `True` jika tanda tangan sengaja dirusak |

> Kunci publik **tidak** disimpan di CSV. Kolom `tampered` digunakan hanya untuk keperluan evaluasi ground truth pada Tahap 2 validasi.

### `public_key.hex`

Berkas teks berisi 64 karakter hex (32 byte) kunci publik A. Dapat dimuat langsung pada tab Batch Verification menggunakan tombol **Muat .hex**.

### `confusion_matrix.png`

Visualisasi confusion matrix 2×2 hasil Tahap 2 (150 DPI):
- **TP** (hijau) — dokumen valid, diprediksi valid
- **TN** (hijau) — dokumen dirusak, diprediksi tidak valid
- **FP** (merah) — dokumen dirusak, diprediksi valid *(kesalahan)*
- **FN** (merah) — dokumen valid, diprediksi tidak valid *(kesalahan)*

---

## Validasi Program

Program dilengkapi tiga tahap validasi yang dapat dijalankan sekaligus dari Tab Validasi Program:

| Tahap | Metode | Kriteria Lulus |
|---|---|---|
| 1 | Tes vektor RFC 8032 §7.3 (TEST abc) | Kunci publik cocok dengan nilai resmi RFC, verifikasi round-trip berhasil |
| 2 | Dataset PDF sintetis (valid + dirusak) dengan confusion matrix | FP = 0 dan FN = 0 |
| 3 | Uji performa waktu & memori (tracemalloc, 2 fase) | Peak RAM stabil pada Fase 1 (signing); Fase 2 membuktikan verifikator tidak memuat ulang PDF asli |

Laporan lengkap ketiga tahap dapat disimpan sebagai satu berkas TXT menggunakan tombol **Simpan Laporan Lengkap (TXT)**.
