import os
import csv
import hashlib
import random
import time
import sys

JUMLAH_DOK_DEFAULT = 10000  
MIN_KB_DEFAULT     = 1000       
MAX_KB_DEFAULT     = 10000     
OUTPUT_DIR_DEFAULT = "dataset" 

def buat_pdf(target_kb: int, nama_file: str, seed_acak: int) -> bytes:
    target_bytes = target_kb * 1024
    overhead     = 700   
    pad_size     = max(0, target_bytes - overhead)
    rng  = random.Random(seed_acak)
    kosa = (
        "lorem ipsum dolor sit amet consectetur adipiscing elit "
        "sed do eiusmod tempor incididunt ut labore et dolore magna "
        "aliqua ut enim ad minim veniam quis nostrud exercitation "
        "ullamco laboris nisi ut aliquip ex ea commodo consequat "
        "duis aute irure dolor in reprehenderit in voluptate velit "
        "esse cillum dolore eu fugiat nulla pariatur excepteur sint "
        "occaecat cupidatat non proident sunt in culpa qui officia "
    )
    padding = (kosa * ((pad_size // len(kosa)) + 2))[:pad_size]
    padding_bytes = padding.encode("latin-1", errors="replace")
    isi_stream = (
        f"BT\n"
        f"/F1 11 Tf\n"
        f"50 770 Td\n"
        f"({nama_file}) Tj\n"
        f"0 -18 Td\n"
        f"(Dokumen sintetis untuk penelitian batch verification Ed25519ph) Tj\n"
        f"ET\n"
    ).encode() + b"\n% " + padding_bytes

    panjang_stream = len(isi_stream)
    obj1 = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    obj2 = b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    obj3 = (
        b"3 0 obj\n"
        b"<< /Type /Page\n"
        b"   /Parent 2 0 R\n"
        b"   /MediaBox [0 0 595 842]\n"
        b"   /Contents 4 0 R\n"
        b"   /Resources << /Font << /F1 << /Type /Font\n"
        b"      /Subtype /Type1\n"
        b"      /BaseFont /Helvetica >> >> >> >>\n"
        b"endobj\n"
    )
    obj4 = (
        f"4 0 obj\n<< /Length {panjang_stream} >>\nstream\n".encode()
        + isi_stream
        + b"\nendstream\nendobj\n"
    )
    header = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    badan  = header + obj1 + obj2 + obj3 + obj4
    offsets = []
    pos     = len(header)
    for obj in [obj1, obj2, obj3, obj4]:
        offsets.append(pos)
        pos += len(obj)
        xref_offset = pos
    xref  = b"xref\n0 5\n"
    xref += b"0000000000 65535 f \n"
    for off in offsets:
        xref += f"{off:010d} 00000 n \n".encode()
    trailer = (
        b"trailer\n"
        b"<< /Size 5 /Root 1 0 R >>\n"
        b"startxref\n"
        + str(xref_offset).encode()
        + b"\n%%EOF\n"
    )

    return badan + xref + trailer

def sha512_file(path: str) -> str:
    """Hitung SHA-512 dari file secara streaming."""
    h = hashlib.sha512()
    with open(path, "rb") as f:
        while blok := f.read(65536):
            h.update(blok)
    return h.hexdigest()

def generate_dataset(
    jumlah   : int = JUMLAH_DOK_DEFAULT,
    min_kb   : int = MIN_KB_DEFAULT,
    max_kb   : int = MAX_KB_DEFAULT,
    out_dir  : str = OUTPUT_DIR_DEFAULT,
):
    assert jumlah > 0,     "Jumlah dokumen harus > 0"
    assert min_kb > 0,     "Ukuran minimum harus > 0 KB"
    assert max_kb > min_kb,"Ukuran maksimum harus > minimum"

    folder_pdf = os.path.join(out_dir, "pdf")
    os.makedirs(folder_pdf, exist_ok=True)

    print("=" * 60)
    print("  Generator Dataset PDF Acak")
    print("  Batch Verification Ed25519ph")
    print("=" * 60)
    print(f"\n  Jumlah dokumen : {jumlah:,}")
    print(f"  Ukuran rentang : {min_kb:,} KB  —  {max_kb:,} KB")
    print(f"  Folder output  : {out_dir}/")
    print()

    rng_ukuran = random.Random(42)  
    ukuran_list = [
        rng_ukuran.randint(min_kb, max_kb)
        for _ in range(jumlah)
    ]

    baris_meta = []
    t_mulai    = time.perf_counter()

    for i in range(jumlah):
        nomor     = i + 1
        nama_file = f"doc_{nomor}.pdf"
        path_file = os.path.join(folder_pdf, nama_file)
        target_kb = ukuran_list[i]
        halaman   = max(1, target_kb // 80)

        pdf_bytes = buat_pdf(target_kb, nama_file, seed_acak=nomor * 7919)
        with open(path_file, "wb") as f:
            f.write(pdf_bytes)

        ukuran_aktual = round(os.path.getsize(path_file) / 1024, 2)
        sha           = sha512_file(path_file)

        baris_meta.append({
            "file_name" : nama_file,
            "size_kb"   : ukuran_aktual,
            "pages"     : halaman,
            "sha512"    : sha,
        })

        if nomor % 100 == 0 or nomor == jumlah:
            elapsed = time.perf_counter() - t_mulai
            persen  = nomor / jumlah * 100
            print(f"  [{persen:5.1f}%] {nomor:>5}/{jumlah}"
                  f"  {nama_file}  ({ukuran_aktual:.1f} KB)"
                  f"  [{elapsed:.1f}s]")

    path_meta = os.path.join(out_dir, "metadata.csv")
    with open(path_meta, "w", newline="", encoding="utf-8") as f:
        penulis = csv.DictWriter(
            f,
            fieldnames=["file_name", "size_kb", "pages", "sha512"],
            delimiter=";",
        )
        penulis.writeheader()
        penulis.writerows(baris_meta)

    total_detik = time.perf_counter() - t_mulai
    ukuran_semua = [b["size_kb"] for b in baris_meta]
    rata2   = sum(ukuran_semua) / len(ukuran_semua)
    total_mb = sum(ukuran_semua) / 1024

    print()
    print("=" * 60)
    print(f"  Selesai dalam {total_detik:.1f} detik")
    print()
    print(f"  Total dokumen     : {jumlah:,}")
    print(f"  Ukuran minimum    : {min(ukuran_semua):.1f} KB")
    print(f"  Ukuran rata-rata  : {rata2:.1f} KB")
    print(f"  Ukuran maksimum   : {max(ukuran_semua):.1f} KB")
    print(f"  Total ukuran      : {total_mb:.1f} MB")
    print(f"  Folder PDF        : {folder_pdf}/")
    print(f"  Metadata          : {path_meta}")
    print("=" * 60)
    print()


if __name__ == "__main__":
    jumlah  = int(sys.argv[1]) if len(sys.argv) > 1 else JUMLAH_DOK_DEFAULT
    min_kb  = int(sys.argv[2]) if len(sys.argv) > 2 else MIN_KB_DEFAULT
    max_kb  = int(sys.argv[3]) if len(sys.argv) > 3 else MAX_KB_DEFAULT
    out_dir =     sys.argv[4]  if len(sys.argv) > 4 else OUTPUT_DIR_DEFAULT

    generate_dataset(
        jumlah  = jumlah,
        min_kb  = min_kb,
        max_kb  = max_kb,
        out_dir = out_dir,
    )
