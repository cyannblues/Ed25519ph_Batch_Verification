import os 
import csv
import hashlib
import secrets
import tracemalloc
from pathlib import Path
from ed25519ph_function import (
    p, l, d, BASE_POINT,
    scalar_clamping, 
    scalar_mult, 
    encode_point, 
    dom2
)   


def sign_message(seed_hex: bytes, ph_message: bytes, ctx: bytes) -> tuple:
    k = hashlib.sha512(seed_hex).digest()
    s = scalar_clamping(k[:32])
    prefix = k[32:] 
    A_ext = scalar_mult(s, BASE_POINT)
    A_bytes = encode_point(A_ext)

    dom = dom2(1, ctx)
    nonce = hashlib.sha512(dom + prefix + ph_message).digest()
    r = int.from_bytes(nonce, 'little') % l

    R_ext = scalar_mult(r, BASE_POINT)
    R_bytes = encode_point(R_ext)

    h_challenge = hashlib.sha512(dom + R_bytes + A_bytes + ph_message).digest()
    h = int.from_bytes(h_challenge, 'little') % l

    S_int = (r + h * s) % l
    S_bytes = S_int.to_bytes(32, 'little')
    signature = R_bytes + S_bytes

    return signature, S_bytes, R_bytes, A_bytes


def sign_pdf_batch(
        pdf_folder: str, 
        privkey_hex: str, 
        ctx: str = "", 
        temper_rate: float = 0.0, 
        limit: int = 0,
        output_folder: str = ".",
        log_callback=None
) -> tuple:
    private_key_bytes = bytes.fromhex(privkey_hex)
    if len(private_key_bytes) == 64:
        seed = private_key_bytes[:32]
    elif len(private_key_bytes) == 32:
        seed = private_key_bytes
    else:
        raise ValueError(f"Format kunci privat tidak valid: panjang {len(private_key_bytes)} byte (harus 32 atau 64 byte)")

    ctx_bytes = ctx.encode('utf-8')
    pdf_folder_path = Path(pdf_folder)
    if not pdf_folder_path.is_dir():
        raise ValueError(f"Folder PDF tidak ditemukan: {pdf_folder}")
    
    output_folder_path = Path(output_folder)
    output_folder_path.mkdir(parents=True, exist_ok=True)

    pdf_files = list(pdf_folder_path.glob("*.pdf"))
    if limit > 0:
        pdf_files = pdf_files[:limit]
    if not pdf_files:
        raise ValueError(f"Tidak ada file PDF ditemukan di folder: {pdf_folder}")
    
    total_files = len(pdf_files)
    tamper_count = int(total_files * temper_rate / 100)
    tamper_indices = set(secrets.SystemRandom().sample(range(total_files), min(tamper_count, total_files)))

    if log_callback:
        log_callback(f"Ditemukan {total_files} file PDF")
        log_callback(f"Dokumen yang akan dirusak: {len(tamper_indices)} ({temper_rate}%)")
    
    csv_path = output_folder_path / "Signature_records.csv"
    records = []
    success_count = 0
    failure_count = 0

    tracemalloc.start()

    for idx, pdf_file in enumerate(pdf_files):
        try:
            with open(pdf_file, 'rb') as f:
                content = f.read()
            file_size_kb = len(content) / 1024

            if log_callback:
                log_callback(f"[{idx + 1}/{total_files}] {pdf_file.name} ({file_size_kb:.1f} KB) - membaca & pre-hash SHA-512...")

            ph_message = hashlib.sha512(content).digest()

            if log_callback:
                log_callback(f"[{idx + 1}/{total_files}] {pdf_file.name} - menandatangani (Ed25519ph)...")

            signature, S_bytes, R_bytes, A_bytes = sign_message(seed, ph_message, ctx_bytes)

            tampered = idx in tamper_indices
            if tampered:
                S_int = int.from_bytes(S_bytes, 'little')
                S_int = (S_int + 1) % l
                S_bytes = S_int.to_bytes(32, 'little')
                signature = R_bytes + S_bytes

            if log_callback:
                status = "[DIRUSAK]" if tampered else "[OK]"
                log_callback(f"[{idx + 1}/{total_files}] {pdf_file.name} - {status} selesai.")

            records.append({
                'filename': pdf_file.name,
                'prehash': ph_message.hex(),
                'R': R_bytes.hex(),
                'S': S_bytes.hex(),
                'Signature': signature.hex(),
                'tampered': tampered
            })
            success_count += 1

        except Exception as e:
            if log_callback:
                log_callback(f"[{idx + 1}/{total_files}] {pdf_file.name} - GAGAL: {str(e)}")
            failure_count += 1
    
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['filename', 'prehash', 'R', 'S', 'Signature', 'tampered']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)

    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    peak_memory_mb = peak / (1024 * 1024)

    if log_callback:
        log_callback(f"\nProses selesai: {success_count} berhasil, {failure_count} gagal, {len(tamper_indices)} dirusak. Rekaman disimpan di {csv_path}")

    return str(csv_path), peak_memory_mb


if __name__ == "__main__":
    privkey_hex = os.urandom(32).hex()
    pdf_folder = "dataset/pdf/"
    output_folder = "output_signatures"
    keypair = {
        'seed_hex': '1f8b8c8d9e0a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123',
        'privkey_hex': privkey_hex,
    }
    ctx = "Contoh konteks untuk Ed25519ph"
    temper_rate = 10.0 

    csv_path, peak_mb = sign_pdf_batch(pdf_folder, keypair['privkey_hex'], ctx, temper_rate, limit=0, output_folder=output_folder)
    print(f"CSV: {csv_path}")
    print(f"Peak memory: {peak_mb:.4f} MB")
