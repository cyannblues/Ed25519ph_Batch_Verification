import csv
import hashlib
import secrets
import time
import tracemalloc
from dataclasses import dataclass, field
from typing import List, Tuple

from ed25519ph_function import (
    l, BASE_POINT,
    scalar_mult,
    point_add,
    encode_point,
    decode_point,
    point_identity,
    scalar_clamping,
    dom2
)
from ed25519ph_signer import sign_message, sign_pdf_batch
from ed25519ph_key_generator import generate_keypair


@dataclass
class SignatureRecord:
    filename: str
    ph_message: bytes
    R_bytes: bytes
    S_bytes: bytes
    A_bytes: bytes
    tampered: bool = False


@dataclass
class VerificationResult:
    total: int = 0
    valid: int = 0
    invalid: int = 0
    invalid_files: List[str] = field(default_factory=list)
    time_taken: float = 0.0
    method: str = ""
    detail: List[str] = field(default_factory=list)
    records: List[SignatureRecord] = field(default_factory=list)


@dataclass
class TestVectorResult:
    name: str
    pubkey_match: bool
    verification_ok: bool
    passed: bool
    computed_signature_hex: str = ""
    detail: str = ""


RFC8032_ED25519PH_VECTORS = [
    {
        'name': 'RFC 8032 §7.3 - Ed25519ph TEST abc',
        'secret_key': '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42',
        'public_key': 'ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf',
        'message': '616263',  # "abc"
        'context': '',
    },
]


def run_rfc8032_test_vectors(log_callback=None) -> List[TestVectorResult]:
    results = []

    for vec in RFC8032_ED25519PH_VECTORS:
        name = vec['name']
        try:
            secret_key = bytes.fromhex(vec['secret_key'])
            expected_pubkey = bytes.fromhex(vec['public_key'])
            message = bytes.fromhex(vec['message'])
            ctx_bytes = vec['context'].encode('utf-8') if vec['context'] else b""

            ph_message = hashlib.sha512(message).digest()

            s = scalar_clamping(hashlib.sha512(secret_key).digest()[:32])
            computed_pubkey = encode_point(scalar_mult(s, BASE_POINT))
            pubkey_match = (computed_pubkey == expected_pubkey)

            signature, S_bytes, R_bytes, A_bytes = sign_message(secret_key, ph_message, ctx_bytes)
            record = SignatureRecord(
                filename=name,
                ph_message=ph_message,
                R_bytes=R_bytes,
                S_bytes=S_bytes,
                A_bytes=A_bytes
            )
            verification_ok = individual_verification(record, ctx_bytes)

            passed = pubkey_match and verification_ok
            detail = (
                f"Public Key cocok dengan RFC 8032 §7.3 : {'YA' if pubkey_match else 'TIDAK'}\n"
                f"Verifikasi sign->verify (round-trip)  : {'LOLOS' if verification_ok else 'GAGAL'}\n"
                f"Signature hasil komputasi (hex)       : {signature.hex()}\n"
                f"(Cocokkan manual dengan SIGNATURE pada RFC 8032 §7.3 bila diperlukan)"
            )

            result = TestVectorResult(
                name=name,
                pubkey_match=pubkey_match,
                verification_ok=verification_ok,
                passed=passed,
                computed_signature_hex=signature.hex(),
                detail=detail
            )

        except Exception as e:
            result = TestVectorResult(
                name=name,
                pubkey_match=False,
                verification_ok=False,
                passed=False,
                detail=f"Error: {e}"
            )

        results.append(result)

        if log_callback:
            status = "PASS" if result.passed else "FAIL"
            log_callback(f"[{status}] {result.name}")
            for line in result.detail.splitlines():
                log_callback(f"    {line}")

    return results


@dataclass
class DatasetValidationResult:
    n_valid: int
    n_tampered: int
    total: int
    true_positive: int
    true_negative: int
    false_positive: int
    false_negative: int
    passed: bool
    time_taken: float = 0.0
    method: str = ""
    csv_path: str = ""
    pubkey_hex: str = ""
    peak_memory_mb: float = 0.0
    report: str = ""


def run_pdf_dataset_validation(
        pdf_folder: str,
        ctx: str = "",
        temper_rate: float = 50.0,
        limit: int = 0,
        batch_size: int = 0,
        output_folder: str = ".",
        log_callback=None
) -> DatasetValidationResult:
    ctx_bytes = ctx.encode('utf-8') if isinstance(ctx, str) else ctx

    kp = generate_keypair()

    if log_callback:
        log_callback("[Tahap 2] Membangkitkan pasangan kunci sementara untuk validasi...")
        log_callback(f"[Tahap 2] Kunci publik A: {kp['pubkey_hex']}")
        log_callback(f"[Tahap 2] Menandatangani dataset PDF pada folder: {pdf_folder}")
        log_callback(f"[Tahap 2] Temper rate: {temper_rate}% (sebagian dokumen sengaja dirusak: S diubah +1 mod l)")

    csv_path, peak_mb = sign_pdf_batch(
        pdf_folder=pdf_folder,
        privkey_hex=kp['privkey_hex'],
        ctx=ctx,
        temper_rate=temper_rate,
        limit=limit,
        output_folder=output_folder,
        log_callback=log_callback
    )

    pubkey_bytes = bytes.fromhex(kp['pubkey_hex'])
    records = parse_signature_csv(csv_path, pubkey_bytes)

    ground_truth = {r.filename: (not r.tampered) for r in records}
    n_tampered = sum(1 for r in records if r.tampered)
    n_valid = len(records) - n_tampered

    if log_callback:
        log_callback(f"[Tahap 2] Total dokumen: {len(records)} "
                      f"({n_valid} valid, {n_tampered} dirusak)")
        log_callback("[Tahap 2] Menjalankan batch verification...")

    result = _verify_batch_raw(records, ctx_bytes, batch_size, log_callback)

    invalid_set = set(result.invalid_files)
    tp = tn = fp = fn = 0
    for r in records:
        actually_valid = ground_truth[r.filename]
        predicted_valid = r.filename not in invalid_set
        if actually_valid and predicted_valid:
            tp += 1
        elif actually_valid and not predicted_valid:
            fn += 1
        elif (not actually_valid) and predicted_valid:
            fp += 1
        else:
            tn += 1

    passed = (fp == 0 and fn == 0)

    report_lines = [
        "=== VALIDASI TAHAP 2: DATASET DOKUMEN PDF (VALID vs DIRUSAK) ===",
        f"Folder dataset PDF     : {pdf_folder}",
        f"Berkas CSV             : {csv_path}",
        f"Kunci publik A         : {kp['pubkey_hex']}",
        f"String konteks         : '{ctx}'",
        f"Temper rate            : {temper_rate}%",
        f"Jumlah dokumen valid   : {n_valid}",
        f"Jumlah dokumen dirusak : {n_tampered} (S diubah +1 mod l)",
        f"Total dokumen          : {len(records)}",
        f"Metode verifikasi      : {result.method}",
        f"Ukuran batch           : {batch_size if batch_size > 0 else 'semua (1 batch)'}",
        f"Waktu proses           : {result.time_taken:.2f} ms",
        f"Peak Memory (sign)     : {peak_mb:.4f} MB",
        "",
        "Confusion Matrix (dibandingkan dengan kondisi sebenarnya):",
        f"  True Positive  (valid -> dinyatakan valid)        : {tp}",
        f"  True Negative  (dirusak -> dinyatakan tidak valid): {tn}",
        f"  False Positive (dirusak -> dinyatakan valid)      : {fp}",
        f"  False Negative (valid -> dinyatakan tidak valid)  : {fn}",
        "",
        f"Kesimpulan: {'IMPLEMENTASI VALID (FP=0, FN=0; seluruh klasifikasi sesuai kondisi sebenarnya)' if passed else 'IMPLEMENTASI TIDAK VALID (ditemukan FP dan/atau FN)'}",
    ]
    report = "\n".join(report_lines)

    if log_callback:
        for line in report_lines:
            log_callback(line)

    return DatasetValidationResult(
        n_valid=n_valid,
        n_tampered=n_tampered,
        total=len(records),
        true_positive=tp,
        true_negative=tn,
        false_positive=fp,
        false_negative=fn,
        passed=passed,
        time_taken=result.time_taken,
        method=result.method,
        csv_path=csv_path,
        pubkey_hex=kp['pubkey_hex'],
        peak_memory_mb=peak_mb,
        report=report
    )


def save_confusion_matrix_png(
        result: DatasetValidationResult,
        output_path: str,
        log_callback=None
) -> str:
    
    import matplotlib
    matplotlib.use('Agg') 
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import numpy as np

    tp = result.true_positive
    tn = result.true_negative
    fp = result.false_positive
    fn = result.false_negative
    total = result.total

    matrix = np.array([[tp, fn],
                       [fp, tn]])

    cell_labels = np.array([
        [f"TP\n{tp}", f"FN\n{fn}"],
        [f"FP\n{fp}", f"TN\n{tn}"],
    ])

    cell_colors = np.array([
        ["#4caf50", "#f44336"],
        ["#f44336", "#4caf50"],
    ])
    text_colors = [["white", "white"], ["white", "white"]]

    fig, ax = plt.subplots(figsize=(7, 5.5))
    fig.patch.set_facecolor('#f9f9f9')
    ax.set_facecolor('#f9f9f9')

    for i in range(2):
        for j in range(2):
            rect = mpatches.FancyBboxPatch(
                (j + 0.05, 1 - i + 0.05), 0.9, 0.9,
                boxstyle="round,pad=0.05",
                linewidth=1.5,
                edgecolor='white',
                facecolor=cell_colors[i][j]
            )
            ax.add_patch(rect)
            pct = f"\n({matrix[i, j] / total * 100:.1f}%)" if total > 0 else ""
            ax.text(
                j + 0.5, 1 - i + 0.5,
                cell_labels[i, j] + pct,
                ha='center', va='center',
                fontsize=16, fontweight='bold',
                color=text_colors[i][j],
                linespacing=1.6
            )

    ax.set_xlim(0, 2)
    ax.set_ylim(0, 2)
    ax.set_xticks([0.5, 1.5])
    ax.set_xticklabels(['Prediksi: VALID', 'Prediksi: TIDAK VALID'],
                        fontsize=11, fontweight='bold')
    ax.set_yticks([0.5, 1.5])
    ax.set_yticklabels(['Aktual: DIRUSAK', 'Aktual: VALID'],
                        fontsize=11, fontweight='bold', rotation=90, va='center')
    ax.tick_params(length=0)
    ax.xaxis.set_label_position('top')
    ax.xaxis.tick_top()

    status = "IMPLEMENTASI VALID ✓" if result.passed else "IMPLEMENTASI TIDAK VALID ✗"
    status_color = "#2e7d32" if result.passed else "#c62828"
    fig.suptitle(
        "Confusion Matrix – Batch Verification Ed25519ph",
        fontsize=14, fontweight='bold', y=1.02
    )
    ax.set_title(
        f"Total: {total} dokumen  |  Valid: {result.n_valid}  |  Dirusak: {result.n_tampered}"
        f"\nWaktu: {result.time_taken:.2f} ms  |  {status}",
        fontsize=10, color=status_color, pad=14
    )

    legend_items = [
        mpatches.Patch(color='#4caf50', label='Klasifikasi Benar (TP / TN)'),
        mpatches.Patch(color='#f44336', label='Klasifikasi Salah (FP / FN)'),
    ]
    ax.legend(
        handles=legend_items,
        loc='lower center',
        bbox_to_anchor=(0.5, -0.13),
        ncol=2, fontsize=9,
        framealpha=0.7
    )

    for spine in ax.spines.values():
        spine.set_visible(False)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight',
                facecolor=fig.get_facecolor())
    plt.close(fig)

    if log_callback:
        log_callback(f"[INFO] Confusion matrix disimpan ke: {output_path}")

    return output_path


def parse_signature_csv(csv_path: str, pubkey_bytes: bytes) -> List[SignatureRecord]:
    if len(pubkey_bytes) != 32:
        raise ValueError(f"Kunci publik harus 32 byte, didapat {len(pubkey_bytes)} byte")

    records = []
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            required = {'filename', 'prehash', 'R', 'S'}
            if not required.issubset(set(reader.fieldnames or [])):
                raise ValueError(
                    f"File CSV tidak memiliki kolom yang diperlukan: {required}. "
                    f"Kolom ditemukan: {reader.fieldnames}"
                )

            for i, row in enumerate(reader):
                try:
                    tampered_val = str(row.get('tampered', '')).strip().lower() in ('true', '1', 'yes')
                    records.append(SignatureRecord(
                        filename=row['filename'],
                        ph_message=bytes.fromhex(row['prehash']),
                        A_bytes=pubkey_bytes,
                        R_bytes=bytes.fromhex(row['R']),
                        S_bytes=bytes.fromhex(row['S']),
                        tampered=tampered_val
                    ))
                except Exception as e:
                    print(f"Error parsing baris {i + 2}: {e}")

    except FileNotFoundError:
        raise FileNotFoundError(f"File CSV tidak ditemukan: {csv_path}")

    return records


def individual_verification(record: SignatureRecord, ctx: bytes = b"") -> bool:
    try:
        S = int.from_bytes(record.S_bytes, 'little')
        if not (0 <= S < l):
            print(f"Nilai S tidak valid pada {record.filename}")
            return False

        A = decode_point(record.A_bytes)
        R = decode_point(record.R_bytes)

        dom = dom2(1, ctx)
        h_digest = hashlib.sha512(dom + record.R_bytes + record.A_bytes + record.ph_message).digest()
        h = int.from_bytes(h_digest, 'little') % l

        left_side = scalar_mult((8 * S) % l, BASE_POINT)
        left_bytes = encode_point(left_side)

        right_side = point_add(scalar_mult(8 % l, R), scalar_mult((8 * h) % l, A))
        right_bytes = encode_point(right_side)

        return left_bytes == right_bytes

    except Exception as e:
        print(f"Error memverifikasi {record.filename}: {e}")
        return False


def batch_verification(batch: List[SignatureRecord], ctx: bytes = b"") -> Tuple[bool, List[str]]:
    dom = dom2(1, ctx)
    n = len(batch)

    z_i = [secrets.randbits(128) for _ in range(n)]

    z_S = 0
    for i, record in enumerate(batch):
        S_int = int.from_bytes(record.S_bytes, 'little')
        if not (0 <= S_int < l):
            print(f"Nilai S tidak valid pada {record.filename}")
            return False, []
        z_S = (z_S + z_i[i] * S_int) % l

    left_side = scalar_mult((8 * z_S) % l, BASE_POINT)
    right_side = point_identity()

    for i, record in enumerate(batch):
        try:
            A = decode_point(record.A_bytes)
            R = decode_point(record.R_bytes)

            h_digest = hashlib.sha512(dom + record.R_bytes + record.A_bytes + record.ph_message).digest()
            h_i = int.from_bytes(h_digest, 'little') % l

            coef_R = (8 * z_i[i]) % l
            coef_A = (8 * z_i[i] * h_i) % l

            right_side = point_add(right_side, scalar_mult(coef_R, R))
            right_side = point_add(right_side, scalar_mult(coef_A, A))

        except Exception as e:
            print(f"Error memproses berkas {record.filename}: {e}")
            return False, []

    left_bytes = encode_point(left_side)
    right_bytes = encode_point(right_side)

    return left_bytes == right_bytes, []


def fallback_individual_verification(
        batch: List[SignatureRecord],
        ctx: bytes = b"",
        log_callback=None
) -> List[str]:
    invalid_files = []
    for record in batch:
        if not individual_verification(record, ctx):
            invalid_files.append(record.filename)
            if log_callback:
                log_callback(f"  -> {record.filename} GAGAL verifikasi individual.")
    return invalid_files


def _verify_batch_raw(records: List[SignatureRecord], ctx_bytes: bytes,
                       batch_size: int, log_callback=None) -> VerificationResult:
    total_records = len(records)
    result = VerificationResult(total=total_records, method="Batch", records=records)

    if total_records == 0:
        return result

    if batch_size <= 0:
        batch_size = total_records

    start_time = time.perf_counter()

    for batch_start in range(0, total_records, batch_size):
        batch = records[batch_start:batch_start + batch_size]
        batch_no = batch_start // batch_size + 1

        if log_callback:
            log_callback(f"Memverifikasi batch ke-{batch_no} ({len(batch)} dokumen)...")

        batch_valid, _ = batch_verification(batch, ctx_bytes)

        if batch_valid:
            result.valid += len(batch)
            if log_callback:
                log_callback(f"Batch ke-{batch_no} VALID (persamaan agregat terpenuhi).")
        else:
            if log_callback:
                log_callback(f"Batch ke-{batch_no} TIDAK VALID. Melakukan verifikasi individual...")
            invalid_files = fallback_individual_verification(batch, ctx_bytes, log_callback)
            result.invalid += len(invalid_files)
            result.valid += len(batch) - len(invalid_files)
            result.invalid_files.extend(invalid_files)

    elapsed_time = (time.perf_counter() - start_time) * 1000
    result.time_taken = elapsed_time

    if log_callback:
        log_callback(f"Verifikasi selesai dalam {elapsed_time:.2f} ms.")
        log_callback(f"Total: {result.total}, Valid: {result.valid}, Tidak Valid: {result.invalid}")
        if result.invalid_files:
            log_callback("Berkas tidak valid:")
            for filename in result.invalid_files:
                log_callback(f"  - {filename}")

    return result


def verify(
        csv_path: str,
        pubkey_hex: str,
        ctx: str = "",
        batch_size: int = 0,
        log_callback=None
) -> VerificationResult:
    ctx_bytes = ctx.encode('utf-8') if isinstance(ctx, str) else ctx
    pubkey_bytes = bytes.fromhex(pubkey_hex)

    if log_callback:
        log_callback("Membaca rekaman tanda tangan dari CSV...")

    records = parse_signature_csv(csv_path, pubkey_bytes)
    total_records = len(records)

    if log_callback:
        log_callback(f"Total rekaman yang akan diverifikasi: {total_records}")

    if total_records == 0:
        return VerificationResult(total=0, method="Batch")

    return _verify_batch_raw(records, ctx_bytes, batch_size, log_callback)


class ManualValidator:
    def __init__(self, csv_path: str, pubkey_hex: str, ctx: str = "",
                 pdf_folder: str = ""):
        self.csv_path = csv_path
        self.ctx_bytes = ctx.encode('utf-8') if isinstance(ctx, str) else ctx
        self.pubkey_bytes = bytes.fromhex(pubkey_hex)
        self.pubkey_hex = pubkey_hex
        self.pdf_folder = pdf_folder 
        self.records = parse_signature_csv(csv_path, self.pubkey_bytes)


    def run_signing_memory_phase(self, log_callback=None) -> List[dict]:
        from ed25519ph_signer import sign_message as _sign_message
        from pathlib import Path

        if not self.pdf_folder:
            raise ValueError("pdf_folder harus diisi untuk mengukur fase penandatanganan.")

        pdf_path = Path(self.pdf_folder)
        seed = bytes.fromhex(
            hashlib.sha512(self.pubkey_bytes).hexdigest()[:64]
        )
        seed = secrets.token_bytes(32)

        rows = []
        total = len(self.records)

        for i, rec in enumerate(self.records):
            pdf_file = pdf_path / rec.filename
            if not pdf_file.exists():
                if log_callback:
                    log_callback(f"  [Fase 1] Lewati {rec.filename} (berkas tidak ditemukan)")
                continue

            tracemalloc.start()
            t0 = time.perf_counter()

            with open(pdf_file, 'rb') as f:
                content = f.read()
            size_kb = len(content) / 1024
            ph = hashlib.sha512(content).digest()
            del content        
            _sign_message(seed, ph, self.ctx_bytes)

            elapsed_ms = (time.perf_counter() - t0) * 1000
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            rows.append({
                'filename': rec.filename,
                'size_kb': round(size_kb, 2),
                'peak_mb': round(peak / (1024 * 1024), 6),
                'time_ms': round(elapsed_ms, 4),
            })

            if log_callback and (i + 1) % max(1, total // 10) == 0:
                log_callback(f"  [Fase 1] {i + 1}/{total} dokumen diukur, "
                              f"terakhir: {rec.filename} "
                              f"({size_kb:.1f} KB → {peak / (1024*1024):.6f} MB)")

        return rows


    def run_individual(self, log_callback=None) -> dict:
        if log_callback:
            log_callback("[Fase 2] Menjalankan verifikasi INDIVIDUAL...")

        tracemalloc.start()
        start = time.perf_counter()

        invalid_files = []
        for record in self.records:
            if not individual_verification(record, self.ctx_bytes):
                invalid_files.append(record.filename)

        elapsed_ms = (time.perf_counter() - start) * 1000
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        return {
            'method': 'Individual',
            'total': len(self.records),
            'invalid_files': invalid_files,
            'time_ms': elapsed_ms,
            'peak_mb': peak / (1024 * 1024),
        }

    def run_batch(self, batch_size: int = 0, log_callback=None) -> dict:
        if log_callback:
            log_callback("[Fase 2] Menjalankan BATCH VERIFICATION (MSM)...")

        bs = batch_size if batch_size > 0 else len(self.records)
        if bs <= 0:
            bs = 1

        tracemalloc.start()
        start = time.perf_counter()

        invalid_files = []
        for i in range(0, len(self.records), bs):
            batch = self.records[i:i + bs]
            ok, _ = batch_verification(batch, self.ctx_bytes)
            if not ok:
                invalid_files.extend(fallback_individual_verification(batch, self.ctx_bytes))

        elapsed_ms = (time.perf_counter() - start) * 1000
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        return {
            'method': 'Batch',
            'total': len(self.records),
            'invalid_files': invalid_files,
            'time_ms': elapsed_ms,
            'peak_mb': peak / (1024 * 1024),
            'batch_size': bs,
        }

    def compare(self, batch_size: int = 0, log_callback=None) -> dict:
        if not self.records:
            empty_report = "Tidak ada rekaman pada CSV untuk diuji."
            if log_callback:
                log_callback(empty_report)
            return {'individual': None, 'batch': None, 'speedup': 0.0,
                    'mem_ratio': 0.0, 'report': empty_report}

        individual = self.run_individual(log_callback)
        batch = self.run_batch(batch_size, log_callback)

        speedup = (individual['time_ms'] / batch['time_ms']) if batch['time_ms'] > 0 else float('inf')
        mem_ratio = (individual['peak_mb'] / batch['peak_mb']) if batch['peak_mb'] > 0 else float('inf')

        report_lines = [
            "--- FASE 2: BATCH VERIFICATION (Waktu & Memori Verifikator) ---",
            f"Berkas CSV           : {self.csv_path}",
            f"String konteks       : '{self.ctx_bytes.decode('utf-8', errors='replace')}'",
            f"Total dokumen (baris): {individual['total']}",
            f"Ukuran batch         : {batch['batch_size']}",
            f"Catatan              : Verifikator HANYA membaca pre-hash 64 byte",
            f"                       dari CSV — dokumen PDF asli tidak dimuat ulang.",
            "",
            f"{'Metode':<16}{'Waktu (ms)':<16}{'Peak RAM (MB)':<16}",
            f"{'Individual':<16}{individual['time_ms']:<16.4f}{individual['peak_mb']:<16.6f}",
            f"{'Batch (MSM)':<16}{batch['time_ms']:<16.4f}{batch['peak_mb']:<16.6f}",
            "",
            f"Speedup waktu  (Individual / Batch) : {speedup:.4f}x",
            f"Rasio memori   (Individual / Batch) : {mem_ratio:.4f}x",
            "",
            f"Dokumen tidak valid (Individual) : {individual['invalid_files'] or '-'}",
            f"Dokumen tidak valid (Batch)      : {batch['invalid_files'] or '-'}",
        ]
        report = "\n".join(report_lines)

        if log_callback:
            for line in report_lines:
                log_callback(line)

        return {
            'individual': individual,
            'batch': batch,
            'speedup': speedup,
            'mem_ratio': mem_ratio,
            'report': report,
        }
