"""
================================================================
    UTS KRIPTOGRAFI
    Materi   : MD5 dan SHA-256
    Tugas    : Aplikasi Pengecekan Integritas File Menggunakan Hashing
================================================================
"""

import hashlib
import os
from datetime import datetime


# ================================================================
#  BAGIAN 1 : FUNGSI HASHING
# ================================================================

def hitung_md5(filepath: str) -> str:
    """
    Menghitung nilai hash MD5 dari sebuah file.
    File dibaca dalam potongan (chunk) 8 KB agar hemat RAM
    saat memproses file berukuran besar.
    """
    hasher = hashlib.md5()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def hitung_sha256(filepath: str) -> str:
    """
    Menghitung nilai hash SHA-256 dari sebuah file.
    SHA-256 menghasilkan digest 256-bit, lebih aman dari MD5.
    """
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def hitung_hash_string(teks: str) -> dict:
    """
    Menghitung MD5 dan SHA-256 dari input string.
    Digunakan untuk demonstrasi Avalanche Effect.
    """
    data = teks.encode("utf-8")
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest()
    }


# ================================================================
#  BAGIAN 2 : MANAJEMEN FILE SIMULASI
# ================================================================

def buat_file_asli(path: str, konten: str) -> None:
    """Membuat file asli sebagai baseline integritas."""
    with open(path, "w", encoding="utf-8") as f:
        f.write(konten)
    print(f"  [OK] File asli dibuat      : {path}")


def buat_file_modifikasi(path: str, konten_asli: str, tambahan: str) -> None:
    """
    Membuat versi file yang sudah dimodifikasi.
    Mensimulasikan file yang diubah oleh pihak tidak berwenang.
    """
    konten_baru = konten_asli + "\n\n" + tambahan
    with open(path, "w", encoding="utf-8") as f:
        f.write(konten_baru)
    print(f"  [OK] File modifikasi dibuat: {path}")


# ================================================================
#  BAGIAN 3 : PERBANDINGAN DAN VERIFIKASI
# ================================================================

def bandingkan_file(path_asli: str, path_modif: str) -> dict:
    """
    Membandingkan hash MD5 dan SHA-256 dari dua file.
    Mengembalikan laporan deteksi perubahan.
    """
    md5_asli    = hitung_md5(path_asli)
    md5_modif   = hitung_md5(path_modif)
    sha_asli    = hitung_sha256(path_asli)
    sha_modif   = hitung_sha256(path_modif)

    return {
        "md5": {
            "asli":    md5_asli,
            "modif":   md5_modif,
            "berubah": md5_asli != md5_modif
        },
        "sha256": {
            "asli":    sha_asli,
            "modif":   sha_modif,
            "berubah": sha_asli != sha_modif
        }
    }


def verifikasi_file(filepath: str, md5_resmi: str, sha256_resmi: str) -> dict:
    """
    Memverifikasi integritas file dengan membandingkan hash
    terhadap nilai referensi resmi (seperti saat cek checksum download).
    """
    md5_cek    = hitung_md5(filepath)
    sha256_cek = hitung_sha256(filepath)

    return {
        "md5": {
            "referensi": md5_resmi,
            "hasil":     md5_cek,
            "valid":     md5_cek == md5_resmi
        },
        "sha256": {
            "referensi": sha256_resmi,
            "hasil":     sha256_cek,
            "valid":     sha256_cek == sha256_resmi
        }
    }


# ================================================================
#  BAGIAN 4 : ANALISIS
# ================================================================

def analisis_md5_sha256() -> None:
    GARIS = "=" * 65
    GARIS2 = "-" * 65

    print(f"\n{GARIS}")
    print("  ANALISIS : MD5 vs SHA-256")
    print(GARIS)

    print("""
    A. MENGAPA MD5 TIDAK LAGI DIREKOMENDASIKAN?
    ─────────────────────────────────────────────────────────
    1. Collision Attack
        Tahun 2004, peneliti Xiaoyun Wang berhasil menemukan
        collision MD5 secara praktis — dua file berbeda bisa
        menghasilkan hash MD5 yang SAMA. Penyerang bisa membuat
        file palsu yang lolos verifikasi MD5.

    2. Hash Length Extension Attack
        Struktur Merkle-Damgard memungkinkan penyerang menambah
        data ke pesan tanpa tahu isi aslinya, hanya dengan tahu
        hash dan panjang pesan.

    3. Kecepatan = Kelemahan
        GPU modern bisa menghitung >10 miliar hash MD5/detik,
        membuat brute-force dan dictionary attack jadi mudah.

    4. Output Terlalu Pendek (128-bit)
        Ruang hash lebih kecil → probabilitas collision lebih
        tinggi dibanding SHA-256 yang berukuran 256-bit.

    B. KEUNGGULAN SHA-256
    ─────────────────────────────────────────────────────────
    1. Tahan Collision
        Belum ada collision yang ditemukan secara praktis.
        Membutuhkan ~2^128 operasi untuk menemukannya.

    2. Output 256-bit
        2^256 ≈ 1.16 × 10^77 kemungkinan — hampir mustahil
        di-brute-force dalam umur alam semesta sekalipun.

    3. Avalanche Effect Lebih Kuat
        1 bit input berubah → ~50% bit output berubah secara acak.

    4. Standar Industri
        Digunakan oleh: Bitcoin, HTTPS/TLS, Git, JWT, SSH,
        Certificate Authority, dan sistem keamanan modern lainnya.

    5. NIST & NSA Approved
        Bagian dari SHA-2 family, disahkan sebagai standar
        federal AS (FIPS 180-4).
        """)

    print(f"\n{GARIS2}")
    print("  TABEL PERBANDINGAN MD5 vs SHA-256")
    print(GARIS2)
    baris = [
        ("Ukuran output",           "128-bit (32 hex)",       "256-bit (64 hex)"),
        ("Kecepatan komputasi",     "Sangat cepat",           "Lebih lambat ~30-40%"),
        ("Collision resistance",    "LEMAH (sudah terbukti)", "Kuat (belum ada kasus)"),
        ("Preimage resistance",     "Rentan secara teoritis", "Kuat"),
        ("Length extension attack", "Rentan",                 "Tidak rentan"),
        ("Direkomendasikan NIST",   "TIDAK (sejak 2011)",     "YA"),
        ("Kegunaan saat ini",       "Non-kritis / legacy",    "Keamanan kritis"),
        ("Digunakan oleh",          "Sistem lama",            "Bitcoin, TLS, Git, JWT"),
    ]
    print(f"\n  {'Aspek':<26} {'MD5':<24} {'SHA-256'}")
    print("  " + "-" * 74)
    for b in baris:
        print(f"  {b[0]:<26} {b[1]:<24} {b[2]}")


# ================================================================
#  PROGRAM UTAMA
# ================================================================

def main():
    GARIS  = "=" * 65
    GARIS2 = "-" * 65

    print(f"\n{GARIS}")
    print("  UTS KRIPTOGRAFI — PENGECEKAN INTEGRITAS FILE")
    print(f"  Waktu: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(GARIS)

    # Siapkan folder output
    os.makedirs("output_simulasi", exist_ok=True)
    FILE_ASLI  = "output_simulasi/dokumen_asli.txt"
    FILE_MODIF = "output_simulasi/dokumen_modifikasi.txt"

    KONTEN_ASLI = (
        "DOKUMEN NILAI MAHASISWA\n"
        "========================\n"
        "Nama   : RADHITYAH WALHIDAYAH\n"
        "NIM    : 105841102724\n"
        "Matkul : Kriptografi\n"
        "Nilai  : 85\n"
        "Grade  : A\n"
        "Status : LULUS\n"
        "TTD    : [Tanda tangan dosen]\n"
    )
    MANIPULASI = (
        "[!!! DOKUMEN DIMANIPULASI !!!]\n"
        "Nilai diubah dari 85 menjadi 100 oleh pihak tidak berwenang."
    )

    # ── Langkah 1: Buat file simulasi ──
    print(f"\n{GARIS2}")
    print("  LANGKAH 1 : Membuat File Simulasi")
    print(GARIS2)
    buat_file_asli(FILE_ASLI, KONTEN_ASLI)
    buat_file_modifikasi(FILE_MODIF, KONTEN_ASLI, MANIPULASI)

    # ── Langkah 2: Tampilkan isi file ──
    print(f"\n{GARIS2}")
    print("  LANGKAH 2 : Isi File")
    print(GARIS2)
    print("\n  [ FILE ASLI ]")
    for baris in KONTEN_ASLI.strip().split("\n"):
        print(f"    {baris}")
    print("\n  [ FILE MODIFIKASI — tambahan penyerang ]")
    for baris in MANIPULASI.split("\n"):
        print(f"    {baris}")

    # ── Langkah 3: Hitung hash ──
    print(f"\n{GARIS2}")
    print("  LANGKAH 3 : Menghitung Hash")
    print(GARIS2)
    md5_asli   = hitung_md5(FILE_ASLI)
    sha_asli   = hitung_sha256(FILE_ASLI)
    md5_modif  = hitung_md5(FILE_MODIF)
    sha_modif  = hitung_sha256(FILE_MODIF)

    print(f"\n  FILE ASLI:")
    print(f"    MD5    : {md5_asli}")
    print(f"    SHA256 : {sha_asli}")
    print(f"\n  FILE MODIFIKASI:")
    print(f"    MD5    : {md5_modif}")
    print(f"    SHA256 : {sha_modif}")

    # ── Langkah 4: Bandingkan ──
    print(f"\n{GARIS2}")
    print("  LANGKAH 4 : Membandingkan Hash (Deteksi Perubahan)")
    print(GARIS2)
    hasil = bandingkan_file(FILE_ASLI, FILE_MODIF)
    for algo, info in hasil.items():
        status = "PERINGATAN — File telah diubah! ✓" if info["berubah"] else "AMAN"
        print(f"\n  [{algo.upper()}]")
        print(f"    Asli   : {info['asli']}")
        print(f"    Modif  : {info['modif']}")
        print(f"    Status : {status}")

    print(f"\n  → Kedua algoritma berhasil mendeteksi perubahan pada file.")

    # ── Langkah 5: Verifikasi integritas ──
    print(f"\n{GARIS2}")
    print("  LANGKAH 5 : Simulasi Verifikasi Checksum (seperti saat download file)")
    print(GARIS2)
    print("\n  Hash resmi yang dipublikasikan server:")
    print(f"    MD5    : {md5_asli}")
    print(f"    SHA256 : {sha_asli}")

    print("\n  [a] Verifikasi file TIDAK dimodifikasi:")
    v1 = verifikasi_file(FILE_ASLI, md5_asli, sha_asli)
    for algo, info in v1.items():
        ket = "VALID — Integritas terjaga ✓" if info["valid"] else "TIDAK VALID ✗"
        print(f"      {algo.upper()}: {ket}")

    print("\n  [b] Verifikasi file SUDAH dimodifikasi (disisipi malware/manipulasi):")
    v2 = verifikasi_file(FILE_MODIF, md5_asli, sha_asli)
    for algo, info in v2.items():
        ket = "VALID ✓" if info["valid"] else "TIDAK VALID — Integritas rusak! ✗"
        print(f"      {algo.upper()}: {ket}")

    # ── Langkah 6: Avalanche Effect ──
    print(f"\n{GARIS2}")
    print("  LANGKAH 6 : Demo Avalanche Effect (beda 1 karakter)")
    print(GARIS2)
    teks_a = "Mahasiswa2024"
    teks_b = "Mahasiswa2025"
    ha = hitung_hash_string(teks_a)
    hb = hitung_hash_string(teks_b)

    print(f"\n  Input A : '{teks_a}'")
    print(f"    MD5    : {ha['md5']}")
    print(f"    SHA256 : {ha['sha256']}")
    print(f"\n  Input B : '{teks_b}'  (beda 1 karakter)")
    print(f"    MD5    : {hb['md5']}")
    print(f"    SHA256 : {hb['sha256']}")
    print(f"\n  → Meski hanya beda 1 karakter, hash berubah TOTAL.")
    print(f"  → Inilah yang disebut Avalanche Effect.")

    # ── Analisis ──
    analisis_md5_sha256()

    print(f"\n{GARIS}")
    print("  Selesai. File simulasi tersimpan di folder output_simulasi/")
    print(GARIS)


if __name__ == "__main__":
    main()