# PQC Migration Trilemma Demo

Proyek Rust ini adalah simulasi eksperimental yang mendemonstrasikan resolusi untuk **Trilema Migrasi Kriptografi Pasca-Kuantum (PQC)** pada infrastruktur blockchain. 

Migrasi menuju algoritma tahan kuantum sering kali mengorbankan salah satu dari tiga aspek utama: **Keamanan**, **Kompatibilitas**, atau **Skalabilitas**. Proyek ini mensimulasikan arsitektur yang mengamankan ketiga pilar tersebut sekaligus.

## Fitur & Solusi Trilema

1. **Keamanan: Mitigasi *Quantum Front-Running* (Commit-and-Reveal)**
   Komputer kuantum (menggunakan Algoritma Grover) berpotensi mengeksploitasi kunci publik yang terekspos di *mempool* sebelum blok ditambang. Proyek ini memitigasi ancaman tersebut dengan mempublikasikan *hash* dari kunci publik terlebih dahulu (Fase Commit), dan menunda penandatanganan hingga blok dikonfirmasi (Fase Reveal).

2. **Kompatibilitas: Tanda Tangan Hibrida (ML-DSA + ECDSA)**
   Untuk menjaga kompatibilitas mundur (*backward compatibility*) dengan node dan sistem warisan, transaksi ditandatangani menggunakan skema hibrida: algoritma PQC mutakhir **ML-DSA-65 (Dilithium)** yang digabungkan dengan algoritma klasik **ECDSA (secp256k1)**.

3. **Skalabilitas: Kompresi ZK-STARK (Simulasi Off-Chain)**
   Tanda tangan ML-DSA memiliki ukuran yang sangat besar (~3.309 bytes) yang menyebabkan *State Bloat* (pembengkakan data) dan lonjakan biaya gas yang masif di Layer-1. Solusinya:
   - Verifikasi tanda tangan hibrida dilakukan secara *off-chain*.
   - Pembuatan bukti kriptografis ringkas menggunakan simulasi **ZK-STARK**.
   - Blockchain Layer-1 hanya perlu memverifikasi ZK-Proof berukuran konstan (~400 bytes), menghasilkan penghematan biaya gas hingga **>88%**.

## Prasyarat

Pastikan Anda telah menginstal lingkungan pengembangan Rust:
- [Rust & Cargo](https://www.rust-lang.org/tools/install) (Edisi 2024 atau terbaru)

## Dependensi Utama

- `pqc-combo`: Untuk pembuatan kunci dan penandatanganan ML-DSA (Dilithium).
- `k256`: Untuk algoritma tanda tangan klasik ECDSA (secp256k1).
- `sha2`: Untuk fungsi *hashing* SHA-256 pada fase *Commit-and-Reveal*.

## Cara Menjalankan

Kloning repositori ini dan jalankan perintah Cargo berikut di terminal Anda:

```bash
cargo run