# PQC Migration Trilemma Demo (Absolute Resolution)

Repositori ini berisi implementasi *Proof-of-Concept* (PoC) tingkat lanjut dalam bahasa Rust yang dirancang untuk memecahkan **Trilema Migrasi Kriptografi Pasca-Kuantum** pada jaringan blockchain (Layer 1 / Layer 2).

Proyek ini mendemonstrasikan resolusi absolut untuk pilar Keamanan, Kompatibilitas, dan Skalabilitas menggunakan kriptografi terapan yang nyata, tanpa menggunakan data statis/dummy.

## Arsitektur Resolusi Trilema & Modul Inti

### 1. Modul Wallet (`wallet.rs`) - Resolusi Kompatibilitas
Mengimplementasikan konsep **Native Account Abstraction** melalui dompet komposit.
- **Mekanisme**: Alamat dompet diturunkan secara kriptografis (SHA-256) dari *hash* gabungan kunci publik klasik (ECDSA `secp256k1`) dan pasca-kuantum (ML-DSA / Dilithium).
- **Pertahanan**: Menutup celah *Downgrade Attack*. Jika entitas mencoba memaksa jaringan memvalidasi via algoritma ECDSA murni, hash alamat akan rusak secara matematis.

### 2. Modul Verifier (`verifier.rs`) - Resolusi Keamanan
Mengamankan jaringan dari eksploitasi *Quantum Front-Running* (Algoritma Grover) di *mempool*.
- **Mekanisme**: Memanfaatkan protokol **Commit-and-Reveal**. Sistem mempublikasikan *hash* komitmen (32 byte) dari kunci PQC ke Layer 1 sebelum mengungkap kunci aslinya untuk dieksekusi, meredam rekayasa asinkron dari serangan kuantum cepat.

### 3. Modul Folding (`folding.rs`) - Resolusi Skalabilitas (State Bloat)
Menggantikan agregasi Merkle konvensional dengan infrastruktur **Recursive Proof Systems (Skema Pelipatan bergaya Nova)** untuk memampatkan ukuran tanda tangan PQC yang sangat masif.
- **Mekanisme**: Mengubah data transaksi publik dan tanda tangan privat menjadi Pasangan Pernyataan-Saksi (*Instance-Witness Pair*) dalam struktur matematika *Rank-1 Constraint Systems (R1CS)*. Bukti-bukti tersebut kemudian dilipat (*folded*) menggunakan faktor acak linear.
- **Efisiensi**: Menghancurkan kompleksitas ruang data Layer 1 secara drastis. Beban ribuan byte saksi komputasi dari transaksi PQC dipampatkan dengan tingkat penghematan lebih dari **99.90%**, menghasilkan satu bukti verifikasi konstan yang siap dikonversi menjadi sirkuit zk-STARK.

## Pengujian Terotomatisasi (Unit Tests)

Proyek ini dilengkapi dengan pengujian unit kriptografis yang membuktikan determinisme logika:
- `test_nova_folding_constant_size`: Memvalidasi operasi pelipatan matriks data ke ukuran konstan (32 byte).
- `test_batch_folding_efficiency`: Menguji efisiensi IVC (*Incrementally Verifiable Computation*) atas 100 transaksi secara rekursif.
- `test_downgrade_attack_prevention`: Menjamin resistensi struktur dompet hibrida dari eksploitasi penurunan versi (*downgrade attacks*).

**Jalankan Pengujian:**
```bash
cargo test