# PQC-SIP: Post-Quantum Cryptographic State Compression Standard

## Abstrak
Ancaman komputasi kuantum (Algoritma Shor & Grover) memaksa transisi mendesak menuju Kriptografi Pasca-Kuantum (PQC) seperti ML-DSA (Dilithium). Namun, ukuran tanda tangan PQC yang masif (>3.309 byte) memicu *State Bloat* yang menghancurkan throughput Layer-1 dan mendongkrak gas fee secara ekstrem. 

Proposal ini mendemonstrasikan arsitektur resolusi *End-to-End* berbasis *Zero-Knowledge Folding Schemes* yang diterapkan secara asimetris:
1. **L2 Prover Aggregator (Rust)**: Memproses dan melipat (*folding*) R1CS *instance-witness* dari ribuan transaksi Dilithium mentah menjadi *proof* rekursif berukuran konstan (32 byte).
2. **L1 Verifier Contract (Sui Move)**: Kontrak pintar berbiaya gas sangat rendah yang menerima komitmen pra-eksekusi (*anti-front-running*) dan mengeksekusi bukti 32 byte tanpa mengeksekusi komputasi matematis *lattice* yang berat.

Arsitektur ini mencapai rasio kompresi jaringan sebesar >99.90%, memungkinkan desentralisasi berdaya komputasi ringan (*mobile-native decentralization*) untuk bertahan di era pasca-kuantum tanpa mengorbankan keamanan sistem warisan.