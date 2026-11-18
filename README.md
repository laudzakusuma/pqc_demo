# AQMP v2.0 Migration Demo (Rust Prover + Sui Move Verifier)

Repositori ini berisi implementasi *Proof-of-Concept* (PoC) dalam bahasa **Rust** dan **Sui Move 2024** yang disejajarkan dengan parameter empiris dan formal **AQMP v2.0 (Adaptive Quantum Migration Protocol)** untuk memecahkan **Trilema Migrasi Kriptografi Pasca-Kuantum** (Keamanan Kuantum, Skalabilitas, dan Kompatibilitas).

## Published Research Trilogy & Zenodo DOIs

**Author:** Laudza Kusuma (Independent Researcher)

1. **Paper #1 (AQMP v2.0 Core Protocol & QROM Proofs):** [https://doi.org/10.5281/zenodo.24303569](https://doi.org/10.5281/zenodo.24303569) (Concept DOI: `10.5281/zenodo.18993494`)
2. **Paper #2 (Stateless PQ-MPC & 676B Knowledge-Asymmetry UTXO Rescue):** [https://doi.org/10.5281/zenodo.24341314](https://doi.org/10.5281/zenodo.24341314)
3. **Paper #3 (AQMP-384 Classical Authentication for DI-QKD & Quantum Repeaters):** [https://doi.org/10.5281/zenodo.24343601](https://doi.org/10.5281/zenodo.24343601)

## Arsitektur AQMP v2.0 & Modul Inti

### 1. Modul Wallet (`src/wallet.rs`): Kompatibilitas & `KeyRegistry` 4-Byte Index
- **Mekanisme P2QRH**: Alamat dompet diturunkan dari SHA-256 gabungan kunci publik klasik (`secp256k1` ECDSA) dan pasca-kuantum (ML-DSA / FALCON-512), menutup celah *Downgrade Attack*.
- **Dukungan AQMP v2.0**: Menyimpan indeks `KeyRegistry` 4-byte (`u32` big-endian) dan anchor awal Dual-Commit XOR 32-byte ($y_0$), memungkinkan pengurangan overhead per transaksi terindeks menjadi $40\text{ B (salt } R\text{)} + 4\text{ B (idx)} = 44\text{ B/tx}$.

### 2. Modul Verifier (`src/verifier.rs`): Dual-Commit XOR, QROM & Tenggat Fukuda ($\Delta^*$)
- **Hash-Based Dual-Commit XOR**:
  - **256-bit Mode (ECDSA Parity):** Commit Tx1 $C = F_{\text{PRE}}(x) \oplus F_{\text{MSG}}(x \parallel m)$ ($32\text{ B}$) + Reveal/Rotate Tx2 $(x, y' = F_{\text{PRE}}(x'))$ ($64\text{ B}$) $= \mathbf{96\text{ B/tx}}$ (setara ECDSA $96\text{ B/tx}$).
  - **384-bit Domain-Separated Sponge Mode:** Menggunakan digest 384-bit ($48\text{ B} + 96\text{ B} = 144\text{ B/tx}$) dengan keamanan QROM formal $\ge \mathbf{187.00\text{ bits}}$ pada $q_F = 2^{64}$ (berdasarkan batas $\text{Adv}^{\text{EUF-CMA-QROM}}_{\text{AQMP-v2}}(\mathcal{A}) \le \frac{8(q_F+1)^2 + 32 q_F^3}{2^n}$).
- **Fukuda Consensus Migration Deadline ($\Delta^*$):**
  - Menegakkan jendela konfirmasi minimum $\Delta_{\text{eff}} \ge \Delta^* = \lceil 4 / (1 - \epsilon) \rceil$ blok ($\Delta^* \in \{5, 6, 8, 16, 40\}$ untuk $\epsilon \in \{0.10, 0.25, 0.50, 0.75, 0.90\}$).

### 3. Modul Aggregator (`src/aggregator.rs`): APSE v2.0 Break-Even Routing
Menggantikan skor heuristik dengan model byte eksak dan switching deterministik dalam anggaran pembuktian **810 ms**:
- **Plonky3 BabyBear (`300 + 44N` B):** Mengungguli FALCON Key-Recovery ($690N\text{ B}$) sejak $N^*_{\text{Plonky3}} = \mathbf{1}\text{ tx/block}$ dan mengungguli ECDSA ($96N\text{ B}$) sejak $N^*_{\text{ECDSA}} = \mathbf{6}\text{ tx/block}$ ($11,300\text{ B}$ vs $24,000\text{ B}$ ECDSA dan $1,315,250\text{ B}$ ML-DSA-65 pada $N = 250$).
- **Fallback LaBRADOR Terindeks (jika budget 810 ms terlampaui):**
  - **Execution Layer (EL):** $a_{N,\text{EL}} + 44N$ ($a_{N,\text{EL}} = 51200 + \lfloor 128 \log_2(\max(N, 2)) \rfloor$), break-even $N^*_{\text{EL}} = \mathbf{81}\text{ tx/block}$.
  - **Consensus Layer (CL):** $71680 + 44N$, break-even $N^*_{\text{CL}} = \mathbf{111}\text{ tx/block}$.

### 4. Modul Folding (`src/folding.rs`) & Precompile (`src/precompile.rs`)
- Mempertahankan `NovaFolder` (pelipatan R1CS ke 32 byte) sekaligus menambahkan `Plonky3Aggregator` (medan prima BabyBear $p = 2^{31} - 2^{27} + 1 = 2,013,265,921$, bukti rekursif konstan **300 B** + metadata terindeks **44 B/tx**).
- Menyediakan verifikasi kriptografis **FALCON-512** nyata (`pqcrypto-falcon`) dan kalkulasi gas EIP-7619 di `src/precompile.rs`.

### 5. Sui Move Verifier (`pqc_verifier/sources/verifier.move`)
- Mempertahankan `commit_intent` & `execute_zk_folded_tx` (kompatibilitas mundur).
- Menambahkan verifikasi **Dual-Commit XOR** on-chain (`init_dual_commit_anchor`, `submit_dual_commit_xor`, `reveal_and_rotate_xor`) lengkap dengan rotasi anchor ephemeral $y \to y'$ dan penegakan batas Fukuda $\Delta_{\text{eff}} \ge \Delta^*$.
- Menambahkan `verify_plonky3_indexed_batch` untuk validasi bukti Plonky3 **300 B** + metadata terindeks **$44N$ B**.

## Pengujian & Benchmark

```bash
# Jalankan unit test Rust (termasuk APSE v2.0, Dual-Commit XOR, QROM, Fukuda, Plonky3, FALCON-512)
cargo test

# Jalankan simulasi end-to-end Rust AQMP v2.0
cargo run

# Jalankan benchmark empiris Python (CSV + grafik 300 DPI di paper/)
python benchmark_aqmp_v2.py

# Jalankan unit test Sui Move (jika Sui CLI terpasang)
cd pqc_verifier && sui move test
```
