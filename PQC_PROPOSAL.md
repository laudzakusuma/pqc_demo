# AQMP v2.0: Adaptive Quantum Migration Protocol & State Compression Standard

## Abstrak
Ancaman komputasi kuantum (Algoritma Shor & Grover) menuntut transisi segera menuju Kriptografi Pasca-Kuantum (PQC). Namun, adopsi naif seperti ML-DSA-65 ($1952\text{ B}$ kunci publik + $3309\text{ B}$ tanda tangan = $5261\text{ B/tx}$) memicu *State Bloat* masif ($1,315,250\text{ B}$ per blok pada $N = 250$ transaksi, atau $19,728.75\text{ MB}$ total replikasi lintas $15,000$ node).

Arsitektur **AQMP v2.0** menggantikan metrik heuristik dengan persamaan tapak-byte formal, perutean break-even deterministik (**APSE v2.0**), protokol **Hash-Based Dual-Commit XOR** ber-paritas ECDSA, bukti QROM formal, serta batas konsensus **Fukuda ($\Delta^*$)** yang ditegakkan secara asimetris antara Prover Rust dan Verifier Sui Move.

## Pilar Matematis AQMP v2.0

1. **APSE v2.0 & Rekursi Plonky3 BabyBear (`300 + 44N` B):**
   - Menggunakan medan prima BabyBear ($p = 2^{31} - 2^{27} + 1$) dengan bukti rekursif konstan **$300\text{ B}$** dan indeks `KeyRegistry` $4\text{ B}$ + salt FALCON $40\text{ B}$ (**$44\text{ B/tx}$**) dalam batas waktu pembuktian **$810\text{ ms}$**.
   - Mengalahkan FALCON Key-Recovery ($690N\text{ B}$) sejak $N^*_{\text{Plonky3}} = 1$ dan mengalahkan ECDSA ($96N\text{ B}$) sejak $N^*_{\text{ECDSA}} = 6$ transaksi per blok (hanya **$11,300\text{ B}$** pada $N = 250$, penghematan **$-99.14\%$** dibanding ML-DSA-65).
   - Fallback deterministik ke **LaBRADOR terindeks** pada $N^*_{\text{EL}} = 81$ (Execution Layer: $51200 + \lfloor 128 \log_2(\max(N,2)) \rfloor + 44N$) dan $N^*_{\text{CL}} = 111$ (Consensus Layer: $71680 + 44N$).

2. **Hash-Based Dual-Commit XOR & Bukti QROM:**
   - **Siklus $96\text{ B/tx}$ (256-bit):** Commit Tx1 $C = F_{\text{PRE}}(x) \oplus F_{\text{MSG}}(x \parallel m)$ ($32\text{ B}$) + Reveal/Rotate Tx2 $(x, y' = F_{\text{PRE}}(x'))$ ($64\text{ B}$) menyamai tepat ukuran ECDSA ($96\text{ B/tx}$, hanya **$360.00\text{ MB}$** per blok di $15,000$ node pada $N=250$).
   - **Varian Domain-Separated Sponge 384-bit:** Pada batas Zhandry/O2H QROM $\text{Adv}(\mathcal{A}) \le \frac{8(q_F+1)^2 + 32 q_F^3}{2^n}$, mencapai keamanan **$\ge 187.00\text{ bits}$** pada anggaran kuari $q_F = 2^{64}$.

3. **Quantum Threat Oracle & Tenggat Konsensus Fukuda ($\Delta^*$):**
   - Kontrak Sui Move (`pqc_verifier::folding_verifier`) memaksa jendela konfirmasi $\Delta_{\text{eff}} \ge \Delta^* = \lceil 4 / (1 - \epsilon) \rceil$ blok sebelum rotasi anchor atau finalisasi disetujui ($\Delta^* \in \{5, 6, 8, 16, 40\}$ untuk $\epsilon \in \{0.10, 0.25, 0.50, 0.75, 0.90\}$).
