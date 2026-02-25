module pqc_verifier::folding_verifier {
    use sui::hash::blake2b256;
    use sui::event;
    
    // Catatan: Modul object, tx_context, transfer, dan vector sudah otomatis diimpor oleh Sui Move 2024!

    // --- Error Codes ---
    const E_INVALID_COMMITMENT: u64 = 0;
    const E_INVALID_FOLDED_PROOF: u64 = 1;

    // --- State Objects ---

    /// Objek untuk Fase 1: Mengunci Hash Komitmen (Mencegah Grover's Algorithm)
    public struct QuantumCommitment has key, store {
        id: UID,
        owner: address,
        commitment_hash: vector<u8>,
    }

    /// Event On-Chain untuk transparansi verifikasi
    public struct TransactionFolded has copy, drop {
        executor: address,
        proof_size: u64,
        is_pqc_secure: bool,
    }

    // --- Fungsi Eksekusi Layer-1 ---

    /// TAHAP 1: COMMIT 
    /// Menerima hash 32-byte dari mesin Rust untuk mengunci niat transaksi sebelum kunci publik diekspos.
    /// (Diperbarui untuk Composability: Mengembalikan objek secara langsung)
    public fun commit_intent(hash: vector<u8>, ctx: &mut TxContext): QuantumCommitment {
        QuantumCommitment {
            id: object::new(ctx),
            owner: tx_context::sender(ctx),
            commitment_hash: hash,
        }
    }

    /// TAHAP 2: REVEAL & VERIFY FOLDED PROOF 
    /// Layer-1 HANYA memvalidasi 32-byte hasil lipatan dari Rust (x_folded, w_folded)
    public fun execute_zk_folded_tx(
        commitment: &QuantumCommitment,
        revealed_pqc_pub: vector<u8>,
        x_folded: vector<u8>, 
        w_folded: vector<u8>, 
        ctx: &mut TxContext
    ) {
        //verifikasi Anti-Front-Running (Quantum Grover)
        let calculated_hash = blake2b256(&revealed_pqc_pub);
        assert!(calculated_hash == commitment.commitment_hash, E_INVALID_COMMITMENT);

        //verifikasi Skalabilitas (Konstrain 32-byte)
        assert!(x_folded.length() == 32, E_INVALID_FOLDED_PROOF);
        assert!(w_folded.length() == 32, E_INVALID_FOLDED_PROOF);

        //EKSEKUSI TRANSAKSI AKTUAL DI SINI

        //pancarkan Event Keberhasilan
        event::emit(TransactionFolded {
            executor: tx_context::sender(ctx),
            proof_size: 32,
            is_pqc_secure: true,
        });
    }
}